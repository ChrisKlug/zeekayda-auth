using System.Globalization;
using System.Security.Cryptography;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using ZeeKayDa.Auth.Logging;

namespace ZeeKayDa.Auth.Clients;

/// <summary>
/// The built-in PBKDF2-HMAC-SHA256 client secret hasher. This is the default hasher provided
/// by ZeeKayDa.Auth and covers the vast majority of deployments.
/// </summary>
/// <remarks>
/// <para>
/// Algorithm parameters:
/// <list type="bullet">
/// <item><description>Algorithm: PBKDF2-HMAC-SHA256</description></item>
/// <item><description>Default iterations: 600,000 (OWASP PBKDF2-HMAC-SHA256 guidance as of 2025)</description></item>
/// <item><description>Minimum iterations: 600,000; operators can only configure stronger</description></item>
/// <item><description>Maximum iterations: 2,000,000 (see below)</description></item>
/// <item><description>Salt: 16 bytes via <see cref="RandomNumberGenerator.GetBytes(int)"/></description></item>
/// <item><description>Hash output: 32 bytes</description></item>
/// </list>
/// </para>
/// <para>
/// <strong>Maximum iteration cap.</strong> At 2,000,000 iterations a single verification takes
/// roughly one second on typical server hardware, making the token endpoint impractical under any
/// real load. <see cref="Pbkdf2ClientSecretHasherOptionsValidator"/> fails startup for a configured
/// count outside 600,000–2,000,000, and this class reads the count from the same
/// <see cref="IOptionsMonitor{TOptions}"/> that validation runs through, so it trusts the value.
/// </para>
/// </remarks>
internal sealed class Pbkdf2ClientSecretHasher(
    IOptionsMonitor<Pbkdf2ClientSecretHasherOptions> options,
    SanitizingLogger<Pbkdf2ClientSecretHasher> logger)
    : IClientSecretHasher
{
    /// <summary>
    /// The PHC algorithm id this hasher owns.
    /// </summary>
    internal const string AlgorithmId = "pbkdf2-sha256";

    /// <summary>
    /// The PHC parameter carrying the iteration count.
    /// </summary>
    internal const string IterationsParameter = "i";

    /// <summary>
    /// Minimum allowed iteration count (OWASP PBKDF2-HMAC-SHA256 minimum as of 2025).
    /// </summary>
    internal const int MinIterations = 600_000;

    /// <summary>
    /// Maximum allowed iteration count, preventing self-inflicted denial of service from an operator
    /// misconfiguration.
    /// </summary>
    internal const int MaxIterations = 2_000_000;

    internal const int SaltLength = 16;
    internal const int HashLength = 32;

    private static readonly IReadOnlySet<string> Ids =
        new HashSet<string>([AlgorithmId], StringComparer.Ordinal).AsReadOnly();

    // The monitor, not IOptions<T>: the framework's options check validates through the monitor, so
    // this reads exactly the value startup validated, even when a host registers IOptions<T> directly.
    private readonly int _iterations = RequireWithinBounds(options.CurrentValue.Iterations);

    /// <summary>
    /// The last line behind <see cref="Pbkdf2ClientSecretHasherOptionsValidator"/>, for a host that
    /// hands the hasher options the validator never saw. Out of range, the timing decoy would cost
    /// nothing to verify and the failure-path padding would pad nothing.
    /// </summary>
    private static int RequireWithinBounds(int iterations) =>
        iterations is >= MinIterations and <= MaxIterations
            ? iterations
            : throw new ZeeKayDaConfigurationException(new ZeeKayDaConfigurationFailure(
                "configuration.pbkdf2.iterations_out_of_range",
                $"The PBKDF2 hasher received {iterations:N0} iterations, outside " +
                $"{MinIterations:N0}–{MaxIterations:N0}, without them passing options validation. " +
                "Configure the count with ConfigurePbkdf2ClientSecretHasher or " +
                "Configure<Pbkdf2ClientSecretHasherOptions>, not by registering the options object directly."));

    /// <inheritdoc/>
    public IReadOnlySet<string> AlgorithmIds => Ids;

    /// <inheritdoc/>
    public bool Verify(ClientSecret stored, ReadOnlySpan<char> presented)
    {
        // Defence-in-depth: reject an empty presented span to guard against a stored hash of "".
        if (presented.IsEmpty || Read(stored.Value) is not { } parts)
            return false;

        // A legitimately created secret can never exceed MaxIterations (the options validator refuses
        // it), so a higher value is a corrupt or malicious record. Deriving would risk a CPU-bound
        // denial of service on every verification for that client.
        if (parts.Iterations > MaxIterations)
        {
            logger.LogWarning(
                "Pbkdf2ClientSecretHasher: stored secret has iteration count {Iterations} " +
                "which exceeds the maximum of {MaxIterations}. Verification rejected.",
                parts.Iterations, MaxIterations);
            return false;
        }

        var expected = Rfc2898DeriveBytes.Pbkdf2(
            presented,
            parts.Salt.Span,
            parts.Iterations,
            HashAlgorithmName.SHA256,
            HashLength);

        return CryptographicOperations.FixedTimeEquals(expected, parts.Hash.Span);
    }

    /// <inheritdoc/>
    public IEnumerable<ZeeKayDaConfigurationFailure> ValidateStoredSecret(ClientSecret stored)
    {
        if (Read(stored.Value) is not { } parts)
        {
            yield return new ZeeKayDaConfigurationFailure(
                "client.credentials.pbkdf2_malformed",
                $"A PBKDF2 secret is not of the form $pbkdf2-sha256$i=<iterations>$<salt>$<hash> with a " +
                $"{SaltLength}-byte salt and a {HashLength}-byte hash, in unpadded base64.");
            yield break;
        }

        if (parts.Iterations < MinIterations)
            yield return new ZeeKayDaConfigurationFailure(
                "client.credentials.pbkdf2_iterations_below_minimum",
                $"A PBKDF2 secret has {parts.Iterations:N0} iterations, " +
                $"which is below the minimum of {MinIterations:N0}. " +
                "Secrets with insufficient iterations do not provide adequate brute-force resistance (NIST SP 800-132).");

        if (parts.Iterations > MaxIterations)
            yield return new ZeeKayDaConfigurationFailure(
                "client.credentials.pbkdf2_iterations_above_maximum",
                $"A PBKDF2 secret has {parts.Iterations:N0} iterations, " +
                $"which exceeds the maximum of {MaxIterations:N0}. " +
                "Verify rejects secrets above this threshold, so the secret can never authenticate.");
    }

    /// <inheritdoc/>
    public ClientSecret Create(ReadOnlySpan<char> plaintext)
    {
        var salt = RandomNumberGenerator.GetBytes(SaltLength);
        var hash = Rfc2898DeriveBytes.Pbkdf2(
            plaintext,
            salt,
            _iterations,
            HashAlgorithmName.SHA256,
            HashLength);

        return Format(_iterations, salt, hash);
    }

    /// <summary>
    /// A random salt and a random hash at the configured iteration count. <see cref="Verify"/>
    /// derives from the presented value with the stored salt and iterations and only then compares,
    /// so verifying against this costs exactly what a real secret costs — and no presented value
    /// derives a random hash. Building it costs nothing, where deriving one would cost a full
    /// derivation at host startup.
    /// </summary>
    ClientSecret IClientSecretHasher.CreateTimingDecoy() =>
        Format(
            _iterations,
            RandomNumberGenerator.GetBytes(SaltLength),
            RandomNumberGenerator.GetBytes(HashLength));

    internal static ClientSecret Format(int iterations, ReadOnlySpan<byte> salt, ReadOnlySpan<byte> hash) =>
        new(new PhcString(
            AlgorithmId,
            salt,
            hash,
            [new(IterationsParameter, iterations.ToString(CultureInfo.InvariantCulture))]).ToString());

    /// <summary>
    /// The parts of a well-formed PBKDF2 secret, or <see langword="null"/>. Well-formed means our id,
    /// no version, exactly one parameter — a positive iteration count — and the salt and hash
    /// lengths this hasher writes. Iteration bounds are not checked here: they have their own
    /// failure codes.
    /// </summary>
    private static Pbkdf2Parts? Read(string? value)
    {
        if (!PhcString.TryParse(value, out var phc)
            || phc.Id != AlgorithmId
            || phc.Version is not null
            || phc.Parameters is not [{ Key: IterationsParameter, Value: var iterationsText }]
            || !int.TryParse(iterationsText, NumberStyles.None, CultureInfo.InvariantCulture, out var iterations)
            || iterations <= 0
            || phc.Salt.Length != SaltLength
            || phc.Hash.Length != HashLength)
        {
            return null;
        }

        return new Pbkdf2Parts(iterations, phc.Salt, phc.Hash);
    }

    private sealed record Pbkdf2Parts(int Iterations, ReadOnlyMemory<byte> Salt, ReadOnlyMemory<byte> Hash);
}
