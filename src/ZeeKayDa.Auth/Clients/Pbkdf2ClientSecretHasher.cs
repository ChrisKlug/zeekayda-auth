using System.Globalization;
using System.Security.Cryptography;
using Microsoft.Extensions.Options;

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
internal sealed class Pbkdf2ClientSecretHasher(IOptionsMonitor<Pbkdf2ClientSecretHasherOptions> options)
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
        if (presented.IsEmpty || Read(stored.Value, out _) is not { Iterations: { } iterations } parts)
            return false;

        // Validation refuses such a secret before it is ever served; this is the last line, because
        // deriving would cost every verification for that client a CPU-bound denial of service.
        if (iterations > MaxIterations)
            return false;

        var expected = Rfc2898DeriveBytes.Pbkdf2(
            presented,
            parts.Salt.Span,
            iterations,
            HashAlgorithmName.SHA256,
            HashLength);

        return CryptographicOperations.FixedTimeEquals(expected, parts.Hash.Span);
    }

    /// <inheritdoc/>
    public IEnumerable<ZeeKayDaConfigurationFailure> ValidateStoredSecret(ClientSecret stored)
    {
        if (Read(stored.Value, out var problem) is not { Iterations: { } iterations })
        {
            yield return new ZeeKayDaConfigurationFailure("client.credentials.pbkdf2_malformed", problem!);
            yield break;
        }

        if (iterations < MinIterations)
            yield return new ZeeKayDaConfigurationFailure(
                "client.credentials.pbkdf2_iterations_below_minimum",
                $"A PBKDF2 secret has {iterations:N0} iterations, " +
                $"which is below the minimum of {MinIterations:N0}. " +
                "Secrets with insufficient iterations do not provide adequate brute-force resistance (NIST SP 800-132).");

        if (iterations > MaxIterations)
            yield return new ZeeKayDaConfigurationFailure(
                "client.credentials.pbkdf2_iterations_above_maximum",
                $"A PBKDF2 secret has {iterations:N0} iterations, " +
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

    private const string NotAPhcString =
        "A PBKDF2 secret is not a PHC string: $pbkdf2-sha256$i=<iterations>$<salt>$<hash>, in unpadded base64.";

    /// <summary>A PBKDF2 secret's fields, each read once from its PHC string.</summary>
    private sealed record Pbkdf2Parts(string Id, int? Version, int? Iterations, ReadOnlyMemory<byte> Salt, ReadOnlyMemory<byte> Hash);

    // What a stored PBKDF2 secret must be. Iteration bounds are not here: they have their own codes.
    private static readonly Func<Pbkdf2Parts, string?>[] Rules =
    [
        parts => parts.Id == AlgorithmId ? null : $"A PBKDF2 secret must have the id {AlgorithmId}.",
        parts => parts.Version is null ? null : "A PBKDF2 secret has no version field.",
        parts => parts.Iterations is not null
            ? null
            : $"A PBKDF2 secret needs exactly one parameter, {IterationsParameter}=<iterations>, a positive whole number.",
        parts => parts.Salt.Length == SaltLength ? null : $"A PBKDF2 secret needs a {SaltLength}-byte salt.",
        parts => parts.Hash.Length == HashLength ? null : $"A PBKDF2 secret needs a {HashLength}-byte hash.",
    ];

    /// <summary>
    /// The parts of a well-formed PBKDF2 secret, or <see langword="null"/> with the first rule it
    /// breaks in <paramref name="problem"/>.
    /// </summary>
    private static Pbkdf2Parts? Read(string? value, out string? problem)
    {
        if (!PhcString.TryParse(value, out var phc))
        {
            problem = NotAPhcString;
            return null;
        }

        var parts = new Pbkdf2Parts(phc.Id, phc.Version, IterationsOf(phc.Parameters), phc.Salt, phc.Hash);
        problem = Rules.Select(rule => rule(parts)).FirstOrDefault(broken => broken is not null);
        return problem is null ? parts : null;
    }

    private static int? IterationsOf(IReadOnlyList<KeyValuePair<string, string>> parameters) =>
        parameters is [{ Key: IterationsParameter, Value: var text }]
        && int.TryParse(text, NumberStyles.None, CultureInfo.InvariantCulture, out var iterations)
        && iterations > 0
            ? iterations
            : null;
}
