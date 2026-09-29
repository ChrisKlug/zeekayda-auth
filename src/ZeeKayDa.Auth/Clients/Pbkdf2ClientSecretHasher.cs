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
// IClientSecretHasher is re-listed on purpose. Inherited through ClientSecretHasher<T> alone, the
// interface's default members stay bound to their defaults, and a public method here with the same
// signature — GetRegistrationFailures — is silently not an implementation of them.
internal sealed class Pbkdf2ClientSecretHasher(
    IOptionsMonitor<Pbkdf2ClientSecretHasherOptions> options,
    ISanitizingLogger<Pbkdf2ClientSecretHasher> logger)
    : ClientSecretHasher<IPbkdf2ClientSecret>, IClientSecretHasher
{
    /// <summary>
    /// Minimum allowed iteration count (OWASP PBKDF2-HMAC-SHA256 minimum as of 2025).
    /// </summary>
    internal const int MinIterations = 600_000;

    /// <summary>
    /// Maximum allowed iteration count, preventing self-inflicted denial of service from an operator
    /// misconfiguration.
    /// </summary>
    internal const int MaxIterations = 2_000_000;

    private const int SaltLength = 16;
    private const int HashLength = 32;

    // The monitor, not IOptions<T>: ValidateOnStart validates through the monitor, so this reads
    // exactly the value startup validated, even when a host registers IOptions<T> directly.
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
    protected override bool VerifyCore(IPbkdf2ClientSecret stored, ReadOnlySpan<char> presented)
    {
        // Defence-in-depth: reject an empty presented span to guard against a stored hash of "".
        if (presented.IsEmpty)
            return false;

        // Reject a stored credential whose iteration count exceeds the cap. A legitimately
        // created credential can never exceed MaxIterations (the options validator refuses it), so
        // a higher value indicates a corrupt or malicious record. Proceeding would risk a
        // CPU-bound denial of service on every verification for that client.
        if (stored.Iterations > MaxIterations)
        {
            logger.LogWarning(
                "Pbkdf2ClientSecretHasher: stored credential has iteration count {Iterations} " +
                "which exceeds the maximum of {MaxIterations}. Verification rejected.",
                stored.Iterations, MaxIterations);
            return false;
        }

        var expected = Rfc2898DeriveBytes.Pbkdf2(
            presented,
            stored.Salt,
            stored.Iterations,
            HashAlgorithmName.SHA256,
            HashLength);

        return CryptographicOperations.FixedTimeEquals(expected, stored.Hash);
    }

    /// <inheritdoc/>
    public IEnumerable<ZeeKayDaConfigurationFailure> GetRegistrationFailures(
        IClientSecret credential, string clientId)
    {
        if (credential is not IPbkdf2ClientSecret pbkdf2)
            yield break;

        if (pbkdf2.Iterations < MinIterations)
            yield return new ZeeKayDaConfigurationFailure(
                "client.credentials.pbkdf2_iterations_below_minimum",
                $"Client '{clientId}' has a PBKDF2 credential with {pbkdf2.Iterations:N0} iterations, " +
                $"which is below the minimum of {MinIterations:N0}. " +
                "Credentials with insufficient iterations do not provide adequate brute-force resistance (NIST SP 800-132).");

        if (pbkdf2.Iterations > MaxIterations)
            yield return new ZeeKayDaConfigurationFailure(
                "client.credentials.pbkdf2_iterations_above_maximum",
                $"Client '{clientId}' has a PBKDF2 credential with {pbkdf2.Iterations:N0} iterations, " +
                $"which exceeds the maximum of {MaxIterations:N0}. " +
                "VerifyCore rejects credentials above this threshold, so the credential can never authenticate.");
    }

    /// <inheritdoc/>
    protected override IPbkdf2ClientSecret CreateCore(ReadOnlySpan<char> plaintext)
    {
        var salt = RandomNumberGenerator.GetBytes(SaltLength);
        var hash = Rfc2898DeriveBytes.Pbkdf2(
            plaintext,
            salt,
            _iterations,
            HashAlgorithmName.SHA256,
            HashLength);

        return new Pbkdf2ClientSecret(_iterations, salt, hash);
    }

    /// <inheritdoc/>
    protected override IPbkdf2ClientSecret CreateCore(string plaintext)
    {
        var salt = RandomNumberGenerator.GetBytes(SaltLength);
        var hash = Rfc2898DeriveBytes.Pbkdf2(
            plaintext,
            salt,
            _iterations,
            HashAlgorithmName.SHA256,
            HashLength);

        return new Pbkdf2ClientSecret(_iterations, salt, hash);
    }

    /// <summary>
    /// A random salt and a random hash at the configured iteration count. <see cref="VerifyCore"/>
    /// derives from the presented value with the stored salt and iterations and only then compares,
    /// so verifying against this costs exactly what a real credential costs — and no presented value
    /// derives a random hash. Building it costs nothing, where deriving one would cost a full
    /// derivation at host startup.
    /// </summary>
    IClientSecret IClientSecretHasher.CreateTimingDecoy() =>
        new Pbkdf2ClientSecret(
            _iterations,
            RandomNumberGenerator.GetBytes(SaltLength),
            RandomNumberGenerator.GetBytes(HashLength));
}
