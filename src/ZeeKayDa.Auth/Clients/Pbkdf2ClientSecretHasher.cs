using System.Security.Cryptography;
using Microsoft.Extensions.Logging;
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
/// <item><description>Minimum iterations: 600,000 — constructor-enforced; operators can only configure stronger</description></item>
/// <item><description>Maximum iterations: 2,000,000 — exceeded values are clamped with a startup warning (see below)</description></item>
/// <item><description>Salt: 16 bytes via <see cref="RandomNumberGenerator.GetBytes(int)"/></description></item>
/// <item><description>Hash output: 32 bytes</description></item>
/// </list>
/// </para>
/// <para>
/// <strong>Maximum iteration cap.</strong> If the configured iteration count exceeds 2,000,000
/// the constructor clamps the value to 2,000,000 and emits a <c>LogWarning</c> rather than
/// throwing. At this level a single verification takes roughly one second on typical server
/// hardware, making the token endpoint impractical under any real load. Clamping lets the server
/// start safely while signalling that reconfiguration is needed.
/// </para>
/// </remarks>
public sealed class Pbkdf2ClientSecretHasher : ClientSecretHasher<IPbkdf2ClientSecret>
{
    /// <summary>
    /// Minimum allowed iteration count (OWASP PBKDF2-HMAC-SHA256 minimum as of 2025).
    /// </summary>
    internal const int MinIterations = 600_000;

    /// <summary>
    /// Maximum allowed iteration count. Values above this are clamped with a startup warning
    /// to prevent self-inflicted denial of service from an operator misconfiguration.
    /// </summary>
    internal const int MaxIterations = 2_000_000;

    private const int SaltLength = 16;
    private const int HashLength = 32;

    private readonly int _iterations;
    private readonly ILogger<Pbkdf2ClientSecretHasher> _logger;

    /// <summary>
    /// Initialises the hasher using configuration from <see cref="Pbkdf2ClientSecretHasherOptions"/>.
    /// </summary>
    /// <param name="options">Hasher options. Configured via DI or constructed directly for tests.</param>
    /// <param name="logger">Logger used to emit a startup warning when iterations exceed the cap.</param>
    /// <exception cref="ArgumentNullException">
    /// Thrown when <paramref name="options"/> or <paramref name="logger"/> is <see langword="null"/>.
    /// </exception>
    /// <exception cref="ArgumentOutOfRangeException">
    /// Thrown when the configured iteration count is below <see cref="MinIterations"/> (600,000).
    /// </exception>
    public Pbkdf2ClientSecretHasher(
        IOptions<Pbkdf2ClientSecretHasherOptions> options,
        ILogger<Pbkdf2ClientSecretHasher> logger)
    {
        ArgumentNullException.ThrowIfNull(options);
        ArgumentNullException.ThrowIfNull(logger);

        var iterations = options.Value.Iterations;

        if (iterations < MinIterations)
            throw new ArgumentOutOfRangeException(
                nameof(options),
                iterations,
                $"PBKDF2 iteration count must be at least {MinIterations:N0} " +
                $"(OWASP PBKDF2-HMAC-SHA256 minimum). Configured value: {iterations:N0}.");

        if (iterations > MaxIterations)
        {
            logger.LogWarning(
                "Pbkdf2ClientSecretHasher: configured iteration count {Iterations} exceeds the " +
                "maximum of {MaxIterations}. The value has been clamped to {MaxIterations}. " +
                "Reduce the iteration count to avoid unacceptably slow startup and per-request timings.",
                iterations, MaxIterations, MaxIterations);

            iterations = MaxIterations;
        }

        _iterations = iterations;
        _logger = logger;
    }

    /// <inheritdoc/>
    protected override bool VerifyCore(IPbkdf2ClientSecret stored, ReadOnlySpan<char> presented)
    {
        // Defence-in-depth: reject an empty presented span to guard against a stored hash of "".
        if (presented.IsEmpty)
            return false;

        // Reject a stored credential whose iteration count exceeds the cap. A legitimately
        // created credential can never exceed MaxIterations (the constructor clamps it), so
        // a higher value indicates a corrupt or malicious record. Proceeding would risk a
        // CPU-bound denial of service on every verification for that client.
        if (stored.Iterations > MaxIterations)
        {
            _logger.LogWarning(
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
}
