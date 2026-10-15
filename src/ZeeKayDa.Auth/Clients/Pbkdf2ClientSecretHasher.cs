using System.Globalization;
using System.Security.Cryptography;
using Microsoft.Extensions.Options;

namespace ZeeKayDa.Auth.Clients;

/// <summary>
/// The built-in PBKDF2-HMAC-SHA256 hasher: 16-byte salt, 32-byte hash, 600,000 to 2,000,000 iterations.
/// </summary>
/// <remarks>
/// The floor is OWASP's guidance; the cap keeps a verification near one second, so a misconfiguration
/// cannot make the token endpoint its own denial of service.
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

    /// <summary>The minimum iteration count, OWASP's PBKDF2-HMAC-SHA256 guidance.</summary>
    internal const int MinIterations = 600_000;

    /// <summary>The maximum iteration count, against a self-inflicted denial of service.</summary>
    internal const int MaxIterations = 2_000_000;

    internal const int SaltLength = 16;
    internal const int HashLength = 32;

    private static readonly IReadOnlySet<string> Ids =
        new HashSet<string>([AlgorithmId], StringComparer.Ordinal).AsReadOnly();

    // The monitor, not IOptions<T>: the framework's options check validates through the monitor, so
    // this reads exactly the value startup validated, even when a host registers IOptions<T> directly.
    private readonly int _iterations = RequireWithinBounds(options.CurrentValue.Iterations);

    /// <summary>
    /// The last line behind options validation, for options it never saw: out of range, the timing decoy
    /// would pad nothing.
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
    public bool Verify(ReadOnlySpan<char> presented, ClientSecret stored)
    {
        // Defence-in-depth: reject an empty presented span to guard against a stored hash of "".
        if (presented.IsEmpty || Read(stored.Value, out _) is not { Iterations: { } iterations } parts)
            return false;

        // Validation refuses such a secret first; deriving it would be a CPU-bound denial of service.
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
    /// A random salt and hash at the configured count: verifying costs a full derivation, building it none,
    /// and no presented value derives a random hash.
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
