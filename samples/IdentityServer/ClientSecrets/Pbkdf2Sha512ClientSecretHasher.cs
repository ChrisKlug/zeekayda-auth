using System.Globalization;
using System.Security.Cryptography;
using ZeeKayDa.Auth;
using ZeeKayDa.Auth.Clients;

namespace ZeeKayDa.Auth.Samples.IdentityServer.ClientSecrets;

/// <summary>
/// PBKDF2-HMAC-SHA512 from the .NET base class library, which works in bytes: this hasher builds
/// its string with <see cref="PhcString"/> (<c>$pbkdf2-sha512$i=210000$&lt;salt&gt;$&lt;hash&gt;</c>) and
/// parses it back the same way.
/// </summary>
public sealed class Pbkdf2Sha512ClientSecretHasher : IClientSecretHasher
{
    private const string Id = "pbkdf2-sha512";
    private const string IterationsParameter = "i";

    // OWASP's PBKDF2-HMAC-SHA512 recommendation.
    private const int Iterations = 210_000;

    // A stored count above this would cost every verification for that client far too much CPU.
    private const int MaxIterations = 1_000_000;

    private const int SaltLength = 16;
    private const int HashLength = 64;

    public IReadOnlySet<string> AlgorithmIds { get; } = new HashSet<string>([Id], StringComparer.Ordinal);

    public bool Verify(ClientSecret stored, ReadOnlySpan<char> presented)
    {
        if (Read(stored) is not { Iterations: { } iterations } parts || iterations > MaxIterations)
            return false;

        var derived = Rfc2898DeriveBytes.Pbkdf2(
            presented, parts.Salt.Span, iterations, HashAlgorithmName.SHA512, HashLength);
        return CryptographicOperations.FixedTimeEquals(derived, parts.Hash.Span);
    }

    public ClientSecret Create(ReadOnlySpan<char> plaintext)
    {
        var salt = RandomNumberGenerator.GetBytes(SaltLength);
        var hash = Rfc2898DeriveBytes.Pbkdf2(plaintext, salt, Iterations, HashAlgorithmName.SHA512, HashLength);

        return new(new PhcString(
            Id,
            salt,
            hash,
            [new(IterationsParameter, Iterations.ToString(CultureInfo.InvariantCulture))]).ToString());
    }

    public IEnumerable<ZeeKayDaConfigurationFailure> ValidateStoredSecret(ClientSecret stored)
    {
        if (Read(stored) is not { } parts)
        {
            yield return new("sample.pbkdf2_sha512.malformed",
                "A PBKDF2-SHA512 secret is not $pbkdf2-sha512$i=<iterations>$<salt>$<hash> with a 16-byte salt and a 64-byte hash.");
        }
        else if (parts.Iterations is < Iterations or > MaxIterations)
        {
            yield return new("sample.pbkdf2_sha512.iterations_out_of_range",
                $"A PBKDF2-SHA512 secret has {parts.Iterations:N0} iterations, outside {Iterations:N0}–{MaxIterations:N0}.");
        }
    }

    private sealed record Parts(int? Version, int? Iterations, ReadOnlyMemory<byte> Salt, ReadOnlyMemory<byte> Hash);

    private static readonly Func<Parts, bool>[] Rules =
    [
        parts => parts.Version is null,
        parts => parts.Iterations is > 0,
        parts => parts.Salt.Length == SaltLength,
        parts => parts.Hash.Length == HashLength,
    ];

    private static Parts? Read(ClientSecret stored) =>
        PhcString.TryParse(stored.Value, out var phc)
        && new Parts(phc.Version, IterationsOf(phc), phc.Salt, phc.Hash) is var parts
        && Rules.All(rule => rule(parts))
            ? parts
            : null;

    private static int? IterationsOf(PhcString phc) =>
        phc.Parameters is [{ Key: IterationsParameter, Value: var text }]
        && int.TryParse(text, NumberStyles.None, CultureInfo.InvariantCulture, out var iterations)
            ? iterations
            : null;
}
