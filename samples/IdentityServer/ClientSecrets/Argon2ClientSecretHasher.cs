using System.Globalization;
using Isopoh.Cryptography.Argon2;
using ZeeKayDa.Auth;
using ZeeKayDa.Auth.Clients;

namespace ZeeKayDa.Auth.Samples.IdentityServer.ClientSecrets;

/// <summary>
/// Argon2id through Isopoh.Cryptography.Argon2, a library that already writes PHC strings
/// (<c>$argon2id$v=19$m=65536,t=3,p=1$&lt;salt&gt;$&lt;hash&gt;</c>). The library writes and reads the
/// string; this class reads its cost parameters with <see cref="PhcString"/> to bound them.
/// </summary>
public sealed class Argon2ClientSecretHasher : IClientSecretHasher
{
    private const int Version = 19;

    // Work is memory (KiB) times passes. The floor is OWASP's weakest Argon2id configuration
    // (19 MiB, two passes); the ceiling is four times what Create writes, so one verification
    // cannot cost the host gigabytes or seconds.
    private const int MinMemory = 19_456;
    private const int MaxMemory = 262_144;
    private const long MinWork = 19_456L * 2;
    private const long MaxWork = 65_536L * 3 * 4;
    private const int MaxParallelism = 4;

    // Exactly what Create writes, so a stored value cannot carry an oversized field.
    private const int SaltLength = 16;
    private const int HashLength = 32;
    private const int MaxValueLength = 128;

    public IReadOnlySet<string> AlgorithmIds { get; } = new HashSet<string>(["argon2id"], StringComparer.Ordinal);

    // The library takes strings only, so the presented secret is copied into one.
    public bool Verify(ClientSecret stored, ReadOnlySpan<char> presented) =>
        Problem(stored) is null && Argon2.Verify(stored.Value, presented.ToString());

    // 64 MiB and three passes, above OWASP's minimum Argon2id configurations.
    public ClientSecret Create(ReadOnlySpan<char> plaintext) =>
        new(Argon2.Hash(
            plaintext.ToString(), timeCost: 3, memoryCost: 65536, parallelism: 1, type: Argon2Type.HybridAddressing));

    public IEnumerable<ZeeKayDaConfigurationFailure> ValidateStoredSecret(ClientSecret stored) =>
        Problem(stored) is { } problem ? [new("sample.argon2.unacceptable", problem)] : [];

    private sealed record Parts(int? Version, int? Memory, int? Passes, int? Parallelism, int SaltLength, int HashLength);

    private const string Shape = "An Argon2id secret is not $argon2id$v=19$m=<KiB>,t=<passes>,p=<lanes>$<salt>$<hash>.";

    private static readonly Func<Parts, string?>[] Rules =
    [
        parts => parts.Version == Version ? null : Shape,
        parts => parts is { Memory: not null, Passes: not null, Parallelism: not null } ? null : Shape,
        parts => parts.Memory is >= MinMemory and <= MaxMemory
            ? null
            : $"An Argon2id secret's memory must be {MinMemory}–{MaxMemory} KiB.",
        parts => (long)parts.Memory!.Value * parts.Passes!.Value is >= MinWork and <= MaxWork
            ? null
            : $"An Argon2id secret's memory × passes must be {MinWork}–{MaxWork}.",
        parts => parts.Parallelism is >= 1 and <= MaxParallelism
            ? null
            : $"An Argon2id secret's lanes must be 1–{MaxParallelism}.",
        parts => parts.SaltLength == SaltLength && parts.HashLength == HashLength
            ? null
            : $"An Argon2id secret needs a {SaltLength}-byte salt and a {HashLength}-byte hash.",
    ];

    private static string? Problem(ClientSecret stored)
    {
        if (stored.Value is not { Length: <= MaxValueLength } || !PhcString.TryParse(stored.Value, out var phc))
            return Shape;

        var parts = phc.Parameters is [{ Key: "m", Value: var m }, { Key: "t", Value: var t }, { Key: "p", Value: var p }]
            ? new Parts(phc.Version, IntOf(m), IntOf(t), IntOf(p), phc.Salt.Length, phc.Hash.Length)
            : new Parts(phc.Version, null, null, null, phc.Salt.Length, phc.Hash.Length);

        return Rules.Select(rule => rule(parts)).FirstOrDefault(problem => problem is not null);
    }

    private static int? IntOf(string text) =>
        int.TryParse(text, NumberStyles.None, CultureInfo.InvariantCulture, out var value) ? value : null;
}
