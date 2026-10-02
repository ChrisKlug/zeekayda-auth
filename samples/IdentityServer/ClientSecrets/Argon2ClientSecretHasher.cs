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

    private static string? Problem(ClientSecret stored)
    {
        if (stored.Value is not { Length: <= MaxValueLength }
            || !PhcString.TryParse(stored.Value, out var phc)
            || phc.Version != Version
            || phc.Parameters is not [{ Key: "m", Value: var m }, { Key: "t", Value: var t }, { Key: "p", Value: var p }]
            || !TryReadInt(m, out var memory) || !TryReadInt(t, out var passes) || !TryReadInt(p, out var parallelism))
        {
            return $"An Argon2id secret is not $argon2id$v={Version}$m=<KiB>,t=<passes>,p=<lanes>$<salt>$<hash>.";
        }

        var work = (long)memory * passes;
        if (memory is < MinMemory or > MaxMemory || passes < 1 || work is < MinWork or > MaxWork || parallelism is < 1 or > MaxParallelism)
        {
            return $"An Argon2id secret has m={memory}, t={passes}, p={parallelism}: memory must be " +
                $"{MinMemory}–{MaxMemory} KiB, memory × passes {MinWork}–{MaxWork}, and lanes 1–{MaxParallelism}.";
        }

        return phc.Salt.Length != SaltLength || phc.Hash.Length != HashLength
            ? $"An Argon2id secret needs a {SaltLength}-byte salt and a {HashLength}-byte hash."
            : null;
    }

    private static bool TryReadInt(string text, out int value) =>
        int.TryParse(text, NumberStyles.None, CultureInfo.InvariantCulture, out value);
}
