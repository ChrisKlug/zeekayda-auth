using Isopoh.Cryptography.Argon2;
using ZeeKayDa.Auth.Clients;

namespace ZeeKayDa.Auth.Samples.IdentityServer.ClientSecrets;

/// <summary>
/// Argon2id through Isopoh.Cryptography.Argon2, a library that already writes PHC strings
/// (<c>$argon2id$v=19$m=65536,t=3,p=1$&lt;salt&gt;$&lt;hash&gt;</c>). The string is stored exactly as the
/// library wrote it, and the library reads it back; nothing here parses it.
/// </summary>
public sealed class Argon2ClientSecretHasher : IClientSecretHasher
{
    public IReadOnlySet<string> AlgorithmIds { get; } = new HashSet<string>(["argon2id"], StringComparer.Ordinal);

    // The library takes strings only, so the presented secret is copied into one.
    public bool Verify(ClientSecret stored, ReadOnlySpan<char> presented) =>
        Argon2.Verify(stored.Value, presented.ToString());

    // 64 MiB and three passes, above OWASP's minimum Argon2id configurations.
    public ClientSecret Create(ReadOnlySpan<char> plaintext) =>
        new(Argon2.Hash(
            plaintext.ToString(), timeCost: 3, memoryCost: 65536, parallelism: 1, type: Argon2Type.HybridAddressing));
}
