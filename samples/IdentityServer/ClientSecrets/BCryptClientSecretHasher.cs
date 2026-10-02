using ZeeKayDa.Auth.Clients;

namespace ZeeKayDa.Auth.Samples.IdentityServer.ClientSecrets;

/// <summary>
/// bcrypt through BCrypt.Net-Next, a library that writes its own self-describing string
/// (<c>$2b$12$&lt;salt and hash&gt;</c>). The string is stored exactly as the library wrote it, and the
/// library reads it back; nothing here parses it.
/// </summary>
/// <remarks>
/// bcrypt reads only the first 72 bytes of a secret, which a generated client secret never reaches.
/// The library's verification compares in fixed time.
/// </remarks>
public sealed class BCryptClientSecretHasher : IClientSecretHasher
{
    private const int WorkFactor = 12;

    // bcrypt's revisions differ only in old implementation bugs; the library reads all three.
    public IReadOnlySet<string> AlgorithmIds { get; } =
        new HashSet<string>(["2a", "2b", "2y"], StringComparer.Ordinal);

    // The library takes strings only, so the presented secret is copied into one.
    public bool Verify(ClientSecret stored, ReadOnlySpan<char> presented) =>
        BCrypt.Net.BCrypt.Verify(presented.ToString(), stored.Value);

    public ClientSecret Create(ReadOnlySpan<char> plaintext) =>
        new(BCrypt.Net.BCrypt.HashPassword(plaintext.ToString(), WorkFactor));
}
