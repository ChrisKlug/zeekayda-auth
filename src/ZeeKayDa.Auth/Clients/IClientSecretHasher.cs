namespace ZeeKayDa.Auth.Clients;

/// <summary>
/// Creates and verifies hashed client secrets.
/// </summary>
/// <remarks>
/// <para>
/// Implementations MUST use fixed-time comparison (e.g.
/// <see cref="System.Security.Cryptography.CryptographicOperations.FixedTimeEquals"/>);
/// MUST NOT throw from <c>Verify</c> (return <see langword="false"/> on internal error);
/// MUST NOT log the presented secret; and MUST be safe for concurrent use (singleton-safe).
/// </para>
/// <para>
/// To add a new hashing algorithm, define a sub-interface of <see cref="IClientSecret"/>,
/// a sealed record implementing it, and a class extending
/// <c>ClientSecretHasher&lt;TSecret&gt;</c>. Register it with <c>AddSecretsHasher&lt;T&gt;()</c>.
/// </para>
/// </remarks>
public interface IClientSecretHasher
{
    /// <summary>
    /// Returns <see langword="true"/> if this hasher can handle the given stored credential.
    /// </summary>
    bool CanHandle(IClientSecret secret);

    /// <summary>
    /// Verifies a presented plaintext secret against a stored hashed credential.
    /// Returns <see langword="false"/> on mismatch or internal error — never throws.
    /// </summary>
    /// <param name="stored">The stored hashed credential.</param>
    /// <param name="presented">The plaintext secret presented by the client.</param>
    bool Verify(IClientSecret stored, ReadOnlySpan<char> presented);

    /// <summary>
    /// Creates a new hashed credential from a plaintext secret.
    /// Rejects null, empty, or whitespace-only input.
    /// </summary>
    IClientSecret Create(string plaintext);
}
