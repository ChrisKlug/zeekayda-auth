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
/// <para>
/// <strong>Managed-string limitation.</strong> The plaintext passed to <see cref="Create"/>
/// is a managed <see langword="string"/> whose contents the .NET garbage collector does not
/// guarantee to erase promptly. Callers should treat the created credential as potentially
/// resident in memory until the next GC cycle. <see cref="Verify"/> accepts a
/// <see cref="System.ReadOnlySpan{T}">ReadOnlySpan&lt;char&gt;</see>, so callers who hold the
/// presented secret in a <c>char[]</c> or similar mutable buffer can zero it out immediately
/// after the call.
/// <code>
/// char[] presented = /* read from network buffer */;
/// try
/// {
///     bool valid = hasher.Verify(storedSecret, presented);
/// }
/// finally
/// {
///     Array.Clear(presented); // erase before GC can observe it
/// }
/// </code>
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

    /// <summary>
    /// Returns any registration-time failures for the given stored credential.
    /// Called during startup validation to enforce per-hasher constraints on stored credentials
    /// (for example, a minimum iteration-count or work-factor floor).
    /// Returns an empty sequence when the credential is acceptable.
    /// </summary>
    /// <remarks>
    /// The default implementation returns no failures. Override to express startup constraints
    /// specific to your credential type. The framework calls this only for credentials whose
    /// hasher returns <see langword="true"/> from <see cref="CanHandle"/>, so
    /// <paramref name="credential"/> is always a type this hasher owns.
    /// The <paramref name="clientId"/> parameter is for diagnostic message formatting only.
    /// </remarks>
    IEnumerable<ZeeKayDaConfigurationFailure> GetRegistrationFailures(
        IClientSecret credential, string clientId) => [];
}
