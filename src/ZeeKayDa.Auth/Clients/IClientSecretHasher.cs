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
/// <see cref="Create(System.ReadOnlySpan{char})"/> is the memory-safe primary overload:
/// callers who hold the plaintext in a mutable <c>char[]</c> can zero the buffer immediately
/// after the call, before the GC has a chance to observe it.
/// <see cref="Create(string)"/> is a convenience overload for callers who already have a
/// managed string and accept that its contents may remain in memory until the next GC cycle.
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
    /// Creates a new hashed credential from a plaintext secret held in a span.
    /// Rejects empty and whitespace-only spans (throws <see cref="ArgumentException"/>).
    /// Spans cannot be null, so no null check is performed.
    /// </summary>
    /// <remarks>
    /// This is the memory-safe primary overload. Callers who allocate the plaintext in a
    /// mutable buffer should zero it immediately after this call:
    /// <code>
    /// char[] secret = /* decoded from buffer */;
    /// IClientSecret stored;
    /// try { stored = hasher.Create(secret.AsSpan()); }
    /// finally { Array.Clear(secret); }
    /// </code>
    /// <para>
    /// This guarantee holds only when the registered hasher overrides
    /// <c>CreateCore(ReadOnlySpan&lt;char&gt;)</c>. The built-in PBKDF2 hasher does.
    /// Custom hashers that only override <c>CreateCore(string)</c> will still allocate an
    /// intermediate managed string via the base-class fallback, defeating the zeroing benefit.
    /// </para>
    /// </remarks>
    /// <param name="plaintext">The plaintext secret to hash.</param>
    /// <exception cref="ArgumentException">
    /// Thrown when <paramref name="plaintext"/> is empty or contains only whitespace.
    /// </exception>
    IClientSecret Create(ReadOnlySpan<char> plaintext);

    /// <summary>
    /// Creates a new hashed credential from a plaintext secret string.
    /// Convenience overload for callers who already hold a managed string.
    /// Rejects null, empty, or whitespace-only input.
    /// </summary>
    /// <remarks>
    /// This overload allocates a managed <see langword="string"/> that the .NET garbage
    /// collector does not guarantee to erase promptly. Prefer
    /// <see cref="Create(System.ReadOnlySpan{char})"/> when the secret is held in a mutable
    /// buffer that can be zeroed after use.
    /// </remarks>
    /// <param name="plaintext">The plaintext secret to hash.</param>
    /// <exception cref="ArgumentNullException">
    /// Thrown when <paramref name="plaintext"/> is <see langword="null"/>.
    /// </exception>
    /// <exception cref="ArgumentException">
    /// Thrown when <paramref name="plaintext"/> is empty or contains only whitespace.
    /// </exception>
    IClientSecret Create(string plaintext)
    {
        ArgumentNullException.ThrowIfNull(plaintext);
        return Create(plaintext.AsSpan());
    }

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
