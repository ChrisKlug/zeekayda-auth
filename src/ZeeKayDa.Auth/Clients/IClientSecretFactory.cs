namespace ZeeKayDa.Auth.Clients;

/// <summary>
/// Creates a new hashed client credential from a plaintext secret using the configured
/// default <see cref="IClientSecretHasher"/>.
/// </summary>
/// <remarks>
/// <para>
/// <strong>This method is CPU-intensive.</strong> The default PBKDF2 hasher performs
/// 600,000 iterations per call (~300 ms on typical server hardware). Callers MUST NOT
/// invoke this method on a hot request path. It is intended for administrative operations
/// such as client registration or credential rotation, which must be rate-limited and
/// authenticated at the application layer.
/// </para>
/// <para>
/// <strong>The plaintext parameter is sensitive.</strong> Callers MUST NOT log, trace,
/// serialise, or pass the plaintext value through any intermediary that may capture method
/// arguments (such as DI interceptors or AOP wrappers). The framework does not zero the
/// string after hashing — string immutability and GC timing mean the caller owns
/// responsibility for minimising the lifetime of the plaintext value.
/// Callers holding the plaintext in a <c>char[]</c> who want to zero it after use should
/// resolve <see cref="IClientSecretHasher"/> directly and call its
/// <c>Create(ReadOnlySpan&lt;char&gt;)</c> overload instead.
/// </para>
/// <para>
/// The strength of the returned credential is determined by the host's configured default
/// <see cref="IClientSecretHasher"/>. The built-in <see cref="Pbkdf2ClientSecretHasher"/>
/// enforces a minimum of 600,000 iterations.
/// </para>
/// </remarks>
public interface IClientSecretFactory
{
    /// <summary>
    /// Creates a new hashed credential from the given plaintext secret.
    /// </summary>
    /// <param name="plaintext">
    /// The plaintext client secret. Must be non-null, non-empty, and non-whitespace.
    /// </param>
    /// <returns>A hashed credential suitable for storage in an <see cref="IClientRegistration"/>.</returns>
    /// <exception cref="ArgumentException">
    /// Thrown when <paramref name="plaintext"/> is null, empty, or whitespace.
    /// </exception>
    IClientSecret Create(string plaintext);
}
