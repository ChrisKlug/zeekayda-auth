namespace ZeeKayDa.Auth.Clients;

/// <summary>
/// Immutable value type holding a PBKDF2-hashed client secret.
/// </summary>
/// <param name="Iterations">Number of PBKDF2 iterations used to derive the hash.</param>
/// <param name="Salt">Random salt used during key derivation.</param>
/// <param name="Hash">PBKDF2 output hash.</param>
/// <remarks>
/// <para>
/// <strong>Buffer ownership.</strong> <see cref="Salt"/> and <see cref="Hash"/> expose their
/// underlying <c>byte[]</c> arrays directly — intentional for ORM-mapper friendliness (flat
/// columns, <c>[NotMapped]</c> projection). The constructor does not copy them, so consumers
/// building registrations from external sources own the buffer lifetime. The framework never uses
/// a store's instance directly: when it looks a client up it takes
/// <see cref="IClientCredential.Snapshot"/>, which copies both arrays, and uses only the copy.
/// </para>
/// <para>
/// Salt and PBKDF2 output hashes are not secret values; the exposure of the underlying arrays is
/// a documented contract, not a security concern.
/// </para>
/// </remarks>
public sealed record Pbkdf2ClientSecret(int Iterations, byte[] Salt, byte[] Hash)
    : IPbkdf2ClientSecret;
