namespace ZeeKayDa.Auth.Tokens;

/// <summary>
/// One key as a signing key source reports it: the source's own stable identifier, the algorithm it
/// signs (or would sign) under, its public key material, and its expiry.
/// </summary>
/// <param name="Id">The source's own stable identifier for this key. Never used as the JWKS/JWS
/// <c>kid</c> directly — <see cref="SigningKeySetBuilder"/> always derives that from
/// <paramref name="PublicKey"/>.</param>
/// <param name="Algorithm">The signing algorithm this key is used with.</param>
/// <param name="PublicKey">The public key material. Never carries private key material.</param>
/// <param name="ExpiresAt">
/// The key's expiry, or <see langword="null"/> when it never expires.
/// </param>
/// <param name="NotBefore">
/// The instant the key's own credential becomes valid, or <see langword="null"/> when it is valid
/// from the moment it exists. A certificate-backed source reports its certificate's
/// <c>NotBefore</c>; a source whose keys carry no validity window reports <see langword="null"/>.
/// </param>
/// <remarks>
/// <see cref="NotBefore"/> and <see cref="ExpiresAt"/> are the two ends of one validity window, and
/// both are facts about the credential rather than policy: neither decides which key signs. That
/// decision belongs entirely to which slot a key is configured in. The ring rejects a signing key
/// whose window has not opened or has already closed.
/// </remarks>
public sealed record SourceKey(
    SourceKeyId Id,
    SigningAlgorithm Algorithm,
    PublicKeyParameters PublicKey,
    DateTimeOffset? ExpiresAt,
    DateTimeOffset? NotBefore = null);
