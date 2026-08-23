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
public sealed record SourceKey(SourceKeyId Id, SigningAlgorithm Algorithm, PublicKeyParameters PublicKey, DateTimeOffset? ExpiresAt);
