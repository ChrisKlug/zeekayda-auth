namespace ZeeKayDa.Auth.Tokens;

/// <summary>
/// Pure public data describing one trusted signing key, returned by
/// <see cref="JwtSigningService{TOptions}.ListKeysAsync"/>. Never carries private material.
/// </summary>
/// <param name="Id">
/// The provider's own stable identifier for this key (a certificate thumbprint, a Key Vault
/// key-version id, …). Not the JWKS/JWS <c>kid</c> — see <see cref="KeyId"/>.
/// </param>
/// <param name="Algorithm">The signing algorithm this key is used with.</param>
/// <param name="PublicKey">The public-only RSA/EC key material.</param>
/// <param name="ActivateAt">
/// The instant this key becomes eligible to be the active signer, or <see langword="null"/> (or a
/// past instant) when it is eligible from startup/bootstrap.
/// </param>
/// <param name="ExpiresAt">
/// The hard expiry instant (e.g. a certificate's <c>NotAfter</c>) — distinct from the derived
/// retirement window, which the base class computes separately.
/// </param>
public sealed record KeyListing(
    KeyId Id,
    SigningAlgorithm Algorithm,
    PublicKeyParameters PublicKey,
    DateTimeOffset? ActivateAt,
    DateTimeOffset ExpiresAt);
