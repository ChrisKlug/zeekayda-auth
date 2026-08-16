namespace ZeeKayDa.Auth.Tokens;

/// <summary>
/// A lightweight wrapper over a signing provider's own stable key identifier (e.g. a certificate
/// thumbprint, a Key Vault key-version id).
/// </summary>
/// <param name="Value">The provider's own stable identifier for this key.</param>
/// <remarks>
/// <para>
/// This is <b>not</b> the JWKS/JWS <c>kid</c>. The base class derives the public <c>kid</c> from
/// <see cref="KeyListing.PublicKey"/> via <see cref="JwkThumbprint.Compute(System.Security.Cryptography.RSAParameters)"/>
/// (or the EC overload) — a provider never supplies the <c>kid</c> directly, which structurally
/// rules out a raw external identifier leaking into a token header or the public JWKS.
/// </para>
/// <para>
/// If a key's material can change while this identifier stays the same (for example, a
/// database-backed "current key" pointer or a KMS alias), this <see cref="Value"/> <b>must</b>
/// change too. The base class caches the signer it obtained for a given <see cref="Value"/> and
/// only calls <see cref="JwtSigningService{TOptions}.CreateSignerAsync"/> again once it observes a
/// different <see cref="Value"/> or a different derived <c>kid</c> — a stable identifier over
/// rotated material risks the cached signer continuing to sign with superseded key material.
/// </para>
/// </remarks>
public readonly record struct KeyId(string Value);
