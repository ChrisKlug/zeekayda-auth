namespace ZeeKayDa.Auth.Tokens;

/// <summary>
/// A lightweight wrapper over a signing provider's own stable key identifier (e.g. a certificate
/// thumbprint, a Key Vault key-version id).
/// </summary>
/// <param name="Value">The provider's own stable identifier for this key.</param>
/// <remarks>
/// This is <b>not</b> the JWKS/JWS <c>kid</c>. The base class derives the public <c>kid</c> from
/// <see cref="KeyListing.PublicKey"/> via <see cref="JwkThumbprint.Compute(System.Security.Cryptography.RSAParameters)"/>
/// (or the EC overload) — a provider never supplies the <c>kid</c> directly, which structurally
/// rules out a raw external identifier leaking into a token header or the public JWKS (ADR 0015 §2).
/// </remarks>
public readonly record struct KeyId(string Value);
