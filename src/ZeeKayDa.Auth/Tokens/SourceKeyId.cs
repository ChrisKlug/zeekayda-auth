namespace ZeeKayDa.Auth.Tokens;

/// <summary>
/// A signing key source's own stable identifier for one key — a certificate thumbprint, a Key Vault
/// key-version id, a configured file name.
/// </summary>
/// <param name="Value">The source's own stable identifier for this key.</param>
/// <remarks>
/// <para>
/// <b>This is deliberately not the JWKS/JWS <c>kid</c>.</b> A source never supplies a <c>kid</c>:
/// <see cref="SigningKeySetBuilder"/> derives every <see cref="SigningKey.Kid"/> from that key's own
/// public material as an RFC 7638 JWK thumbprint. That split is what structurally prevents a raw
/// external identifier — a vault URL, an internal file path — from reaching a token header or the
/// public JWKS. A source's job is to say <i>which of its own keys</i> it means; naming it publicly is
/// the framework's.
/// </para>
/// <para>
/// This value is what <see cref="ISigningKeySource.CreateSignerAsync"/> receives, so it must be
/// enough for the source to reopen exactly that key. If a key's material can change while this
/// identifier stays the same — a database "current key" pointer, a KMS alias — this
/// <see cref="Value"/> <b>must</b> change with it, or a signer opened for the old material will keep
/// signing under a <c>kid</c> derived from the new.
/// </para>
/// </remarks>
public readonly record struct SourceKeyId(string Value);
