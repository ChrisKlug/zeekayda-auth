namespace ZeeKayDa.Auth.Tokens;

/// <summary>
/// A signing key source's own stable identifier for one key — a certificate thumbprint, a Key Vault
/// key-version id, a configured file name.
/// </summary>
/// <param name="Value">The source's own stable identifier for this key.</param>
/// <remarks>
/// <para>
/// <b>Deliberately not the <c>kid</c>.</b> The framework derives every <see cref="SigningKey.Kid"/> from
/// the public key, so a vault URL or file path can never reach a token header or the JWKS.
/// </para>
/// <para>
/// <see cref="ISigningKeySource.CreateSignerAsync"/> receives it, so it must reopen exactly that key. If
/// the material behind an identifier can change, such as a KMS alias, the identifier <b>must</b> change
/// with it, or a signer opened for the old material signs under the new <c>kid</c>.
/// </para>
/// </remarks>
public readonly record struct SourceKeyId(string Value);
