namespace ZeeKayDa.Auth.Tokens;

/// <summary>
/// One key's identity and public material, as the framework sees it — never private key material.
/// </summary>
/// <remarks>
/// The only way to obtain an instance is <see cref="SigningKeySetBuilder.Build"/>, and its
/// constructor is <see langword="internal"/>, so nothing outside this assembly can produce a
/// <see cref="SigningKey"/> whose <see cref="Kid"/> disagrees with <see cref="PublicKey"/> — the
/// builder always derives <see cref="Kid"/> via <see cref="JwkThumbprint"/>.
/// </remarks>
public sealed class SigningKey
{
    internal SigningKey(
        SourceKeyId sourceId,
        string kid,
        SigningAlgorithm algorithm,
        PublicKeyParameters publicKey,
        DateTimeOffset? expiresAt,
        DateTimeOffset? notBefore = null)
    {
        SourceId = sourceId;
        Kid = kid;
        Algorithm = algorithm;
        PublicKey = publicKey;
        ExpiresAt = expiresAt;
        NotBefore = notBefore;
    }

    /// <summary>Gets the source's own identifier for this key.</summary>
    public SourceKeyId SourceId { get; }

    /// <summary>
    /// Gets the JWKS/JWS key identifier, always an RFC 7638 thumbprint of <see cref="PublicKey"/>.
    /// </summary>
    public string Kid { get; }

    /// <summary>Gets the signing algorithm this key is used with.</summary>
    public SigningAlgorithm Algorithm { get; }

    /// <summary>Gets the public key material. Never carries private key material.</summary>
    public PublicKeyParameters PublicKey { get; }

    /// <summary>Gets the key's expiry, or <see langword="null"/> when it never expires.</summary>
    public DateTimeOffset? ExpiresAt { get; }

    /// <summary>
    /// Gets the instant this key's own credential becomes valid, or <see langword="null"/> when it
    /// is valid from the moment it exists — carried through from
    /// <see cref="SourceKey.NotBefore"/>.
    /// </summary>
    public DateTimeOffset? NotBefore { get; }
}
