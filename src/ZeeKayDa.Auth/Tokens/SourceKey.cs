namespace ZeeKayDa.Auth.Tokens;

/// <summary>
/// One key as a signing key source lists it: the source's own stable identifier, the algorithm it
/// signs under, its public key material, and the window in which it is valid.
/// </summary>
/// <remarks>
/// A source only lists keys; the framework decides which one signs and which are published, from
/// the dates alone. <see cref="NotBefore"/> must be a date every replica agrees on — a certificate's
/// own <c>NotBefore</c>, a vault version's creation date — never "first seen by this process".
/// </remarks>
public sealed record SourceKey
{
    /// <summary>
    /// Initialises a <see cref="SourceKey"/>.
    /// </summary>
    /// <param name="id">The source's own stable identifier for this key. Never used as the JWKS/JWS
    /// <c>kid</c>: the framework always derives that from <paramref name="publicKey"/>.</param>
    /// <param name="algorithm">The signing algorithm this key is used with.</param>
    /// <param name="publicKey">The public key material. Never carries private key material.</param>
    /// <param name="notBefore">
    /// The instant the key becomes valid, or <see langword="null"/> for a key with no date. An
    /// undated key is accepted only when it is the only key the source lists.
    /// </param>
    /// <param name="expiresAt">The key's expiry, or <see langword="null"/> when it never expires.</param>
    public SourceKey(
        SourceKeyId id,
        SigningAlgorithm algorithm,
        PublicKeyParameters publicKey,
        DateTimeOffset? notBefore = null,
        DateTimeOffset? expiresAt = null)
    {
        Id = id;
        Algorithm = algorithm;
        PublicKey = publicKey;
        NotBefore = notBefore ?? DateTimeOffset.MinValue;
        ExpiresAt = expiresAt ?? DateTimeOffset.MaxValue;
    }

    /// <summary>Gets the source's own stable identifier for this key.</summary>
    public SourceKeyId Id { get; }

    /// <summary>Gets the signing algorithm this key is used with.</summary>
    public SigningAlgorithm Algorithm { get; }

    /// <summary>Gets the public key material.</summary>
    public PublicKeyParameters PublicKey { get; }

    /// <summary>
    /// Gets the instant the key becomes valid; <see cref="DateTimeOffset.MinValue"/> for an undated key.
    /// </summary>
    public DateTimeOffset NotBefore { get; }

    /// <summary>
    /// Gets the key's expiry; <see cref="DateTimeOffset.MaxValue"/> for a key that never expires.
    /// </summary>
    public DateTimeOffset ExpiresAt { get; }
}
