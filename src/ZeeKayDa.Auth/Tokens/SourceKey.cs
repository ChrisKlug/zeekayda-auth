using System.Security.Cryptography.X509Certificates;

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
    /// undated key is accepted only when it is the only key the source lists. The framework signs
    /// with a key up to five minutes before this instant, to tolerate a host clock running behind
    /// the machine that minted the credential.
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

    /// <summary>
    /// Creates the <see cref="SourceKey"/> for a certificate's public key, dated by the certificate's
    /// own validity window.
    /// </summary>
    /// <param name="certificate">The certificate. Only its public material is read.</param>
    /// <param name="id">The source's own stable identifier for this key, named in every
    /// configuration failure about it.</param>
    /// <param name="algorithm">The signing algorithm this key is used with.</param>
    /// <exception cref="ArgumentOutOfRangeException">
    /// Thrown when <paramref name="algorithm"/> is not a defined <see cref="SigningAlgorithm"/> member.
    /// </exception>
    /// <exception cref="ZeeKayDaConfigurationException">
    /// Thrown with failure code <c>signing.certificate.unsupported_key_type</c> when the certificate
    /// carries neither an RSA nor an EC public key.
    /// </exception>
    public static SourceKey FromCertificate(X509Certificate2 certificate, SourceKeyId id, SigningAlgorithm algorithm)
    {
        ArgumentNullException.ThrowIfNull(certificate);
        if (!Enum.IsDefined(algorithm))
            throw new ArgumentOutOfRangeException(nameof(algorithm), algorithm, $"Not a defined {nameof(SigningAlgorithm)} member.");

        // X509Certificate2 reports both ends of the validity window as local-kind DateTime, so
        // DateTimeOffset applies the local offset rather than reinterpreting them as UTC.
        return new SourceKey(
            id,
            algorithm,
            PublicKeyOf(certificate, id),
            notBefore: new DateTimeOffset(certificate.NotBefore),
            expiresAt: new DateTimeOffset(certificate.NotAfter));
    }

    private static PublicKeyParameters PublicKeyOf(X509Certificate2 certificate, SourceKeyId id)
    {
        using (var rsa = certificate.GetRSAPublicKey())
        {
            if (rsa is not null)
                return PublicKeyParameters.FromRsa(rsa.ExportParameters(false));
        }

        using (var ec = certificate.GetECDsaPublicKey())
        {
            if (ec is not null)
                return PublicKeyParameters.FromEc(ec.ExportParameters(false));
        }

        throw new ZeeKayDaConfigurationException(
            new ZeeKayDaConfigurationFailure(
                "signing.certificate.unsupported_key_type",
                $"The certificate for key '{id.Value}' does not carry an RSA or EC public key. Only RSA and EC " +
                "certificates are supported for JWT signing."));
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
