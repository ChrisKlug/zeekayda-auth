using System.Security.Cryptography.X509Certificates;

namespace ZeeKayDa.Auth.Tokens;

/// <summary>
/// One key as a signing key source lists it: the source's own stable identifier, its public key
/// material, and the dates it is published from and expires at. Every key signs under the source's
/// <see cref="ISigningKeySource.Algorithm"/>.
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
    /// <param name="publicKey">The public key material. Never carries private key material.</param>
    /// <param name="notBefore">
    /// The instant the key is published from, or <see langword="null"/> for a key with no date. The
    /// framework orders keys by it and counts <see cref="SigningKeyOptions.LeadTime"/> from it; it is
    /// not a validity gate, since no relying party can observe it. An undated key is accepted only
    /// when it is the only key the source lists.
    /// </param>
    /// <param name="expiresAt">The key's expiry, or <see langword="null"/> when it never expires.</param>
    public SourceKey(
        SourceKeyId id,
        PublicKeyParameters publicKey,
        DateTimeOffset? notBefore = null,
        DateTimeOffset? expiresAt = null)
    {
        Id = id;
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
    /// <exception cref="ZeeKayDaConfigurationException">
    /// Thrown with failure code <c>signing.certificate.unsupported_key_type</c> when the certificate
    /// carries neither an RSA nor an EC public key.
    /// </exception>
    public static SourceKey FromCertificate(X509Certificate2 certificate, SourceKeyId id)
    {
        ArgumentNullException.ThrowIfNull(certificate);

        // X509Certificate2 reports both ends of the validity window as local-kind DateTime, so
        // DateTimeOffset applies the local offset rather than reinterpreting them as UTC.
        return new SourceKey(
            id,
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

    /// <summary>Gets the public key material.</summary>
    public PublicKeyParameters PublicKey { get; }

    /// <summary>
    /// Gets the instant the key is published from; <see cref="DateTimeOffset.MinValue"/> for an undated key.
    /// </summary>
    public DateTimeOffset NotBefore { get; }

    /// <summary>
    /// Gets the key's expiry; <see cref="DateTimeOffset.MaxValue"/> for a key that never expires.
    /// </summary>
    public DateTimeOffset ExpiresAt { get; }
}
