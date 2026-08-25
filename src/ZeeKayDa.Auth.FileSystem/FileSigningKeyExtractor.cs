using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using ZeeKayDa.Auth.Tokens;

namespace ZeeKayDa.Auth.FileSystem;

/// <summary>
/// Extracts public and private key handles from an already-loaded <see cref="X509Certificate2"/>.
/// </summary>
/// <remarks>
/// Uses only <c>GetRSAPublicKey()</c> / <c>GetRSAPrivateKey()</c> / <c>GetECDsaPublicKey()</c> /
/// <c>GetECDsaPrivateKey()</c> — never <c>.PrivateKey</c> or <c>ExportParameters(true)</c>. These
/// accessors return handles that remain valid after the parent <see cref="X509Certificate2"/> is
/// disposed, which is what lets the caller dispose the certificate once handles are extracted.
/// </remarks>
internal static class FileSigningKeyExtractor
{
    /// <summary>Extracts a public-only key handle and its key type from a certificate.</summary>
    public static (AsymmetricAlgorithm PublicKey, SigningKeyType KeyType) ExtractPublicKey(
        X509Certificate2 certificate, string path)
    {
        var rsa = certificate.GetRSAPublicKey();
        if (rsa is not null)
            return (rsa, SigningKeyType.Rsa);

        var ec = certificate.GetECDsaPublicKey();
        if (ec is not null)
            return (ec, SigningKeyType.Ec);

        throw UnsupportedKeyType(path);
    }

    /// <summary>Extracts a private key handle and its key type from a certificate.</summary>
    public static (AsymmetricAlgorithm PrivateKey, SigningKeyType KeyType) ExtractPrivateKey(
        X509Certificate2 certificate, string path)
    {
        if (!certificate.HasPrivateKey)
        {
            throw new ZeeKayDaConfigurationException(new ZeeKayDaConfigurationFailure(
                "signing.file_signing.private_key_not_found",
                $"The signing key file '{path}' was loaded but carries no private key. " +
                "AddPemFileSigning/AddPfxFileSigning require a file containing both the certificate " +
                "and its private key."));
        }

        var rsa = certificate.GetRSAPrivateKey();
        if (rsa is not null)
            return (rsa, SigningKeyType.Rsa);

        var ec = certificate.GetECDsaPrivateKey();
        if (ec is not null)
            return (ec, SigningKeyType.Ec);

        // HasPrivateKey was true but neither accessor returned a handle: a distinct root cause from
        // "no private key at all", still surfaced under the same failure code.
        throw new ZeeKayDaConfigurationException(new ZeeKayDaConfigurationFailure(
            "signing.file_signing.private_key_not_found",
            $"The signing key file '{path}' has a private key, but it could not be accessed. " +
            "Verify the file is not corrupt and, for PFX files, that the correct password was supplied."));
    }

    /// <summary>
    /// Builds the <see cref="SourceKey"/> a file-based signing key source reports for one configured
    /// slot, from that slot's certificate and nothing else.
    /// </summary>
    /// <param name="certificate">The slot's certificate. Only public material is read.</param>
    /// <param name="certificatePath">
    /// The configured path, used as the source's own identifier for this key. Never the JWKS/JWS
    /// <c>kid</c> — <see cref="SigningKeySetBuilder"/> derives that from the public material — but it
    /// is what every configuration failure names, so it must be the path the operator typed.
    /// </param>
    /// <param name="algorithm">The algorithm the slot is signed under, from the provider's options.</param>
    /// <remarks>
    /// No algorithm/key-type check happens here. <see cref="SigningKeySetBuilder"/> is the single
    /// choke point for that, and it checks more than a provider-local version would.
    /// </remarks>
    public static SourceKey ToSourceKey(
        X509Certificate2 certificate, string certificatePath, SigningAlgorithm algorithm)
    {
        var (rawPublicKey, keyType) = ExtractPublicKey(certificate, certificatePath);
        using var publicKey = rawPublicKey;

        // X509Certificate2 reports both ends of the validity window as local-kind DateTime, so the
        // conversion below applies the local offset rather than reinterpreting them as UTC.
        return new SourceKey(
            new SourceKeyId(certificatePath),
            algorithm,
            ToPublicKeyParameters(publicKey, keyType),
            ExpiresAt: new DateTimeOffset(certificate.NotAfter),
            NotBefore: new DateTimeOffset(certificate.NotBefore));
    }

    /// <summary>
    /// Exports <paramref name="publicKey"/>'s public parameters. The cast is safe:
    /// <see cref="ExtractPublicKey"/> only ever returns an <see cref="RSA"/> paired with
    /// <see cref="SigningKeyType.Rsa"/> or an <see cref="ECDsa"/> paired with
    /// <see cref="SigningKeyType.Ec"/>.
    /// </summary>
    private static PublicKeyParameters ToPublicKeyParameters(AsymmetricAlgorithm publicKey, SigningKeyType keyType) =>
        keyType == SigningKeyType.Rsa
            ? PublicKeyParameters.FromRsa(((RSA)publicKey).ExportParameters(false))
            : PublicKeyParameters.FromEc(((ECDsa)publicKey).ExportParameters(false));

    /// <summary>Best-effort key type/size description for the informational startup log line.</summary>
    public static (string KeyType, int KeySizeBits) DescribeKeyForLogging(X509Certificate2 certificate)
    {
        using var rsa = certificate.GetRSAPublicKey();
        if (rsa is not null)
            return ("RSA", rsa.KeySize);

        using var ec = certificate.GetECDsaPublicKey();
        if (ec is not null)
            return ("EC", ec.KeySize);

        return ("unknown", 0);
    }

    private static ZeeKayDaConfigurationException UnsupportedKeyType(string path) =>
        new(new ZeeKayDaConfigurationFailure(
            "signing.file_signing.unsupported_key_type",
            $"The signing key file '{path}' does not carry an RSA or EC public key. Only RSA and EC " +
            "certificates are supported for JWT signing."));
}
