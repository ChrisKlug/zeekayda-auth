using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using ZeeKayDa.Auth.Tokens;

namespace ZeeKayDa.Auth.FileSystem;

/// <summary>
/// Extracts public and private key handles from an already-loaded <see cref="X509Certificate2"/>.
/// </summary>
/// <remarks>
/// Uses only <c>GetRSAPublicKey()</c> / <c>GetRSAPrivateKey()</c> / <c>GetECDsaPublicKey()</c> /
/// <c>GetECDsaPrivateKey()</c> — never <c>.PrivateKey</c>, never <c>ExportParameters(true)</c> — the
/// same discipline <c>WindowsCertificateKeyExtractor</c> applies, preferring CNG/CAPI-backed handles
/// over exporting raw key bytes into managed memory. These accessors return handle objects that
/// remain valid and usable independently after the parent <see cref="X509Certificate2"/> is
/// disposed, which is what lets the caller dispose every loaded certificate once all needed handles
/// have been extracted.
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

        // HasPrivateKey was true but neither accessor returned a handle: the key exists but could
        // not be reconstructed from the loaded certificate — a distinct root cause from "no private
        // key at all", still surfaced under the same failure code with a tailored message.
        throw new ZeeKayDaConfigurationException(new ZeeKayDaConfigurationFailure(
            "signing.file_signing.private_key_not_found",
            $"The signing key file '{path}' has a private key, but it could not be accessed. " +
            "Verify the file is not corrupt and, for PFX files, that the correct password was supplied."));
    }

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
