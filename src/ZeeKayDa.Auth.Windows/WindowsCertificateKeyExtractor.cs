using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using ZeeKayDa.Auth.Tokens;

namespace ZeeKayDa.Auth.Windows;

/// <summary>
/// Extracts public and private key handles from an already-obtained <see cref="X509Certificate2"/>.
/// </summary>
/// <remarks>
/// Uses only <c>GetRSAPublicKey()</c> / <c>GetRSAPrivateKey()</c> / <c>GetECDsaPublicKey()</c> /
/// <c>GetECDsaPrivateKey()</c> — never <c>.PrivateKey</c>, never <c>ExportParameters(true)</c> — per the issue's security
/// requirement to prefer CNG/CAPI-backed handles over exporting raw key bytes into managed memory.
/// These accessors return handle objects that remain valid and usable independently after the
/// parent <see cref="X509Certificate2"/> is disposed (documented .NET Core 3.0+ behavior: the
/// returned handle duplicates the underlying key handle), which is what lets the caller dispose
/// every fetched certificate once all needed handles have been extracted.
/// </remarks>
internal static class WindowsCertificateKeyExtractor
{
    /// <summary>Extracts a public-only key handle and its key type from a certificate.</summary>
    public static (AsymmetricAlgorithm PublicKey, SigningKeyType KeyType) ExtractPublicKey(
        X509Certificate2 certificate, string thumbprint)
    {
        var rsa = certificate.GetRSAPublicKey();
        if (rsa is not null)
            return (rsa, SigningKeyType.Rsa);

        var ec = certificate.GetECDsaPublicKey();
        if (ec is not null)
            return (ec, SigningKeyType.Ec);

        throw UnsupportedKeyType(thumbprint);
    }

    /// <summary>Extracts a private key handle and its key type from a certificate.</summary>
    public static (AsymmetricAlgorithm PrivateKey, SigningKeyType KeyType) ExtractPrivateKey(
        X509Certificate2 certificate, string thumbprint)
    {
        if (!certificate.HasPrivateKey)
        {
            throw new ZeeKayDaConfigurationException(new ZeeKayDaConfigurationFailure(
                "signing.windows_certificate_store.private_key_not_found",
                $"Certificate '{thumbprint}' was found but has no private key installed alongside it " +
                "in the store. AddWindowsCertificateStoreSigning requires a certificate with an " +
                "accessible private key."));
        }

        var rsa = certificate.GetRSAPrivateKey();
        if (rsa is not null)
            return (rsa, SigningKeyType.Rsa);

        var ec = certificate.GetECDsaPrivateKey();
        if (ec is not null)
            return (ec, SigningKeyType.Ec);

        // HasPrivateKey was true but neither accessor returned a handle: the key exists but the
        // current process identity cannot access it (e.g. a restrictive CNG key ACL) — a distinct
        // root cause from "no private key at all", still surfaced under the same failure code with
        // a message tailored to this case.
        throw new ZeeKayDaConfigurationException(new ZeeKayDaConfigurationFailure(
            "signing.windows_certificate_store.private_key_not_found",
            $"Certificate '{thumbprint}' has a private key, but it could not be accessed by this " +
            "process. Verify the process identity has permission to use the private key (see the " +
            "Certificates MMC snap-in's 'Manage Private Keys', or 'certutil -repairstore')."));
    }

    private static ZeeKayDaConfigurationException UnsupportedKeyType(string thumbprint) =>
        new(new ZeeKayDaConfigurationFailure(
            "signing.windows_certificate_store.unsupported_key_type",
            $"Certificate '{thumbprint}' does not carry an RSA or EC public key. Only RSA and EC " +
            "certificates are supported for JWT signing."));
}
