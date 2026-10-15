using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using ZeeKayDa.Auth.Tokens;

namespace ZeeKayDa.Auth.Windows;

/// <summary>
/// Extracts a private key handle through <c>GetRSAPrivateKey()</c>/<c>GetECDsaPrivateKey()</c>,
/// whose handles outlive the certificate.
/// </summary>
internal static class WindowsCertificateKeyExtractor
{
    /// <summary>Extracts a private key handle and its key type from a certificate.</summary>
    public static (AsymmetricAlgorithm PrivateKey, SigningKeyType KeyType) ExtractPrivateKey(
        X509Certificate2 certificate, string thumbprint)
    {
        if (!certificate.HasPrivateKey)
            throw NoPrivateKey(thumbprint);

        try
        {
            var rsa = certificate.GetRSAPrivateKey();
            if (rsa is not null)
                return (rsa, SigningKeyType.Rsa);

            var ec = certificate.GetECDsaPrivateKey();
            if (ec is not null)
                return (ec, SigningKeyType.Ec);
        }
        catch (CryptographicException ex)
        {
            // The common shape of a denied CNG key ACL: the accessor throws rather than returning null.
            throw InaccessiblePrivateKey(thumbprint, ex);
        }

        // HasPrivateKey was true, so no handle means the process likely lacks access to the key.
        throw InaccessiblePrivateKey(thumbprint, cause: null);
    }

    /// <summary>The failure for a listed certificate with no private key installed beside it.</summary>
    public static ZeeKayDaConfigurationException NoPrivateKey(string thumbprint) =>
        new(new ZeeKayDaConfigurationFailure(
            "signing.windows_certificate_store.private_key_not_found",
            $"Certificate '{thumbprint}' was found but has no private key installed alongside it " +
            "in the store. Every listed certificate must have one, because any of them may be chosen to sign."));

    private static ZeeKayDaConfigurationException InaccessiblePrivateKey(string thumbprint, CryptographicException? cause)
    {
        var failure = new ZeeKayDaConfigurationFailure(
            "signing.windows_certificate_store.private_key_not_found",
            $"Certificate '{thumbprint}' has a private key, but it could not be accessed by this " +
            $"process{ProcessIdentityHelper.FormatIdentitySuffix(ProcessIdentityHelper.TryResolveProcessIdentity())}. " +
            "Verify the process identity has permission to use the private key (see the Certificates " +
            "MMC snap-in's 'Manage Private Keys', or 'certutil -repairstore').");
        return cause is null ? new(failure) : new(failure, cause);
    }
}
