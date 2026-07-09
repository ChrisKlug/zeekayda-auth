using System.Diagnostics.CodeAnalysis;
using System.Security;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace ZeeKayDa.Auth.Windows;

/// <summary>
/// Reads certificates from a real Windows Certificate Store via <see cref="X509Store"/>.
/// </summary>
/// <remarks>
/// This is the one genuinely Windows-only piece of I/O in this provider. It cannot be meaningfully
/// unit-tested on a single CI OS, so it is exercised only by the Windows-only integration tests in
/// <c>Integration/CertificateStoreReaderTests.cs</c>; the rest of the provider is tested against
/// <c>ICertificateStoreReader</c> fakes on any OS — mirroring the precedent set by
/// <c>LocalSigningKeyFileSystem</c> for the development signing provider's OS-specific ACL code.
/// </remarks>
[ExcludeFromCodeCoverage(Justification = "Requires a real Windows Certificate Store; exercised by Windows-only integration tests. Unit tests fake ICertificateStoreReader instead.")]
internal sealed class CertificateStoreReader : ICertificateStoreReader
{
    /// <inheritdoc/>
    public X509Certificate2 GetCertificate(string normalizedThumbprint, StoreLocation storeLocation, StoreName storeName)
    {
        using var store = new X509Store(storeName, storeLocation);

        try
        {
            store.Open(OpenFlags.ReadOnly);
        }
        catch (Exception ex) when (ex is CryptographicException or UnauthorizedAccessException or SecurityException)
        {
            throw new ZeeKayDaConfigurationException(new ZeeKayDaConfigurationFailure(
                "signing.windows_certificate_store.store_inaccessible",
                $"The Windows Certificate Store '{storeName}'/'{storeLocation}' could not be opened: " +
                $"{ex.Message}. Grant the host process identity read access to this store — do not " +
                "relax the store's ACLs to a broader principal."));
        }

        // validOnly:false — X.509 chain-trust/revocation validity is not a signing-key eligibility
        // concept here; NotBefore/NotAfter eligibility is decided by
        // ZeeKayDa.Auth.Tokens.SigningKeyRotation, not by the OS's notion of chain validity.
        // X509Certificate2Collection itself is not IDisposable, but every certificate it contains
        // is — dispose them explicitly once a standalone copy of the match has been made.
        var matches = store.Certificates.Find(X509FindType.FindByThumbprint, normalizedThumbprint, validOnly: false);
        if (matches.Count == 0)
        {
            foreach (var match in matches)
            {
                using var _ = match;
            }

            throw new ZeeKayDaConfigurationException(new ZeeKayDaConfigurationFailure(
                "signing.windows_certificate_store.certificate_not_found",
                $"No certificate with thumbprint '{normalizedThumbprint}' was found in the '{storeName}' " +
                $"store at '{storeLocation}'. Verify the thumbprint and that the certificate has been " +
                "installed into this exact store/location combination."));
        }

        // Return a standalone copy: every certificate in 'matches' is disposed after this copy
        // has been made, which preserves the handle the caller needs.
        var result = new X509Certificate2(matches[0]);
        foreach (var match in matches)
        {
            using var _ = match;
        }

        return result;
    }
}
