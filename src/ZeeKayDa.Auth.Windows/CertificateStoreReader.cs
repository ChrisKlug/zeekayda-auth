using System.Diagnostics.CodeAnalysis;
using System.Security;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace ZeeKayDa.Auth.Windows;

/// <summary>Reads certificates from a real Windows Certificate Store via <see cref="X509Store"/>.</summary>
[ExcludeFromCodeCoverage(Justification = "Requires a real Windows Certificate Store; exercised by Windows-only integration tests. Unit tests fake ICertificateStoreReader instead.")]
internal sealed class CertificateStoreReader : ICertificateStoreReader
{
    /// <inheritdoc/>
    public X509Certificate2? FindCertificate(string normalizedThumbprint, StoreLocation storeLocation, StoreName storeName)
    {
        using var store = new X509Store(storeName, storeLocation);

        try
        {
            store.Open(OpenFlags.ReadOnly);
        }
        catch (Exception ex) when (ex is CryptographicException or UnauthorizedAccessException or SecurityException)
        {
            // Never ex.Message: a failure message is not redacted, so the cause travels as the inner exception.
            throw new ZeeKayDaConfigurationException(
                new ZeeKayDaConfigurationFailure(
                    "signing.windows_certificate_store.store_inaccessible",
                    $"The Windows Certificate Store '{storeName}'/'{storeLocation}' could not be " +
                    $"opened: {ex.GetType().FullName} was thrown. See the inner exception for the " +
                    "root cause. Grant the host process identity read access to this store — do " +
                    "not relax the store's ACLs to a broader principal."),
                ex);
        }

        // validOnly:false: chain trust is not what makes a signing key eligible; the ring decides from its dates.
        var matches = store.Certificates.Find(X509FindType.FindByThumbprint, normalizedThumbprint, validOnly: false);
        if (matches.Count == 0)
            return null;

        var result = new X509Certificate2(matches[0]);
        foreach (var match in matches)
        {
            using var _ = match;
        }

        return result;
    }
}
