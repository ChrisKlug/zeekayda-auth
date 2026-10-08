using System.Security.Cryptography.X509Certificates;

namespace ZeeKayDa.Auth.Windows;

/// <summary>
/// Reads certificates from the Windows Certificate Store by thumbprint. The seam that isolates
/// the one genuinely Windows-only piece of I/O in this provider so it can be faked in tests that
/// run on any OS.
/// </summary>
internal interface ICertificateStoreReader
{
    /// <summary>
    /// Finds the certificate with the given (already-normalized) thumbprint in the given store, or
    /// returns <see langword="null"/> when the store holds none. The caller owns the returned
    /// certificate and must dispose it.
    /// </summary>
    X509Certificate2? FindCertificate(string normalizedThumbprint, StoreLocation storeLocation, StoreName storeName);
}
