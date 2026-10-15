using System.Security.Cryptography.X509Certificates;

namespace ZeeKayDa.Auth.Windows;

/// <summary>Reads certificates from the Windows Certificate Store; faked in tests that run on any OS.</summary>
internal interface ICertificateStoreReader
{
    /// <summary>The certificate with this thumbprint, or <see langword="null"/>; the caller disposes it.</summary>
    X509Certificate2? FindCertificate(string normalizedThumbprint, StoreLocation storeLocation, StoreName storeName);
}
