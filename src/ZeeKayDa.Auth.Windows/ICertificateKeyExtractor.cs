using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using ZeeKayDa.Auth.Tokens;

namespace ZeeKayDa.Auth.Windows;

/// <summary>
/// Extracts a private key handle from an already-obtained <see cref="X509Certificate2"/>. A seam so
/// tests can observe which certificate a handle is extracted for, and substitute a handle.
/// </summary>
internal interface ICertificateKeyExtractor
{
    /// <summary>Extracts a private key handle and its key type from a certificate.</summary>
    (AsymmetricAlgorithm PrivateKey, SigningKeyType KeyType) ExtractPrivateKey(X509Certificate2 certificate, string thumbprint);
}
