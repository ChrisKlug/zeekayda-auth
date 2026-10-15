using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using ZeeKayDa.Auth.Tokens;

namespace ZeeKayDa.Auth.Windows;

/// <summary>Extracts a private key handle from a certificate; substituted in tests.</summary>
internal interface ICertificateKeyExtractor
{
    /// <summary>Extracts a private key handle and its key type from a certificate.</summary>
    (AsymmetricAlgorithm PrivateKey, SigningKeyType KeyType) ExtractPrivateKey(X509Certificate2 certificate, string thumbprint);
}
