using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using ZeeKayDa.Auth.Tokens;

namespace ZeeKayDa.Auth.Windows;

/// <summary>
/// Extracts public and private key handles from an already-obtained <see cref="X509Certificate2"/>.
/// This seam exists so tests can exercise a private key handle that does not pair with the
/// certificate's own public key — a state a genuine Windows Certificate Store entry can reach if
/// its key-container association is repointed post-startup (e.g. via <c>certutil -repairstore</c>).
/// </summary>
internal interface ICertificateKeyExtractor
{
    /// <summary>Extracts a public-only key handle and its key type from a certificate.</summary>
    (AsymmetricAlgorithm PublicKey, SigningKeyType KeyType) ExtractPublicKey(X509Certificate2 certificate, string thumbprint);

    /// <summary>Extracts a private key handle and its key type from a certificate.</summary>
    (AsymmetricAlgorithm PrivateKey, SigningKeyType KeyType) ExtractPrivateKey(X509Certificate2 certificate, string thumbprint);
}
