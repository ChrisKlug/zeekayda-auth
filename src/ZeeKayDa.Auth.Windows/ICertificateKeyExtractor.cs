using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using ZeeKayDa.Auth.Tokens;

namespace ZeeKayDa.Auth.Windows;

/// <summary>
/// Extracts public and private key handles from an already-obtained <see cref="X509Certificate2"/>.
/// This seam exists so tests can exercise a private key handle that does not pair with the
/// certificate's own public key — a state a real <see cref="X509Certificate2"/> loaded through any
/// public .NET API cannot be made to represent, since certificate/private-key association is
/// cryptographically validated at load time, but which a genuine Windows Certificate Store entry can
/// reach after its key-container association is repointed post-startup (for example, via
/// <c>certutil -repairstore</c>).
/// </summary>
internal interface ICertificateKeyExtractor
{
    /// <summary>Extracts a public-only key handle and its key type from a certificate.</summary>
    (AsymmetricAlgorithm PublicKey, SigningKeyType KeyType) ExtractPublicKey(X509Certificate2 certificate, string thumbprint);

    /// <summary>Extracts a private key handle and its key type from a certificate.</summary>
    (AsymmetricAlgorithm PrivateKey, SigningKeyType KeyType) ExtractPrivateKey(X509Certificate2 certificate, string thumbprint);
}
