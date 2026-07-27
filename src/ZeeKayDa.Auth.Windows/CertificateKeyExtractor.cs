using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using ZeeKayDa.Auth.Tokens;

namespace ZeeKayDa.Auth.Windows;

/// <summary>
/// Production <see cref="ICertificateKeyExtractor"/> — a thin instance wrapper over
/// <see cref="WindowsCertificateKeyExtractor"/>'s static methods, registered as the default via
/// dependency injection so a test double can be substituted instead.
/// </summary>
internal sealed class CertificateKeyExtractor : ICertificateKeyExtractor
{
    public (AsymmetricAlgorithm PublicKey, SigningKeyType KeyType) ExtractPublicKey(X509Certificate2 certificate, string thumbprint) =>
        WindowsCertificateKeyExtractor.ExtractPublicKey(certificate, thumbprint);

    public (AsymmetricAlgorithm PrivateKey, SigningKeyType KeyType) ExtractPrivateKey(X509Certificate2 certificate, string thumbprint) =>
        WindowsCertificateKeyExtractor.ExtractPrivateKey(certificate, thumbprint);
}
