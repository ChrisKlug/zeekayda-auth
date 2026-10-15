using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using ZeeKayDa.Auth.Tokens;

namespace ZeeKayDa.Auth.Windows;

/// <summary>The production <see cref="ICertificateKeyExtractor"/>, over <see cref="WindowsCertificateKeyExtractor"/>.</summary>
internal sealed class CertificateKeyExtractor : ICertificateKeyExtractor
{
    public (AsymmetricAlgorithm PrivateKey, SigningKeyType KeyType) ExtractPrivateKey(X509Certificate2 certificate, string thumbprint) =>
        WindowsCertificateKeyExtractor.ExtractPrivateKey(certificate, thumbprint);
}
