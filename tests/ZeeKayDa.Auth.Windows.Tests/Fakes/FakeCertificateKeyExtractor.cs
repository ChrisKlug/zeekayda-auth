using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using ZeeKayDa.Auth.Tokens;
using ZeeKayDa.Auth.Windows;

namespace ZeeKayDa.Auth.Windows.Tests.Fakes;

/// <summary>
/// <see cref="ICertificateKeyExtractor"/> test double that delegates to the real
/// <see cref="WindowsCertificateKeyExtractor"/> by default, but lets a test substitute the private
/// key handle returned for a specific thumbprint — simulating the one state a real
/// <see cref="X509Certificate2"/> cannot represent (a certificate whose backing private key no
/// longer pairs with its own public key), which is exactly what a Windows Certificate Store entry's
/// key-container association changing post-startup (e.g. via <c>certutil -repairstore</c>) looks
/// like at the <see cref="ICertificateKeyExtractor"/> seam (M-2, PR #436 security review).
/// </summary>
internal sealed class FakeCertificateKeyExtractor : ICertificateKeyExtractor
{
    private readonly Dictionary<string, (AsymmetricAlgorithm PrivateKey, SigningKeyType KeyType)> _privateKeyOverridesByThumbprint =
        new(StringComparer.Ordinal);

    /// <summary>
    /// From the next call onward, <see cref="ExtractPrivateKey"/> for <paramref name="thumbprint"/>
    /// returns <paramref name="privateKey"/>/<paramref name="keyType"/> instead of delegating to the
    /// real extractor — simulating the store entry's key-container association having changed to a
    /// private key that no longer pairs with the certificate's own public key.
    /// </summary>
    public void OverridePrivateKey(string thumbprint, AsymmetricAlgorithm privateKey, SigningKeyType keyType) =>
        _privateKeyOverridesByThumbprint[thumbprint] = (privateKey, keyType);

    public (AsymmetricAlgorithm PublicKey, SigningKeyType KeyType) ExtractPublicKey(X509Certificate2 certificate, string thumbprint) =>
        WindowsCertificateKeyExtractor.ExtractPublicKey(certificate, thumbprint);

    public (AsymmetricAlgorithm PrivateKey, SigningKeyType KeyType) ExtractPrivateKey(X509Certificate2 certificate, string thumbprint) =>
        _privateKeyOverridesByThumbprint.TryGetValue(thumbprint, out var overridden)
            ? overridden
            : WindowsCertificateKeyExtractor.ExtractPrivateKey(certificate, thumbprint);
}
