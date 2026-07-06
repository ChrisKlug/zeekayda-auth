using System.Security.Cryptography;
using ZeeKayDa.Auth.Tokens;
using ZeeKayDa.Auth.Windows.Tests.Fixtures;

namespace ZeeKayDa.Auth.Windows.Tests;

public sealed class WindowsCertificateKeyExtractorTests
{
    private static readonly DateTimeOffset T0 = DateTimeOffset.Parse("2026-01-01T00:00:00Z");

    [Fact]
    public void ExtractPrivateKey_for_RSA_certificate_returns_a_usable_RSA_handle()
    {
        using var certificate = TestCertificateFactory.CreateRsaSelfSigned("test", T0 - TimeSpan.FromDays(1), T0 + TimeSpan.FromDays(365));

        var (privateKey, keyType) = WindowsCertificateKeyExtractor.ExtractPrivateKey(certificate, "AABBCC");

        keyType.Should().Be(SigningKeyType.Rsa);
        var signature = ((RSA)privateKey).SignData("payload"u8.ToArray(), HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        signature.Should().NotBeEmpty();
        privateKey.Dispose();
    }

    [Fact]
    public void ExtractPrivateKey_for_EC_certificate_returns_a_usable_ECDsa_handle()
    {
        using var certificate = TestCertificateFactory.CreateEcSelfSigned("test", T0 - TimeSpan.FromDays(1), T0 + TimeSpan.FromDays(365));

        var (privateKey, keyType) = WindowsCertificateKeyExtractor.ExtractPrivateKey(certificate, "AABBCC");

        keyType.Should().Be(SigningKeyType.Ec);
        var signature = ((ECDsa)privateKey).SignData("payload"u8.ToArray(), HashAlgorithmName.SHA256);
        signature.Should().NotBeEmpty();
        privateKey.Dispose();
    }

    [Fact]
    public void ExtractPrivateKey_throws_private_key_not_found_when_certificate_has_no_private_key()
    {
        using var certificate = TestCertificateFactory.CreateRsaSelfSigned(
            "test", T0 - TimeSpan.FromDays(1), T0 + TimeSpan.FromDays(365), withPrivateKey: false);

        var act = () => WindowsCertificateKeyExtractor.ExtractPrivateKey(certificate, "AABBCC");

        act.Should().Throw<ZeeKayDaConfigurationException>().WithMessage("*private_key_not_found*");
    }

    [Fact]
    public void ExtractPublicKey_succeeds_for_a_certificate_with_no_private_key()
    {
        using var certificate = TestCertificateFactory.CreateRsaSelfSigned(
            "test", T0 - TimeSpan.FromDays(1), T0 + TimeSpan.FromDays(365), withPrivateKey: false);

        var (publicKey, keyType) = WindowsCertificateKeyExtractor.ExtractPublicKey(certificate, "AABBCC");

        keyType.Should().Be(SigningKeyType.Rsa);
        publicKey.Should().NotBeNull();
        publicKey.Dispose();
    }
}
