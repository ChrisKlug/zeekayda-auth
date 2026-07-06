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

    // ── Handle-outlives-certificate contract ─────────────────────────────────────────────────────
    // LoadKeysAsync disposes every fetched X509Certificate2 in a `finally` block immediately after
    // extracting the handles it needs (see WindowsCertificateStoreSigningJwtSigningService), relying
    // on the documented .NET Core 3.0+ guarantee that GetRSAPrivateKey()/GetECDsaPrivateKey() return
    // a duplicated handle that remains valid and usable after the parent certificate is disposed.
    // The tests above never actually exercise this: `using var certificate` disposes it only after
    // the test method returns, by which point signing has already happened. These two tests
    // explicitly dispose the certificate *before* using the extracted handle, proving the contract
    // this codebase's disposal discipline depends on actually holds — cross-platform, since this is
    // general BCL behavior, not a Windows Certificate Store-specific guarantee (the real store-backed
    // path is additionally covered by Integration/CertificateStoreReaderTests.cs on Windows).

    [Fact]
    public void ExtractPrivateKey_RSA_handle_remains_usable_after_the_parent_certificate_is_disposed()
    {
        IDisposable? privateKey = null;
        var certificate = TestCertificateFactory.CreateRsaSelfSigned("test", T0 - TimeSpan.FromDays(1), T0 + TimeSpan.FromDays(365));
        try
        {
            (privateKey, _) = WindowsCertificateKeyExtractor.ExtractPrivateKey(certificate, "AABBCC");
        }
        finally
        {
            certificate.Dispose();
        }

        try
        {
            var act = () => ((RSA)privateKey).SignData("payload"u8.ToArray(), HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);

            act.Should().NotThrow("the extracted handle must remain usable after its parent certificate is disposed - LoadKeysAsync's disposal ordering depends on this");
        }
        finally
        {
            privateKey?.Dispose();
        }
    }

    [Fact]
    public void ExtractPrivateKey_EC_handle_remains_usable_after_the_parent_certificate_is_disposed()
    {
        IDisposable? privateKey = null;
        var certificate = TestCertificateFactory.CreateEcSelfSigned("test", T0 - TimeSpan.FromDays(1), T0 + TimeSpan.FromDays(365));
        try
        {
            (privateKey, _) = WindowsCertificateKeyExtractor.ExtractPrivateKey(certificate, "AABBCC");
        }
        finally
        {
            certificate.Dispose();
        }

        try
        {
            var act = () => ((ECDsa)privateKey).SignData("payload"u8.ToArray(), HashAlgorithmName.SHA256);

            act.Should().NotThrow("the extracted handle must remain usable after its parent certificate is disposed - LoadKeysAsync's disposal ordering depends on this");
        }
        finally
        {
            privateKey?.Dispose();
        }
    }

    [Fact]
    public void ExtractPublicKey_handle_remains_usable_after_the_parent_certificate_is_disposed()
    {
        var certificate = TestCertificateFactory.CreateRsaSelfSigned("test", T0 - TimeSpan.FromDays(1), T0 + TimeSpan.FromDays(365));
        using var publicKey = WindowsCertificateKeyExtractor.ExtractPublicKey(certificate, "AABBCC").PublicKey;

        certificate.Dispose();

        var act = () => ((RSA)publicKey).ExportParameters(includePrivateParameters: false);

        act.Should().NotThrow("a non-active included certificate's public-only handle must also survive disposal of its parent certificate");
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
