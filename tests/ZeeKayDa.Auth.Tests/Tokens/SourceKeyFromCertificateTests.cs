using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using ZeeKayDa.Auth.Tokens;

namespace ZeeKayDa.Auth.Tests.Tokens;

public sealed class SourceKeyFromCertificateTests
{
    private static readonly SourceKeyId KeyId = new("cert-1");

    [Fact]
    public void FromCertificate_exports_the_public_key_of_an_RSA_certificate()
    {
        using var rsa = RSA.Create(2048);
        using var certificate = SelfSigned(rsa);

        var sut = SourceKey.FromCertificate(certificate, KeyId, SigningAlgorithm.RS256);

        sut.PublicKey.KeyType.Should().Be(SigningKeyType.Rsa);
        sut.PublicKey.RsaPublicParameters!.Value.Modulus.Should().Equal(rsa.ExportParameters(false).Modulus);
    }

    [Fact]
    public void FromCertificate_carries_the_id_and_algorithm_it_was_given()
    {
        using var rsa = RSA.Create(2048);
        using var certificate = SelfSigned(rsa);

        var sut = SourceKey.FromCertificate(certificate, KeyId, SigningAlgorithm.PS256);

        sut.Id.Should().Be(KeyId);
        sut.Algorithm.Should().Be(SigningAlgorithm.PS256);
    }

    [Fact]
    public void FromCertificate_exports_the_public_key_of_an_EC_certificate()
    {
        using var ecdsa = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        using var certificate = SelfSigned(ecdsa);

        var sut = SourceKey.FromCertificate(certificate, KeyId, SigningAlgorithm.ES256);

        sut.PublicKey.KeyType.Should().Be(SigningKeyType.Ec);
        sut.PublicKey.EcPublicParameters!.Value.Q.X.Should().Equal(ecdsa.ExportParameters(false).Q.X);
    }

    [Fact]
    public void FromCertificate_never_exports_private_key_material()
    {
        using var rsa = RSA.Create(2048);
        using var certificate = SelfSigned(rsa);

        var sut = SourceKey.FromCertificate(certificate, KeyId, SigningAlgorithm.RS256);

        sut.PublicKey.RsaPublicParameters!.Value.D.Should().BeNull();
    }

    [Fact]
    public void FromCertificate_dates_the_key_by_the_certificates_validity_window_as_the_same_UTC_instants()
    {
        using var rsa = RSA.Create(2048);
        using var certificate = SelfSigned(rsa);

        var sut = SourceKey.FromCertificate(certificate, KeyId, SigningAlgorithm.RS256);

        sut.NotBefore.UtcDateTime.Should().Be(certificate.NotBefore.ToUniversalTime());
        sut.ExpiresAt.UtcDateTime.Should().Be(certificate.NotAfter.ToUniversalTime());
    }

    [Fact]
    public void FromCertificate_rejects_a_key_that_does_not_suit_the_algorithm_naming_the_id()
    {
        using var rsa = RSA.Create(2048);
        using var certificate = SelfSigned(rsa);

        var act = () => SourceKey.FromCertificate(certificate, KeyId, SigningAlgorithm.ES256);

        var exception = act.Should().Throw<ZeeKayDaConfigurationException>();
        exception.Which.AggregatedFailures.Should().ContainSingle(f => f.Code == "signing.key_algorithm_mismatch");
        exception.Which.Message.Should().Contain(KeyId.Value);
    }

    [Fact]
    public void FromCertificate_rejects_an_undefined_algorithm()
    {
        using var rsa = RSA.Create(2048);
        using var certificate = SelfSigned(rsa);

        var act = () => SourceKey.FromCertificate(certificate, KeyId, (SigningAlgorithm)999);

        act.Should().Throw<ArgumentOutOfRangeException>().Which.ParamName.Should().Be("algorithm");
    }

    [Fact]
    public void FromCertificate_reads_a_certificate_without_a_private_key()
    {
        using var rsa = RSA.Create(2048);
        using var withKey = SelfSigned(rsa);
        using var publicOnly = X509CertificateLoader.LoadCertificate(withKey.Export(X509ContentType.Cert));

        var sut = SourceKey.FromCertificate(publicOnly, KeyId, SigningAlgorithm.RS256);

        sut.PublicKey.KeyType.Should().Be(SigningKeyType.Rsa);
    }

    [Fact]
    public void FromCertificate_throws_unsupported_key_type_for_a_certificate_that_is_neither_RSA_nor_EC()
    {
        Assert.SkipWhen(OperatingSystem.IsWindows(), "Windows' certificate stack may refuse to load a DSA certificate at all, before the key-type check is reached.");

        using var certificate = X509Certificate2.CreateFromPem(DsaCertificatePem);

        var act = () => SourceKey.FromCertificate(certificate, KeyId, SigningAlgorithm.RS256);

        act.Should().Throw<ZeeKayDaConfigurationException>().Which.AggregatedFailures
            .Should().ContainSingle(f => f.Code == "signing.certificate.unsupported_key_type")
            .Which.Message.Should().Contain(KeyId.Value);
    }

    /// <summary>
    /// A DSA self-signed certificate (openssl-generated, valid for a century). Checked in as text
    /// because <see cref="CertificateRequest"/> can only produce RSA and ECDSA certificates.
    /// </summary>
    private const string DsaCertificatePem = """
        -----BEGIN CERTIFICATE-----
        MIIElTCCBEKgAwIBAgIUZ/wI0gCPxUhIqWpdcLL3roeD0IwwCwYJYIZIAWUDBAMC
        MCwxKjAoBgNVBAMMIXprZGEtdW5zdXBwb3J0ZWQta2V5LXR5cGUtZml4dHVyZTAg
        Fw0yNjA4MjcxNzU5MzBaGA8yMTI2MDgwMzE3NTkzMFowLDEqMCgGA1UEAwwhemtk
        YS11bnN1cHBvcnRlZC1rZXktdHlwZS1maXh0dXJlMIIDQzCCAjYGByqGSM44BAEw
        ggIpAoIBAQDv6fOMTzPI5adGpTaFuWakccaXuc6SQtlB3bUhfyf662ZemTmWo/Ls
        3EUVGAzZFdbouNuTSHPVxbD5OI85TD1c5z2ne/dE5Wd+2jyKUrN0ZYWhWHCPz7dQ
        vNaiiWAm+JX+ndXNuVSL+TwotwnhLd2z8dTTEIbr2ywL09vsw/8N55//P0mfY/kY
        nWUVCAOqR6hVbjPAvGqtWrYpIVIBVZ9f37mI39cXI1aJXE5gYFigYJMYghHzEMvE
        4WkrlA28TBCqskKFKYw/o2Idp4hxpIsYZ53VK6NrAk74qh92haWokXErgzjVCgoB
        qQTSeM92s4FslzPeWYFyd4KPH6rX5GvHAh0AwrOMBSMLQp0cPVC0h6EFROtpKVLb
        GwDFPgVVzQKCAQEAyfeCNUlrPEfGR4jc7Aep4akKdozKFqVzT+DxW0acdFJ1Oe7M
        zZNButmzw8z6fdotWGt7u9KgmYX9wcs4Zvl2bEIxU5mAba3bPggdgfots+sM9aq6
        DOt168/lWBX5PbsbUweM8u3jEIONaYsYlw6AMhPCR2gtd8vOlA7KnUGA+W6h+5Qp
        bUW7yPIymXDRhw/ihe5iqEcltQAUL24YFtIErcYmxZeQdkziaAHkUclAUtfuKI16
        XaNllYfdwr/Kjrmff+GFkxjk4YCSV3I5ANJ7UGFhm7Acabgaf/4y407SDwNMQ0NM
        U/fMDLFMu5beccxX7egLZyxy2EpKLJqKolkUyAOCAQUAAoIBAA0qFz942DK40Yk5
        7yhG8j6oWorxtE3oSFTgJ+moEEyPKUu4M2AO7yFL3RNOLWU59RU0kNCQTyDV7get
        Q2eTHDbaTYADVzw5FiuBY3jTO6s2VrIMJSXveAmO5NVWU8VmNdek944Ymuu5BUg6
        7wMqAEzHGu79jHrCmYry9KycvkmEic8qhQceuMseNLjNvf9IlpkRgnXc8tp7r7Kq
        3MGQ3m6ec+J4jE0FNoYVHEL+5lpnSFKoW1EyG2QBSAbThMIH9s/HI4u6F2KeAc6n
        q/IFESvn7yrKp+BJr3QydVxrzgit0+1l94t7KmbbNAgeKhQDM4vhM8eCooomwqz8
        MaWVUXGjUzBRMB0GA1UdDgQWBBRvM48hp1aJB/YXYSgVzu9fTu+CKDAfBgNVHSME
        GDAWgBRvM48hp1aJB/YXYSgVzu9fTu+CKDAPBgNVHRMBAf8EBTADAQH/MAsGCWCG
        SAFlAwQDAgNAADA9AhxsR8W1AJ9rSGQb2fZfbBlYHTFK/ezeh6wP4+9GAh0AiqnN
        nAJCNS2zwuZjpqaLnkmix9MkXCghY7eGuQ==
        -----END CERTIFICATE-----
        """;


    private static X509Certificate2 SelfSigned(RSA rsa)
    {
        var request = new CertificateRequest("CN=source-key-test", rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        return request.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-3), DateTimeOffset.UtcNow.AddDays(30));
    }

    private static X509Certificate2 SelfSigned(ECDsa ecdsa)
    {
        var request = new CertificateRequest("CN=source-key-test", ecdsa, HashAlgorithmName.SHA256);
        return request.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-3), DateTimeOffset.UtcNow.AddDays(30));
    }
}
