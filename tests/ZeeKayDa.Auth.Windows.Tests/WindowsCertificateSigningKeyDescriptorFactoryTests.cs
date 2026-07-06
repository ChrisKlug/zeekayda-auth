using System.Security.Cryptography;
using ZeeKayDa.Auth.Tokens;

namespace ZeeKayDa.Auth.Windows.Tests;

public sealed class WindowsCertificateSigningKeyDescriptorFactoryTests
{
    [Fact]
    public void BuildDescriptor_for_RSA_key_derives_kid_via_JwkThumbprint_of_the_public_key()
    {
        using var rsa = RSA.Create(2048);
        var publicOnly = RSA.Create();
        publicOnly.ImportParameters(rsa.ExportParameters(includePrivateParameters: false));

        var descriptor = WindowsCertificateSigningKeyDescriptorFactory.BuildDescriptor(
            publicOnly, SigningKeyType.Rsa, SigningAlgorithm.RS256, "AABBCCDD");

        descriptor.Kid.Should().Be(JwkThumbprint.Compute(rsa.ExportParameters(includePrivateParameters: false)));
        descriptor.KeyType.Should().Be(SigningKeyType.Rsa);
    }

    [Fact]
    public void BuildDescriptor_for_EC_key_derives_kid_via_JwkThumbprint()
    {
        using var ecdsa = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var publicOnly = ECDsa.Create();
        publicOnly.ImportParameters(ecdsa.ExportParameters(includePrivateParameters: false));

        var descriptor = WindowsCertificateSigningKeyDescriptorFactory.BuildDescriptor(
            publicOnly, SigningKeyType.Ec, SigningAlgorithm.ES256, "AABBCCDD");

        descriptor.Kid.Should().Be(JwkThumbprint.Compute(ecdsa.ExportParameters(includePrivateParameters: false)));
        descriptor.KeyType.Should().Be(SigningKeyType.Ec);
    }

    [Fact]
    public void BuildDescriptor_kid_does_not_contain_the_raw_certificate_thumbprint()
    {
        using var rsa = RSA.Create(2048);
        var publicOnly = RSA.Create();
        publicOnly.ImportParameters(rsa.ExportParameters(includePrivateParameters: false));
        const string thumbprint = "DEADBEEFCAFE0123456789ABCDEF0123456789AB";

        var descriptor = WindowsCertificateSigningKeyDescriptorFactory.BuildDescriptor(
            publicOnly, SigningKeyType.Rsa, SigningAlgorithm.RS256, thumbprint);

        descriptor.Kid.Should().NotContain(thumbprint, "kid must be the RFC 7638 thumbprint of the public key, never the certificate's own X.509 thumbprint");
    }

    [Fact]
    public void BuildDescriptor_throws_algorithm_key_type_mismatch_when_EC_algorithm_configured_for_RSA_key()
    {
        using var rsa = RSA.Create(2048);
        var publicOnly = RSA.Create();
        publicOnly.ImportParameters(rsa.ExportParameters(includePrivateParameters: false));

        var act = () => WindowsCertificateSigningKeyDescriptorFactory.BuildDescriptor(
            publicOnly, SigningKeyType.Rsa, SigningAlgorithm.ES256, "AABBCCDD");

        act.Should().Throw<ZeeKayDaConfigurationException>().WithMessage("*algorithm_key_type_mismatch*");
    }

    [Fact]
    public void BuildDescriptor_throws_algorithm_key_type_mismatch_when_RSA_algorithm_configured_for_EC_key()
    {
        using var ecdsa = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var publicOnly = ECDsa.Create();
        publicOnly.ImportParameters(ecdsa.ExportParameters(includePrivateParameters: false));

        var act = () => WindowsCertificateSigningKeyDescriptorFactory.BuildDescriptor(
            publicOnly, SigningKeyType.Ec, SigningAlgorithm.RS256, "AABBCCDD");

        act.Should().Throw<ZeeKayDaConfigurationException>().WithMessage("*algorithm_key_type_mismatch*");
    }
}
