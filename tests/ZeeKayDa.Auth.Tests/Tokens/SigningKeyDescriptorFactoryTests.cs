using System.Linq;
using System.Security.Cryptography;
using ZeeKayDa.Auth;
using ZeeKayDa.Auth.Tokens;

namespace ZeeKayDa.Auth.Tests.Tokens;

public sealed class SigningKeyDescriptorFactoryTests
{
    private const string MismatchFailureCode = "test.algorithm_key_type_mismatch";

    [Fact]
    public void BuildDescriptor_for_RSA_key_derives_kid_via_JwkThumbprint_of_the_public_key()
    {
        using var rsa = RSA.Create(2048);
        using var publicOnly = RSA.Create();
        publicOnly.ImportParameters(rsa.ExportParameters(includePrivateParameters: false));

        var descriptor = SigningKeyDescriptorFactory.BuildDescriptor(
            publicOnly, SigningKeyType.Rsa, SigningAlgorithm.RS256, MismatchFailureCode, MismatchMessage);

        descriptor.Kid.Should().Be(JwkThumbprint.Compute(rsa.ExportParameters(includePrivateParameters: false)));
        descriptor.KeyType.Should().Be(SigningKeyType.Rsa);
    }

    [Fact]
    public void BuildDescriptor_for_EC_key_derives_kid_via_JwkThumbprint()
    {
        using var ecdsa = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        using var publicOnly = ECDsa.Create();
        publicOnly.ImportParameters(ecdsa.ExportParameters(includePrivateParameters: false));

        var descriptor = SigningKeyDescriptorFactory.BuildDescriptor(
            publicOnly, SigningKeyType.Ec, SigningAlgorithm.ES256, MismatchFailureCode, MismatchMessage);

        descriptor.Kid.Should().Be(JwkThumbprint.Compute(ecdsa.ExportParameters(includePrivateParameters: false)));
        descriptor.KeyType.Should().Be(SigningKeyType.Ec);
    }

    [Fact]
    public void BuildDescriptor_kid_does_not_contain_arbitrary_external_identifiers()
    {
        using var rsa = RSA.Create(2048);
        using var publicOnly = RSA.Create();
        publicOnly.ImportParameters(rsa.ExportParameters(includePrivateParameters: false));
        const string externalIdentifier = "DEADBEEFCAFE0123456789ABCDEF0123456789AB";

        var descriptor = SigningKeyDescriptorFactory.BuildDescriptor(
            publicOnly, SigningKeyType.Rsa, SigningAlgorithm.RS256, MismatchFailureCode, MismatchMessage);

        descriptor.Kid.Should().NotContain(externalIdentifier, "kid must be the RFC 7638 thumbprint of the public key, never a raw external identifier");
    }

    [Fact]
    public void BuildDescriptor_throws_with_caller_supplied_failure_code_when_EC_algorithm_configured_for_RSA_key()
    {
        using var rsa = RSA.Create(2048);
        using var publicOnly = RSA.Create();
        publicOnly.ImportParameters(rsa.ExportParameters(includePrivateParameters: false));

        var act = () => SigningKeyDescriptorFactory.BuildDescriptor(
            publicOnly, SigningKeyType.Rsa, SigningAlgorithm.ES256, MismatchFailureCode, MismatchMessage);

        act.Should().Throw<ZeeKayDaConfigurationException>()
            .Where(ex => ex.AggregatedFailures.Single().Code == MismatchFailureCode)
            .WithMessage("*mismatch for*Rsa*");
    }

    [Fact]
    public void BuildDescriptor_throws_with_caller_supplied_failure_code_when_RSA_algorithm_configured_for_EC_key()
    {
        using var ecdsa = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        using var publicOnly = ECDsa.Create();
        publicOnly.ImportParameters(ecdsa.ExportParameters(includePrivateParameters: false));

        var act = () => SigningKeyDescriptorFactory.BuildDescriptor(
            publicOnly, SigningKeyType.Ec, SigningAlgorithm.RS256, MismatchFailureCode, MismatchMessage);

        act.Should().Throw<ZeeKayDaConfigurationException>()
            .Where(ex => ex.AggregatedFailures.Single().Code == MismatchFailureCode)
            .WithMessage("*mismatch for*Ec*");
    }

    [Fact]
    public void BuildDescriptor_does_not_invoke_the_mismatch_message_delegate_when_algorithm_matches_key_type()
    {
        using var rsa = RSA.Create(2048);
        using var publicOnly = RSA.Create();
        publicOnly.ImportParameters(rsa.ExportParameters(includePrivateParameters: false));
        var invoked = false;

        SigningKeyDescriptorFactory.BuildDescriptor(
            publicOnly, SigningKeyType.Rsa, SigningAlgorithm.RS256, MismatchFailureCode,
            mismatchedKeyType =>
            {
                invoked = true;
                return MismatchMessage(mismatchedKeyType);
            });

        invoked.Should().BeFalse("the mismatch delegate must only run when a mismatch is actually detected");
    }

    [Fact]
    public void BuildDescriptor_throws_when_publicKey_is_null()
    {
        var act = () => SigningKeyDescriptorFactory.BuildDescriptor(
            null!, SigningKeyType.Rsa, SigningAlgorithm.RS256, MismatchFailureCode, MismatchMessage);

        act.Should().Throw<ArgumentNullException>().WithParameterName("publicKey");
    }

    [Fact]
    public void BuildDescriptor_throws_NotSupportedException_for_an_unrecognized_key_type()
    {
        using var rsa = RSA.Create(2048);
        using var publicOnly = RSA.Create();
        publicOnly.ImportParameters(rsa.ExportParameters(includePrivateParameters: false));
        const SigningKeyType unrecognizedKeyType = (SigningKeyType)99;

        var act = () => SigningKeyDescriptorFactory.BuildDescriptor(
            publicOnly, unrecognizedKeyType, SigningAlgorithm.RS256, MismatchFailureCode, MismatchMessage);

        act.Should().Throw<NotSupportedException>().WithMessage($"*{unrecognizedKeyType}*");
    }

    [Theory]
    [InlineData(SigningAlgorithm.RS256)]
    [InlineData(SigningAlgorithm.RS384)]
    [InlineData(SigningAlgorithm.RS512)]
    [InlineData(SigningAlgorithm.PS256)]
    [InlineData(SigningAlgorithm.PS384)]
    [InlineData(SigningAlgorithm.PS512)]
    public void BuildDescriptor_accepts_every_RSA_algorithm_for_an_RSA_key(SigningAlgorithm algorithm)
    {
        using var rsa = RSA.Create(2048);
        using var publicOnly = RSA.Create();
        publicOnly.ImportParameters(rsa.ExportParameters(includePrivateParameters: false));

        var descriptor = SigningKeyDescriptorFactory.BuildDescriptor(
            publicOnly, SigningKeyType.Rsa, algorithm, MismatchFailureCode, MismatchMessage);

        descriptor.Algorithm.Should().Be(algorithm);
    }

    [Theory]
    [InlineData(SigningAlgorithm.ES256)]
    [InlineData(SigningAlgorithm.ES384)]
    [InlineData(SigningAlgorithm.ES512)]
    public void BuildDescriptor_accepts_every_EC_algorithm_for_an_EC_key(SigningAlgorithm algorithm)
    {
        var curve = algorithm switch
        {
            SigningAlgorithm.ES256 => ECCurve.NamedCurves.nistP256,
            SigningAlgorithm.ES384 => ECCurve.NamedCurves.nistP384,
            _ => ECCurve.NamedCurves.nistP521,
        };
        using var ecdsa = ECDsa.Create(curve);
        using var publicOnly = ECDsa.Create();
        publicOnly.ImportParameters(ecdsa.ExportParameters(includePrivateParameters: false));

        var descriptor = SigningKeyDescriptorFactory.BuildDescriptor(
            publicOnly, SigningKeyType.Ec, algorithm, MismatchFailureCode, MismatchMessage);

        descriptor.Algorithm.Should().Be(algorithm);
    }

    private static string MismatchMessage(SigningKeyType mismatchedKeyType) =>
        $"mismatch for {mismatchedKeyType}";
}
