using System.Security.Cryptography;
using ZeeKayDa.Auth.Tokens;

namespace ZeeKayDa.Auth.Tests.Tokens;

public sealed class SigningKeyDescriptorTests
{
    // ── RSA constructor ───────────────────────────────────────────────────────────────────────────

    [Fact]
    public void RsaConstructor_throws_when_kid_is_null()
    {
        var rsa = RSA.Create(2048);
        var parameters = rsa.ExportParameters(false);

        var act = () => new SigningKeyDescriptor(null!, SigningAlgorithm.RS256, parameters);

        act.Should().Throw<ArgumentNullException>().WithParameterName("kid");
    }

    [Fact]
    public void RsaConstructor_throws_when_kid_is_empty()
    {
        var rsa = RSA.Create(2048);
        var parameters = rsa.ExportParameters(false);

        var act = () => new SigningKeyDescriptor(string.Empty, SigningAlgorithm.RS256, parameters);

        act.Should().Throw<ArgumentException>().WithParameterName("kid");
    }

    [Theory]
    [InlineData(SigningAlgorithm.ES256)]
    [InlineData(SigningAlgorithm.ES384)]
    [InlineData(SigningAlgorithm.ES512)]
    public void RsaConstructor_throws_when_ec_algorithm_is_passed(SigningAlgorithm algorithm)
    {
        var rsa = RSA.Create(2048);
        var parameters = rsa.ExportParameters(false);

        var act = () => new SigningKeyDescriptor("kid-1", algorithm, parameters);

        act.Should().Throw<ArgumentException>().WithParameterName("algorithm");
    }

    [Theory]
    [InlineData(SigningAlgorithm.RS256)]
    [InlineData(SigningAlgorithm.RS384)]
    [InlineData(SigningAlgorithm.RS512)]
    [InlineData(SigningAlgorithm.PS256)]
    [InlineData(SigningAlgorithm.PS384)]
    [InlineData(SigningAlgorithm.PS512)]
    public void RsaConstructor_accepts_all_rsa_algorithms(SigningAlgorithm algorithm)
    {
        var rsa = RSA.Create(2048);
        var parameters = rsa.ExportParameters(false);

        var descriptor = new SigningKeyDescriptor("kid-1", algorithm, parameters);

        descriptor.Algorithm.Should().Be(algorithm);
        descriptor.KeyType.Should().Be(SigningKeyType.Rsa);
        descriptor.RsaPublicParameters.Should().NotBeNull();
        descriptor.EcPublicParameters.Should().BeNull();
    }

    // ── EC constructor ────────────────────────────────────────────────────────────────────────────

    [Fact]
    public void EcConstructor_throws_when_kid_is_null()
    {
        var ec = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var parameters = ec.ExportParameters(false);

        var act = () => new SigningKeyDescriptor(null!, SigningAlgorithm.ES256, parameters);

        act.Should().Throw<ArgumentNullException>().WithParameterName("kid");
    }

    [Theory]
    [InlineData(SigningAlgorithm.RS256)]
    [InlineData(SigningAlgorithm.PS256)]
    public void EcConstructor_throws_when_rsa_algorithm_is_passed(SigningAlgorithm algorithm)
    {
        var ec = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var parameters = ec.ExportParameters(false);

        var act = () => new SigningKeyDescriptor("kid-1", algorithm, parameters);

        act.Should().Throw<ArgumentException>().WithParameterName("algorithm");
    }

    [Theory]
    [InlineData(SigningAlgorithm.ES256)]
    [InlineData(SigningAlgorithm.ES384)]
    [InlineData(SigningAlgorithm.ES512)]
    public void EcConstructor_accepts_all_ec_algorithms(SigningAlgorithm algorithm)
    {
        var curve = algorithm switch
        {
            SigningAlgorithm.ES256 => ECCurve.NamedCurves.nistP256,
            SigningAlgorithm.ES384 => ECCurve.NamedCurves.nistP384,
            _ => ECCurve.NamedCurves.nistP521,
        };
        var ec = ECDsa.Create(curve);
        var parameters = ec.ExportParameters(false);

        var descriptor = new SigningKeyDescriptor("kid-1", algorithm, parameters);

        descriptor.Algorithm.Should().Be(algorithm);
        descriptor.KeyType.Should().Be(SigningKeyType.Ec);
        descriptor.EcPublicParameters.Should().NotBeNull();
        descriptor.RsaPublicParameters.Should().BeNull();
    }

    // ── Kid stability ─────────────────────────────────────────────────────────────────────────────

    [Fact]
    public void Kid_is_stable_and_matches_the_value_passed_to_constructor()
    {
        var rsa = RSA.Create(2048);
        var parameters = rsa.ExportParameters(false);

        var descriptor = new SigningKeyDescriptor("my-stable-kid", SigningAlgorithm.RS256, parameters);

        descriptor.Kid.Should().Be("my-stable-kid");
    }
}
