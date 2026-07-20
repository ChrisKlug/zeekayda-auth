using System.Security.Cryptography;
using ZeeKayDa.Auth.Tokens;

namespace ZeeKayDa.Auth.Tests.Tokens;

public sealed class PublicKeyParametersTests
{
    [Fact]
    public void FromRsa_sets_KeyType_to_Rsa_and_carries_the_supplied_parameters()
    {
        using var rsa = RSA.Create(2048);
        var rsaParams = rsa.ExportParameters(false);

        var result = PublicKeyParameters.FromRsa(rsaParams);

        result.KeyType.Should().Be(SigningKeyType.Rsa);
        result.RsaPublicParameters.Should().Be(rsaParams);
        result.EcPublicParameters.Should().BeNull();
    }

    [Fact]
    public void FromEc_sets_KeyType_to_Ec_and_carries_the_supplied_parameters()
    {
        using var ec = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var ecParams = ec.ExportParameters(false);

        var result = PublicKeyParameters.FromEc(ecParams);

        result.KeyType.Should().Be(SigningKeyType.Ec);
        result.EcPublicParameters.Should().Be(ecParams);
        result.RsaPublicParameters.Should().BeNull();
    }
}
