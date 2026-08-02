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
        result.RsaPublicParameters!.Value.Modulus.Should().Equal(rsaParams.Modulus);
        result.RsaPublicParameters!.Value.Exponent.Should().Equal(rsaParams.Exponent);
        result.EcPublicParameters.Should().BeNull();
    }

    [Fact]
    public void FromEc_sets_KeyType_to_Ec_and_carries_the_supplied_parameters()
    {
        using var ec = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var ecParams = ec.ExportParameters(false);

        var result = PublicKeyParameters.FromEc(ecParams);

        result.KeyType.Should().Be(SigningKeyType.Ec);
        result.EcPublicParameters!.Value.Curve.Oid.Value.Should().Be(ecParams.Curve.Oid.Value);
        result.EcPublicParameters!.Value.Q.X.Should().Equal(ecParams.Q.X);
        result.EcPublicParameters!.Value.Q.Y.Should().Equal(ecParams.Q.Y);
        result.RsaPublicParameters.Should().BeNull();
    }

    [Fact]
    public void FromRsa_defensively_copies_the_caller_supplied_arrays()
    {
        using var rsa = RSA.Create(2048);
        var rsaParams = rsa.ExportParameters(false);
        var originalModulus = (byte[])rsaParams.Modulus!.Clone();

        var result = PublicKeyParameters.FromRsa(rsaParams);
        rsaParams.Modulus[0] ^= 0xFF; // mutate the caller's own array after construction

        result.RsaPublicParameters!.Value.Modulus.Should().Equal(
            originalModulus, "the caller mutating its own array afterwards must not retroactively change the listing");
    }

    [Fact]
    public void FromEc_defensively_copies_the_caller_supplied_arrays()
    {
        using var ec = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var ecParams = ec.ExportParameters(false);
        var originalX = (byte[])ecParams.Q.X!.Clone();

        var result = PublicKeyParameters.FromEc(ecParams);
        ecParams.Q.X[0] ^= 0xFF; // mutate the caller's own array after construction

        result.EcPublicParameters!.Value.Q.X.Should().Equal(
            originalX, "the caller mutating its own array afterwards must not retroactively change the listing");
    }
}
