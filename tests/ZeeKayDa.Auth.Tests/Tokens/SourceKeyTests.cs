using System.Security.Cryptography;
using ZeeKayDa.Auth.Tokens;

namespace ZeeKayDa.Auth.Tests.Tokens;

public sealed class SourceKeyTests
{
    [Fact]
    public void Constructor_rejects_a_null_public_key()
    {
        var act = () => new SourceKey(new SourceKeyId("key"), null!);

        act.Should().Throw<ArgumentNullException>().WithParameterName("publicKey");
    }

    [Fact]
    public void Constructor_rejects_an_id_with_a_null_value()
    {
        using var rsa = RSA.Create(2048);
        var publicKey = PublicKeyParameters.FromRsa(rsa.ExportParameters(false));

        var act = () => new SourceKey(new SourceKeyId(null!), publicKey);

        act.Should().Throw<ArgumentNullException>().WithParameterName("id");
    }
}
