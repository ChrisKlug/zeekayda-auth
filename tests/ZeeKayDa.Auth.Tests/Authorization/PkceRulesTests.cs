using ZeeKayDa.Auth.Authorization;
using ZeeKayDa.Auth.Clients;

namespace ZeeKayDa.Auth.Tests.Authorization;

/// <summary>
/// The one PKCE rule both endpoints consult: a confidential client registered without
/// <c>RequirePkce</c> may omit the challenge, and nobody else may, whatever the registration says.
/// </summary>
public sealed class PkceRulesTests
{
    [Theory]
    [InlineData(false, false, true)]
    [InlineData(false, true, false)]
    [InlineData(true, false, false)]
    [InlineData(true, true, false)]
    public void Only_a_confidential_client_that_opted_in_may_omit_the_challenge(bool isPublic, bool requirePkce, bool expected)
    {
        var client = ClientRegistration.CreatePublic("client", ["https://app.example.com/cb"], [], ["openid"])
            with
        { IsPublic = isPublic, RequirePkce = requirePkce };

        PkceRules.MayOmitChallenge(client).Should().Be(expected);
    }
}
