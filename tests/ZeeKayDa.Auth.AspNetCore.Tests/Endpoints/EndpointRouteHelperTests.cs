using Microsoft.Extensions.Options;
using ZeeKayDa.Auth;
using ZeeKayDa.Auth.AspNetCore.Endpoints;

namespace ZeeKayDa.Auth.AspNetCore.Tests.Endpoints;

public sealed class EndpointRouteHelperTests
{
    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("   ")]
    public void GetIssuerUri_throws_ZeeKayDaConfigurationException_if_Issuer_is_null_or_whitespace(string? issuer)
    {
        var options = Options.Create(new AuthorizationServerOptions { Issuer = issuer });

        var act = () => EndpointRouteHelper.GetIssuerUri(options);

        act.Should().Throw<ZeeKayDaConfigurationException>()
            .Which.AggregatedFailures.Should().ContainSingle()
            .Which.Code.Should().Be("configuration.issuer.missing");
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("   ")]
    public void GetIssuerUri_throws_with_message_mentioning_Issuer_if_Issuer_is_null_or_whitespace(string? issuer)
    {
        var options = Options.Create(new AuthorizationServerOptions { Issuer = issuer });

        var act = () => EndpointRouteHelper.GetIssuerUri(options);

        act.Should().Throw<ZeeKayDaConfigurationException>()
            .Which.AggregatedFailures[0].Message.Should().Contain("Issuer must be configured");
    }

    [Theory]
    [InlineData("https://auth.example.com", "/.well-known/oauth-authorization-server")]
    [InlineData("https://auth.example.com/", "/.well-known/oauth-authorization-server")]
    [InlineData("https://auth.example.com/tenant1", "/.well-known/oauth-authorization-server/tenant1")]
    [InlineData("https://auth.example.com/org/tenant1", "/.well-known/oauth-authorization-server/org/tenant1")]
    public void GetWellKnownInsertedRoute_inserts_the_well_known_segment_before_the_issuer_path(string issuer, string expected)
    {
        var route = EndpointRouteHelper.GetWellKnownInsertedRoute(new Uri(issuer), "oauth-authorization-server");

        route.Should().Be(expected, because: "RFC 8414 §3.1 inserts the well-known segment rather than appending it");
    }
}
