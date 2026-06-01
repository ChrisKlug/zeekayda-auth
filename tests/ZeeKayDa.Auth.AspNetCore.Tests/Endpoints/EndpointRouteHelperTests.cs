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
    public void GetIssuerUri_NullOrWhitespaceIssuer_ThrowsInvalidOperationException(string? issuer)
    {
        var options = Options.Create(new AuthorizationServerOptions { Issuer = issuer });

        var act = () => EndpointRouteHelper.GetIssuerUri(options);

        act.Should().Throw<InvalidOperationException>()
            .WithMessage("*Issuer must be configured*");
    }
}
