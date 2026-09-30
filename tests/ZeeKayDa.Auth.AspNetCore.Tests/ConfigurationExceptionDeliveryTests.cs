using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Routing;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using ZeeKayDa.Auth.Extensions;

namespace ZeeKayDa.Auth.AspNetCore.Tests;

/// <summary>
/// Pins the two points at which an invalid <see cref="AuthorizationServerOptions"/> is first read —
/// <c>ValidateOnStart()</c> at host start, and <c>MapZeeKayDaAuth()</c>'s own eager read at map time —
/// each surfacing the validator's <see cref="ZeeKayDaConfigurationException"/> itself, with its code,
/// rather than wrapped in an <see cref="AggregateException"/> or an
/// <see cref="Microsoft.Extensions.Options.OptionsValidationException"/>.
/// </summary>
public sealed class ConfigurationExceptionDeliveryTests
{
    // A bad issuer (no scheme permitted without AllowInsecureIssuer) triggers exactly one failure,
    // "configuration.issuer.not_https", so the exception this delivery path throws is pinned to it.
    private const string BadIssuer = "http://auth.example.com";

    [Fact]
    public async Task StartAsync_surfaces_an_invalid_AuthorizationServerOptions_as_ZeeKayDaConfigurationException_with_its_code()
    {
        using var host = Host.CreateDefaultBuilder()
            .ConfigureServices(services => services.AddZeeKayDaAuth(options => options.Issuer = BadIssuer))
            .Build();

        var act = () => host.StartAsync();

        var exception = await act.Should().ThrowAsync<ZeeKayDaConfigurationException>();
        exception.Which.AggregatedFailures.Should().ContainSingle(f => f.Code == "configuration.issuer.not_https");
    }

    [Fact]
    public void MapZeeKayDaAuth_surfaces_an_invalid_AuthorizationServerOptions_as_ZeeKayDaConfigurationException_with_its_code()
    {
        var builder = WebApplication.CreateBuilder();
        builder.Services.AddRouting();
        builder.Services.AddZeeKayDaAuth(options => options.Issuer = BadIssuer);

        // Built, but never started — MapZeeKayDaAuth reads AuthorizationServerOptions eagerly, before
        // the host would ever get to run ValidateOnStart.
        using var app = builder.Build();

        Action act = () => ((IEndpointRouteBuilder)app).MapZeeKayDaAuth();

        act.Should().Throw<ZeeKayDaConfigurationException>()
            .Which.AggregatedFailures.Should().ContainSingle(f => f.Code == "configuration.issuer.not_https");
    }
}
