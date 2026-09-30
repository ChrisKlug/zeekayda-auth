using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Routing;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using ZeeKayDa.Auth.Clients;
using ZeeKayDa.Auth.Extensions;

namespace ZeeKayDa.Auth.AspNetCore.Tests;

/// <summary>
/// Pins the two points at which the framework's options are first validated — the startup gate at
/// host start, and <c>MapZeeKayDaAuth()</c> at map time — each surfacing one
/// <see cref="ZeeKayDaConfigurationException"/> with every options type's codes, rather than an
/// <see cref="AggregateException"/> or an
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

        // Built, but never started: MapZeeKayDaAuth validates before the host would ever start.
        using var app = builder.Build();

        Action act = () => app.MapZeeKayDaAuth();

        act.Should().Throw<ZeeKayDaConfigurationException>()
            .Which.AggregatedFailures.Should().ContainSingle(f => f.Code == "configuration.issuer.not_https");
    }

    [Fact]
    public async Task StartAsync_reports_the_failures_of_every_invalid_options_type_in_one_exception()
    {
        using var host = Host.CreateDefaultBuilder()
            .ConfigureServices(services =>
            {
                services.AddZeeKayDaAuth(options => options.Issuer = BadIssuer);
                services.Configure<Pbkdf2ClientSecretHasherOptions>(options => options.Iterations = 1);
            })
            .Build();

        var act = () => host.StartAsync();

        var exception = await act.Should().ThrowAsync<ZeeKayDaConfigurationException>();
        exception.Which.AggregatedFailures.Select(f => f.Code).Should().Contain(
            new[] { "configuration.issuer.not_https", "configuration.pbkdf2.iterations_out_of_range" });
    }

    [Fact]
    public void MapZeeKayDaAuth_reports_the_failures_of_every_invalid_options_type_in_one_exception()
    {
        var builder = WebApplication.CreateBuilder();
        builder.Services.AddRouting();
        builder.Services.AddZeeKayDaAuth(options => options.Issuer = BadIssuer);
        builder.Services.Configure<Pbkdf2ClientSecretHasherOptions>(options => options.Iterations = 1);
        using var app = builder.Build();

        Action act = () => app.MapZeeKayDaAuth();

        act.Should().Throw<ZeeKayDaConfigurationException>()
            .Which.AggregatedFailures.Select(f => f.Code).Should().Contain(
                new[] { "configuration.issuer.not_https", "configuration.pbkdf2.iterations_out_of_range" });
    }

    [Fact]
    public void A_later_PostConfigure_that_replaces_a_collection_fails_with_options_frozen()
    {
        var services = new ServiceCollection();
        services.AddLogging();
        services.AddZeeKayDaAuth(options => options.Issuer = "https://auth.example.com");
        services.PostConfigure<AuthorizationServerOptions>(options => options.GrantTypesSupported = [GrantType.AuthorizationCode]);
        using var provider = services.BuildServiceProvider();

        var act = () => ValidatedOptionsCheck.ThrowIfAnyInvalid(provider);

        act.Should().Throw<ZeeKayDaConfigurationException>()
            .Which.AggregatedFailures.Should().ContainSingle(f => f.Code == "configuration.options_frozen");
    }
}
