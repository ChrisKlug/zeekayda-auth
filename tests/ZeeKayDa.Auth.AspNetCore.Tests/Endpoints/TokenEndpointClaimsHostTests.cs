using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using ZeeKayDa.Auth.AspNetCore.Clients;
using ZeeKayDa.Auth.Clients;
using ZeeKayDa.Auth.Scopes;
using ZeeKayDa.Auth.Tokens;

namespace ZeeKayDa.Auth.AspNetCore.Tests.Endpoints;

/// <summary>
/// The one claims-seam scenario a host-free <see cref="EndpointHost"/> container cannot
/// reproduce: <see cref="EndpointHost"/> always ends up with some <see cref="Claims.IClaimsProvider"/>
/// registered — it registers a no-op one itself when a test does not supply its own — so "no
/// provider was registered at all" needs a container built by hand rather than through it. Every
/// other claims-seam behaviour is covered host-free in <see cref="TokenEndpointClaimsTests"/>.
/// </summary>
public sealed class TokenEndpointClaimsHostTests
{
    private const string Issuer = "https://test.example.com";
    private const string Redirect = "https://test.example.com/callback";
    private const string App = "app";

    [Fact]
    public void A_host_with_no_claims_provider_fails_startup_naming_the_registration()
    {
        using var factory = new StartupFactory(registerProvider: false);

        var act = () => factory.CreateClient();

        var failure = ExceptionChain.FindInChain<ZeeKayDaConfigurationException>(act.Should().Throw<Exception>().Which)!
            .AggregatedFailures.Should().Contain(f => f.Code == "claims.provider.missing").Subject;
        failure.Message.Should().Contain("AddClaimsProvider");
    }

    /// <summary>A host built by hand, for the one startup failure <see cref="EndpointHost"/> cannot express.</summary>
    private sealed class StartupFactory(
        Action<IInMemoryClientRegistrationBuilder>? clients = null,
        IEnumerable<ScopeDefinition>? scopes = null,
        bool registerProvider = true) : WebApplicationFactory<StartupFactory>
    {
        protected override IHostBuilder CreateHostBuilder()
            => Host.CreateDefaultBuilder().ConfigureWebHostDefaults(webBuilder => webBuilder.UseTestServer());

        protected override void ConfigureWebHost(IWebHostBuilder builder)
        {
            builder.UseContentRoot(AppContext.BaseDirectory);
            builder.ConfigureServices(services =>
            {
                services.AddRouting();
                var auth = services.AddZeeKayDaAuth(options =>
                {
                    options.Issuer = Issuer;
                    options.TokenEndpoint.AuthMethodsSupported.Add(TokenEndpointAuthMethods.None);
                })
                .AddInMemoryScopes(scopes ?? StandardScopes.All)
                .AddInMemoryClients(clients ?? (c => c.AddPublic(App, [Redirect], [], ["openid"])))
                .AddInMemoryStores(allowOutsideDevelopment: true)
                .AddTestSigningKeys();

                if (registerProvider)
                    auth.AddTestClaimsProvider();
            });

            builder.Configure(app =>
            {
                app.UseRouting();
                app.UseEndpoints(endpoints => endpoints.MapZeeKayDaAuth());
            });
        }
    }
}
