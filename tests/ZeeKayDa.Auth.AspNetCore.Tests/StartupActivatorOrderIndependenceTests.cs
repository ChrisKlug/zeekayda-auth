using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using ZeeKayDa.Auth.Clients;
using ZeeKayDa.Auth.Extensions;
using ZeeKayDa.Auth.Tokens;

namespace ZeeKayDa.Auth.AspNetCore.Tests;

/// <summary>
/// The client-registration subset check needs the signing key ring to have read its source, because
/// it validates against the algorithms the server advertises. That used to be a registration-order
/// assumption. It is now structural — the client activator asks the ring to initialize itself — and
/// these tests prove the check holds with the registrations made in either order.
/// </summary>
public sealed class StartupActivatorOrderIndependenceTests
{
    [Theory]
    [InlineData(true)]
    [InlineData(false)]
    public void Host_startup_rejects_an_unadvertised_client_algorithm_whichever_order_registration_happens_in(
        bool signingRegisteredFirst)
    {
        using var factory = new OrderedRegistrationWebAppFactory(signingRegisteredFirst);

        var act = () => factory.CreateClient();

        var ex = act.Should().Throw<Exception>().Which;
        FindConfigurationException(ex)!
            .AggregatedFailures.Should().Contain(f => f.Code == "client.signing_algorithms.not_subset");
    }

    [Fact]
    public void Both_activators_are_registered_in_the_activator_collection()
    {
        var services = new ServiceCollection();
        services.AddZeeKayDaAuth(options => options.Issuer = "https://test.example.com");
        services.AddZeeKayDaSigningKeySource<TestSigningKeySource>();

        var activators = services
            .Where(d => d.ServiceType == typeof(IStartupActivator))
            .Select(d => d.ImplementationType)
            .ToList();

        activators.Should().Contain(typeof(SigningKeyRingStartupVerifier));
        activators.Should().Contain(typeof(ClientRepositoryStartupActivator));
        services.Should().NotContain(
            d => d.ServiceType == typeof(IStartupVerifier) && d.ImplementationType == typeof(SigningKeyRingStartupVerifier),
            "reading a signing key source is real work and belongs in the activator phase");
    }

    private static ZeeKayDaConfigurationException? FindConfigurationException(Exception? exception)
    {
        while (exception is not null)
        {
            if (exception is ZeeKayDaConfigurationException match)
                return match;

            if (exception is AggregateException aggregate &&
                aggregate.InnerExceptions.Select(FindConfigurationException).FirstOrDefault(m => m is not null) is { } found)
            {
                return found;
            }

            exception = exception.InnerException;
        }

        return null;
    }

    private sealed class OrderedRegistrationWebAppFactory(bool signingRegisteredFirst)
        : WebApplicationFactory<OrderedRegistrationWebAppFactory>
    {
        protected override IHostBuilder CreateHostBuilder()
            => Host.CreateDefaultBuilder()
                   .ConfigureWebHostDefaults(webBuilder => webBuilder.UseTestServer());

        protected override void ConfigureWebHost(IWebHostBuilder builder)
        {
            builder.UseContentRoot(AppContext.BaseDirectory);
            var signingFirst = signingRegisteredFirst;

            builder.ConfigureServices(services =>
            {
                services.AddRouting();

                // What a provider package's sample looks like when signing comes first.
                if (signingFirst)
                    services.AddZeeKayDaSigningKeySource<TestSigningKeySource>();

                var authBuilder = services.AddZeeKayDaAuth(options =>
                {
                    options.Issuer = "https://test.example.com";
                    options.TokenEndpoint.AuthMethodsSupported.Add(TokenEndpointAuthMethods.None);
                })
                .AddInMemoryClients(clients =>
                    clients.Add(ClientRegistration.CreatePublic(
                        "es512-client",
                        ["https://test.example.com/callback"],
                        [],
                        ["openid"]) with
                    {
                        AllowedSigningAlgorithms = new HashSet<SigningAlgorithm> { SigningAlgorithm.ES512 },
                    }))
                .AddInMemoryStores(allowOutsideDevelopment: true);

                if (!signingFirst)
                    authBuilder.AddTestSigningKeys();
            });

            builder.Configure(app =>
            {
                app.UseRouting();
                app.UseEndpoints(endpoints => endpoints.MapZeeKayDaAuth());
            });
        }
    }
}
