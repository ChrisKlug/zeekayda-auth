using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using System.Linq;
using ZeeKayDa.Auth.Clients;
using ZeeKayDa.Auth.Tokens;

namespace ZeeKayDa.Auth.AspNetCore.Tests.ClientAuthentication;

/// <summary>
/// End-to-end proof that a client declaring a signing algorithm the server does not advertise fails
/// host startup (#515). The check depends on the signing key ring having read its source before
/// client registrations are validated; an ordering regression would silently downgrade it to a
/// no-op, which a unit test on the validator alone cannot see.
/// </summary>
public sealed class ClientSigningAlgorithmStartupIntegrationTests
{
    [Fact]
    public void Host_startup_throws_when_a_client_allows_an_algorithm_the_server_does_not_advertise()
    {
        // The test signing key source publishes RS256 only; the client asks for ES512.
        using var factory = new UnadvertisedAlgorithmWebAppFactory();

        var act = () => factory.CreateClient();

        var ex = act.Should().Throw<Exception>().Which;
        FindInChain<ZeeKayDaConfigurationException>(ex)!
            .AggregatedFailures.Should().Contain(f => f.Code == "client.signing_algorithms.not_subset");
    }

    private static T? FindInChain<T>(Exception? exception) where T : Exception
    {
        while (exception is not null)
        {
            if (exception is T match)
                return match;

            if (exception is AggregateException aggregate)
            {
                foreach (var found in aggregate.InnerExceptions
                             .Select(FindInChain<T>)
                             .Where(found => found is not null))
                {
                    return found;
                }
            }

            exception = exception.InnerException;
        }

        return null;
    }

    private sealed class UnadvertisedAlgorithmWebAppFactory
        : WebApplicationFactory<UnadvertisedAlgorithmWebAppFactory>
    {
        protected override IHostBuilder CreateHostBuilder()
            => Host.CreateDefaultBuilder()
                   .ConfigureWebHostDefaults(webBuilder => webBuilder.UseTestServer());

        protected override void ConfigureWebHost(IWebHostBuilder builder)
        {
            builder.UseContentRoot(AppContext.BaseDirectory);
            builder.ConfigureServices(services =>
            {
                services.AddRouting();
                services.AddZeeKayDaAuth(options =>
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
                .AddInMemoryStores(allowOutsideDevelopment: true)
                .AddTestSigningKeys();
            });

            builder.Configure(app =>
            {
                app.UseRouting();
                app.UseEndpoints(endpoints => endpoints.MapZeeKayDaAuth());
            });
        }
    }
}
