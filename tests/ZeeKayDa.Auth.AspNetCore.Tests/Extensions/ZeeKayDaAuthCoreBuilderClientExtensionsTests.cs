using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using ZeeKayDa.Auth;
using ZeeKayDa.Auth.AspNetCore;
using ZeeKayDa.Auth.Clients;
using ZeeKayDa.Auth.Tokens;

namespace ZeeKayDa.Auth.AspNetCore.Tests.Extensions;

public sealed class ZeeKayDaAuthCoreBuilderClientExtensionsTests
{
    // ── Missing IClientRepository fails startup ───────────────────────────────────────────────────

    [Fact]
    public async Task MissingClientRepository_causes_host_start_to_fail()
    {
        using var factory = new ClientRepositoryMissingFactory();

        Func<Task> act = async () => await factory.CreateClient().GetAsync("/");

        // The presence check is a verifier, so it fails in the phase before the activators run —
        // before ClientRepositoryActivator could hit a raw DI resolution error.
        var thrown = await act.Should().ThrowAsync<ZeeKayDaConfigurationException>();
        thrown.Which.AggregatedFailures.Should().Contain(f => f.Code == "client.repository.missing");
    }

    [Fact]
    public async Task MisconfiguredClientSet_causes_host_start_to_fail()
    {
        // A duplicate client_id is detected in InMemoryClientRepository's constructor. Because the
        // repository is a singleton, ClientRepositoryActivator forces it to be resolved at
        // startup so construction-time validation fails at host start rather than first request.
        using var factory = new DuplicateClientFactory();

        Func<Task> act = async () => await factory.CreateClient().GetAsync("/");

        await act.Should().ThrowAsync<Exception>();
    }

    // ── Fake hasher for tests ─────────────────────────────────────────────────────────────────────

    private sealed class TestSecret : IClientSecret { public IClientCredential Snapshot() => new TestSecret(); }

    private sealed class TestHasher : IClientSecretHasher
    {
        public bool CanHandle(IClientSecret secret) => secret is TestSecret;
        public bool Verify(IClientSecret stored, ReadOnlySpan<char> presented) => false;
        public IClientSecret Create(ReadOnlySpan<char> plaintext) => new TestSecret();
    }

    // ── Web application factory for missing-repository test ───────────────────────────────────────

    private sealed class ClientRepositoryMissingFactory : WebApplicationFactory<ClientRepositoryMissingFactory>
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
                // Deliberately do NOT call AddInMemoryClients — startup should fail
                services.AddZeeKayDaAuth(o => o.Issuer = "https://test.example.com");
            });
            builder.Configure(app =>
            {
                app.UseRouting();
                app.UseEndpoints(endpoints => endpoints.MapGet("/", () => "ok"));
            });
        }
    }

    // ── Web application factory for misconfigured-client-set test ─────────────────────────────────

    private sealed class DuplicateClientFactory : WebApplicationFactory<DuplicateClientFactory>
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
                services.AddZeeKayDaAuth(o =>
                    {
                        o.Issuer = "https://test.example.com";
                        o.TokenEndpoint.AuthMethodsSupported.Add(TokenEndpointAuthMethods.None);
                    })
                    .AddClientSecretHasher<TestHasher>()
                    // Register the same client_id twice — duplicate detection in the repository
                    // constructor must surface as a startup failure.
                    .AddInMemoryClients(clients =>
                    {
                        clients.AddPublic("dupe", ["https://app.example.com/cb"], [], ["openid"]);
                        clients.AddPublic("dupe", ["https://app.example.com/cb"], [], ["openid"]);
                    });
            });
            builder.Configure(app =>
            {
                app.UseRouting();
                app.UseEndpoints(endpoints => endpoints.MapGet("/", () => "ok"));
            });
        }
    }
}
