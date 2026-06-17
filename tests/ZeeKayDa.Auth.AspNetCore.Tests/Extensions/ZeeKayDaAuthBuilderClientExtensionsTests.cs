using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Options;
using ZeeKayDa.Auth;
using ZeeKayDa.Auth.AspNetCore;
using ZeeKayDa.Auth.AspNetCore.Clients;
using ZeeKayDa.Auth.Clients;

namespace ZeeKayDa.Auth.AspNetCore.Tests.Extensions;

public sealed class ZeeKayDaAuthBuilderClientExtensionsTests
{
    // ── Argument validation ───────────────────────────────────────────────────────────────────────

    [Fact]
    public void AddInMemoryClients_throws_ArgumentNullException_if_builder_is_null()
    {
        ZeeKayDaAuthBuilder builder = null!;

        var act = () => builder.AddInMemoryClients(_ => { });

        act.Should().Throw<ArgumentNullException>().WithParameterName("builder");
    }

    [Fact]
    public void AddInMemoryClients_throws_ArgumentNullException_if_configure_is_null()
    {
        var services = new ServiceCollection();
        services.AddLogging();
        services.AddOptions();
        var builder = new ZeeKayDaAuthBuilder(services);

        var act = () => builder.AddInMemoryClients(null!);

        act.Should().Throw<ArgumentNullException>().WithParameterName("configure");
    }

    // ── IClientRepository registration ───────────────────────────────────────────────────────────

    [Fact]
    public void AddInMemoryClients_registers_IClientRepository()
    {
        var services = new ServiceCollection();

        services.AddZeeKayDaAuth(o => o.Issuer = "https://test.example.com")
            .AddInMemoryClients(clients =>
                clients.AddPublic("client",
                    ["https://app.example.com/cb"],
                    [],
                    ["openid"]));

        services.Should().Contain(sd => sd.ServiceType == typeof(IClientRepository));
    }

    [Fact]
    public void AddInMemoryClients_returns_builder_for_chaining()
    {
        var services = new ServiceCollection();
        services.AddLogging();
        services.AddOptions();
        var builder = new ZeeKayDaAuthBuilder(services);

        var returned = builder.AddInMemoryClients(_ => { });

        returned.Should().BeSameAs(builder);
    }

    [Fact]
    public void AddInMemoryClients_throws_if_IClientRepository_is_already_registered()
    {
        var services = new ServiceCollection();
        services.AddLogging();
        services.AddOptions();
        var builder = new ZeeKayDaAuthBuilder(services);

        // A custom IClientRepository registered first would silently win TryAddSingleton, leaving
        // the configured in-memory clients unreachable. AddInMemoryClients must fail loudly instead.
        services.AddSingleton<IClientRepository, CustomClientRepository>();

        var act = () => builder.AddInMemoryClients(clients =>
            clients.AddPublic("client", ["https://app.example.com/cb"], [], ["openid"]));

        act.Should().Throw<InvalidOperationException>()
            .WithMessage("*IClientRepository*");
    }

    [Fact]
    public void AddInMemoryClients_throws_with_unknown_in_message_if_IClientRepository_registered_via_factory()
    {
        // When IClientRepository is registered via a factory delegate, ImplementationType is null.
        // The error message must fall back to "unknown" rather than null-referencing.
        var services = new ServiceCollection();
        services.AddLogging();
        services.AddOptions();
        var builder = new ZeeKayDaAuthBuilder(services);

        services.AddSingleton<IClientRepository>(_ => new CustomClientRepository());

        var act = () => builder.AddInMemoryClients(clients =>
            clients.AddPublic("client", ["https://app.example.com/cb"], [], ["openid"]));

        act.Should().Throw<InvalidOperationException>()
            .WithMessage("*unknown*");
    }

    // ── Multiple calls are additive ───────────────────────────────────────────────────────────────

    [Fact]
    public async Task AddInMemoryClients_accumulates_clients_when_called_multiple_times()
    {
        var ct = TestContext.Current.CancellationToken;
        var services = new ServiceCollection();
        services.AddLogging();
        services.AddOptions();

        services.AddZeeKayDaAuth(o =>
            {
                o.Issuer = "https://test.example.com";
                o.TokenEndpoint.AuthMethodsSupported.Add(TokenEndpointAuthMethods.None);
            })
            .AddSecretsHasher<TestHasher>()
            .AddInMemoryClients(clients =>
                clients.AddPublic("client-a",
                    ["https://app.example.com/cb"],
                    [],
                    ["openid"]))
            .AddInMemoryClients(clients =>
                clients.AddPublic("client-b",
                    ["https://app.example.com/cb"],
                    [],
                    ["openid"]));

        using var provider = services.BuildServiceProvider();
        var repo = provider.GetRequiredService<IClientRepository>();

        var a = await repo.FindByClientIdAsync("client-a", ct);
        var b = await repo.FindByClientIdAsync("client-b", ct);

        a.Should().NotBeNull();
        b.Should().NotBeNull();
    }

    // ── AddPublic, AddConfidential, Add ───────────────────────────────────────────────────────────

    [Fact]
    public async Task AddPublic_resolves_client_as_public()
    {
        var ct = TestContext.Current.CancellationToken;
        var services = new ServiceCollection();
        services.AddLogging();
        services.AddOptions();

        services.AddZeeKayDaAuth(o =>
            {
                o.Issuer = "https://test.example.com";
                o.TokenEndpoint.AuthMethodsSupported.Add(TokenEndpointAuthMethods.None);
            })
            .AddSecretsHasher<TestHasher>()
            .AddInMemoryClients(clients =>
                clients.AddPublic("public-client",
                    ["https://app.example.com/cb"],
                    ["https://app.example.com/logout"],
                    ["openid"]));

        using var provider = services.BuildServiceProvider();
        var repo = provider.GetRequiredService<IClientRepository>();

        var found = await repo.FindByClientIdAsync("public-client", ct);

        found.Should().NotBeNull();
        found!.IsPublic.Should().BeTrue();
        found.Credentials.Should().BeEmpty();
    }

    [Fact]
    public async Task AddConfidential_resolves_client_as_confidential()
    {
        var ct = TestContext.Current.CancellationToken;
        var services = new ServiceCollection();
        services.AddLogging();
        services.AddOptions();

        // Note: confidential client uses client_secret_basic (the default), which IS in the
        // server's default AuthMethodsSupported. No need to add None for this test.
        services.AddZeeKayDaAuth(o => o.Issuer = "https://test.example.com")
            .AddSecretsHasher<TestHasher>()
            .AddInMemoryClients(clients =>
                clients.AddConfidential(
                    "confidential-client",
                    "very-secret",
                    ["https://app.example.com/cb"],
                    [],
                    ["openid"]));

        using var provider = services.BuildServiceProvider();
        var repo = provider.GetRequiredService<IClientRepository>();

        var found = await repo.FindByClientIdAsync("confidential-client", ct);

        found.Should().NotBeNull();
        found!.IsPublic.Should().BeFalse();
        found.Credentials.Should().ContainSingle(c => c is IClientSecret);
    }

    [Fact]
    public async Task Add_resolves_pre_built_registration()
    {
        var ct = TestContext.Current.CancellationToken;
        var services = new ServiceCollection();
        services.AddLogging();
        services.AddOptions();

        var preBuilt = ClientRegistration.CreatePublic(
            "pre-built-client",
            ["https://app.example.com/cb"],
            [],
            ["openid"]);

        services.AddZeeKayDaAuth(o =>
            {
                o.Issuer = "https://test.example.com";
                o.TokenEndpoint.AuthMethodsSupported.Add(TokenEndpointAuthMethods.None);
            })
            .AddSecretsHasher<TestHasher>()
            .AddInMemoryClients(clients => clients.Add(preBuilt));

        using var provider = services.BuildServiceProvider();
        var repo = provider.GetRequiredService<IClientRepository>();

        var found = await repo.FindByClientIdAsync("pre-built-client", ct);

        found.Should().NotBeNull();
        found.Should().BeSameAs(preBuilt);
    }

    // ── Missing IClientRepository fails ValidateOnStart ───────────────────────────────────────────

    [Fact]
    public async Task MissingClientRepository_causes_host_start_to_fail()
    {
        using var factory = new ClientRepositoryMissingFactory();

        Func<Task> act = async () => await factory.CreateClient().GetAsync("/");

        // The startup validator (ClientRepositoryPresenceValidator) runs as an IStartupValidator
        // before hosted services, so its friendly OptionsValidationException surfaces first —
        // rather than a raw DI "unable to resolve service for type 'IClientRepository'" error from
        // the activator. The validator's message names the missing IClientRepository.
        var thrown = await act.Should().ThrowAsync<OptionsValidationException>();
        thrown.Which.Message.Should().Contain("IClientRepository");
    }

    [Fact]
    public async Task MisconfiguredClientSet_causes_host_start_to_fail()
    {
        // A duplicate client_id is detected in InMemoryClientRepository's constructor. Because the
        // repository is a singleton, ClientRepositoryStartupActivator forces it to be resolved at
        // startup so construction-time validation fails at host start rather than first request.
        using var factory = new DuplicateClientFactory();

        Func<Task> act = async () => await factory.CreateClient().GetAsync("/");

        await act.Should().ThrowAsync<Exception>();
    }

    // ── Fake hasher for tests ─────────────────────────────────────────────────────────────────────

    private sealed class TestSecret : IClientSecret { }

    private sealed class TestHasher : IClientSecretHasher
    {
        public bool CanHandle(IClientSecret secret) => secret is TestSecret;
        public bool Verify(IClientSecret stored, ReadOnlySpan<char> presented) => false;
        public IClientSecret Create(string plaintext) => new TestSecret();
    }

    // ── Custom repository used by the "AddInMemoryClients after custom repo" guard test ───────────

    private sealed class CustomClientRepository : IClientRepository
    {
        public ValueTask<IClientRegistration?> FindByClientIdAsync(
            string clientId, CancellationToken cancellationToken = default)
            => ValueTask.FromResult<IClientRegistration?>(null);
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
                    .AddSecretsHasher<TestHasher>()
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
