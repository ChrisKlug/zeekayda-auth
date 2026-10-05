using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;
using ZeeKayDa.Auth;
using ZeeKayDa.Auth.Clients;
using ZeeKayDa.Auth.Tokens;

namespace ZeeKayDa.Auth.Tests.Extensions;

public sealed class ZeeKayDaAuthCoreBuilderClientExtensionsTests
{
    private static ServiceCollection ServicesWithLogging()
    {
        var services = new ServiceCollection();
        services.AddSingleton(typeof(ILogger<>), typeof(NullLogger<>));
        return services;
    }

    private static void AllowPublicClients(AuthorizationServerOptions options)
    {
        options.Issuer = "https://test.example.com";
    }

    /// <summary>
    /// The core alone has no client authenticator, so it advertises only <c>none</c>; a confidential
    /// client needs the methods <c>AddZeeKayDaAuth</c>'s authenticator performs.
    /// </summary>
    private static void AdvertiseClientSecretMethods(IServiceCollection services) =>
        services.AddSingleton(new AdvertisedAuthMethods(
            [TokenEndpointAuthMethods.ClientSecretBasic, TokenEndpointAuthMethods.ClientSecretPost], filter: null));

    [Fact]
    public void AddInMemoryClients_throws_if_IClientRepository_is_already_registered()
    {
        var services = ServicesWithLogging();
        var builder = services.AddZeeKayDaAuthCore(AllowPublicClients);

        // A custom IClientRepository registered first would silently win TryAddSingleton, leaving
        // the configured in-memory clients unreachable. AddInMemoryClients must fail loudly instead.
        services.AddSingleton<IClientRepository, CustomClientRepository>();

        var act = () => builder.AddInMemoryClients(clients =>
            clients.AddPublic("client", client =>
            {
                client.RedirectUris.UnionWith(["https://app.example.com/cb"]);
                client.AllowedScopes.UnionWith(["openid"]);
            }));

        act.Should().Throw<InvalidOperationException>()
            .WithMessage("*IClientRepository*");
    }

    [Fact]
    public void AddInMemoryClients_throws_with_unknown_in_message_if_IClientRepository_registered_via_factory()
    {
        // When IClientRepository is registered via a factory delegate, ImplementationType is null.
        // The error message must fall back to "unknown" rather than null-referencing.
        var services = ServicesWithLogging();
        var builder = services.AddZeeKayDaAuthCore(AllowPublicClients);

        services.AddSingleton<IClientRepository>(_ => new CustomClientRepository());

        var act = () => builder.AddInMemoryClients(clients =>
            clients.AddPublic("client", client =>
            {
                client.RedirectUris.UnionWith(["https://app.example.com/cb"]);
                client.AllowedScopes.UnionWith(["openid"]);
            }));

        act.Should().Throw<InvalidOperationException>()
            .WithMessage("*unknown*");
    }

    [Fact]
    public async Task A_PBKDF2_secret_stored_as_a_string_round_trips_through_the_in_memory_repository_and_verifies()
    {
        // A hash produced elsewhere (Python's hashlib here) is stored as it is: any store persists
        // any hasher's output as a string, and the framework hands it back unchanged.
        const string stored =
            "$pbkdf2-sha256$i=600000$AAECAwQFBgcICQoLDA0ODw$7xdxRO7JQgy8EJPSqLNEqSvFBtDU7JwCjdGfgyTYweY";
        var services = ServicesWithLogging();
        services.AddZeeKayDaAuthCore(AllowPublicClients).AddInMemoryClients(clients => clients.Add(
            Client.CreateConfidential("client", new ClientSecret(stored), ["https://app.example.com/cb"], [], ["openid"])));
        AdvertiseClientSecretMethods(services);
        using var provider = services.BuildServiceProvider();

        var client = await provider.GetRequiredService<ValidatedClientResolver>()
            .FindClientWithCredentialsAsync("client", TestContext.Current.CancellationToken);

        var secret = client!.Secrets.Should().ContainSingle().Subject;
        secret.Value.Should().Be(stored);
        provider.GetRequiredService<ClientSecrets>()
            .Verify("correct horse battery staple", [secret]).Matched.Should().BeTrue();
    }

    // ── Multiple calls are additive ───────────────────────────────────────────────────────────────

    [Fact]
    public async Task AddInMemoryClients_accumulates_clients_when_called_multiple_times()
    {
        var ct = TestContext.Current.CancellationToken;
        var services = ServicesWithLogging();

        services.AddZeeKayDaAuthCore(AllowPublicClients)
            .AddClientSecretHasher<TestHasher>()
            .AddInMemoryClients(clients =>
                clients.AddPublic("client-a", client =>
                {
                    client.RedirectUris.UnionWith(["https://app.example.com/cb"]);
                    client.AllowedScopes.UnionWith(["openid"]);
                }))
            .AddInMemoryClients(clients =>
                clients.AddPublic("client-b", client =>
                {
                    client.RedirectUris.UnionWith(["https://app.example.com/cb"]);
                    client.AllowedScopes.UnionWith(["openid"]);
                }));

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
        var services = ServicesWithLogging();

        services.AddZeeKayDaAuthCore(AllowPublicClients)
            .AddClientSecretHasher<TestHasher>()
            .AddInMemoryClients(clients =>
                clients.AddPublic("public-client", client =>
                {
                    client.RedirectUris.UnionWith(["https://app.example.com/cb"]);
                    client.PostLogoutRedirectUris.UnionWith(["https://app.example.com/logout"]);
                    client.AllowedScopes.UnionWith(["openid"]);
                }));

        using var provider = services.BuildServiceProvider();
        var repo = provider.GetRequiredService<IClientRepository>();

        var found = await repo.FindByClientIdAsync("public-client", ct);

        found.Should().NotBeNull();
        found!.IsPublic.Should().BeTrue();
        found.Secrets.Should().BeEmpty();
    }

    [Fact]
    public async Task AddConfidential_resolves_client_as_confidential()
    {
        var ct = TestContext.Current.CancellationToken;
        var services = ServicesWithLogging();

        services.AddZeeKayDaAuthCore(o => o.Issuer = "https://test.example.com")
            .AddClientSecretHasher<TestHasher>()
            .AddInMemoryClients(clients =>
                clients.AddConfidential("confidential-client", client =>
                {
                    client.Secret = "very-secret";
                    client.RedirectUris.UnionWith(["https://app.example.com/cb"]);
                    client.AllowedScopes.UnionWith(["openid"]);
                }));
        AdvertiseClientSecretMethods(services);

        using var provider = services.BuildServiceProvider();
        var repo = provider.GetRequiredService<IClientRepository>();

        var found = await repo.FindByClientIdAsync("confidential-client", ct);

        found.Should().NotBeNull();
        found!.IsPublic.Should().BeFalse();
        found.Secrets.Should().ContainSingle();
    }

    [Fact]
    public async Task Add_resolves_pre_built_registration()
    {
        var ct = TestContext.Current.CancellationToken;
        var services = ServicesWithLogging();

        var preBuilt = Client.CreatePublic(
            "pre-built-client",
            ["https://app.example.com/cb"],
            [],
            ["openid"]);

        services.AddZeeKayDaAuthCore(AllowPublicClients)
            .AddClientSecretHasher<TestHasher>()
            .AddInMemoryClients(clients => clients.Add(preBuilt));

        using var provider = services.BuildServiceProvider();
        var repo = provider.GetRequiredService<IClientRepository>();

        var found = await repo.FindByClientIdAsync("pre-built-client", ct);

        found.Should().NotBeNull();
        found.Should().BeSameAs(preBuilt);
    }

    // ── Fakes ─────────────────────────────────────────────────────────────────────────────────────

    private static readonly ClientSecret TestSecret = new("$test-secret$x");

    private sealed class TestHasher : IClientSecretHasher
    {
        public IReadOnlySet<string> AlgorithmIds { get; } = new HashSet<string> { "test-secret" };
        public bool Verify(ReadOnlySpan<char> presented, ClientSecret stored) => false;
        public ClientSecret Create(ReadOnlySpan<char> plaintext) => TestSecret;
    }

    private sealed class CustomClientRepository : IClientRepository
    {
        public Task<IClientWithCredentials?> FindByClientIdAsync(
            string clientId, CancellationToken cancellationToken = default)
            => Task.FromResult<IClientWithCredentials?>(null);
    }
}
