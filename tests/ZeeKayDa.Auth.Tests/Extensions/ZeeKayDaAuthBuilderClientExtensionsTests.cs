using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;
using ZeeKayDa.Auth;
using ZeeKayDa.Auth.Clients;
using ZeeKayDa.Auth.Tokens;

namespace ZeeKayDa.Auth.Tests.Extensions;

public sealed class ZeeKayDaAuthBuilderClientExtensionsTests
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
        options.TokenEndpoint.AuthMethodsSupported.Add(TokenEndpointAuthMethods.None);
    }

    [Fact]
    public void AddInMemoryClients_throws_if_IClientRepository_is_already_registered()
    {
        var services = ServicesWithLogging();
        var builder = services.AddZeeKayDaAuthCore(AllowPublicClients);

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
        var services = ServicesWithLogging();
        var builder = services.AddZeeKayDaAuthCore(AllowPublicClients);

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
        var services = ServicesWithLogging();

        services.AddZeeKayDaAuthCore(AllowPublicClients)
            .AddClientSecretHasher<TestHasher>()
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
        var services = ServicesWithLogging();

        services.AddZeeKayDaAuthCore(AllowPublicClients)
            .AddClientSecretHasher<TestHasher>()
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
        var services = ServicesWithLogging();

        // Note: confidential client uses client_secret_basic (the default), which IS in the
        // server's default AuthMethodsSupported. No need to add None for this test.
        services.AddZeeKayDaAuthCore(o => o.Issuer = "https://test.example.com")
            .AddClientSecretHasher<TestHasher>()
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
        var services = ServicesWithLogging();

        var preBuilt = ClientRegistration.CreatePublic(
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

    private sealed class TestSecret : IClientSecret { public IClientCredential Snapshot() => new TestSecret(); }

    private sealed class TestHasher : IClientSecretHasher
    {
        public bool CanHandle(IClientSecret secret) => secret is TestSecret;
        public bool Verify(IClientSecret stored, ReadOnlySpan<char> presented) => false;
        public IClientSecret Create(ReadOnlySpan<char> plaintext) => new TestSecret();
    }

    private sealed class CustomClientRepository : IClientRepository
    {
        public Task<IClientRegistration?> FindByClientIdAsync(
            string clientId, CancellationToken cancellationToken = default)
            => Task.FromResult<IClientRegistration?>(null);
    }
}
