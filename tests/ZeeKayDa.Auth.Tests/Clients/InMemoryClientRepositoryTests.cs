using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using ZeeKayDa.Auth.Clients;
using ZeeKayDa.Auth.Configuration;

namespace ZeeKayDa.Auth.Tests.Clients;

public sealed class InMemoryClientRepositoryTests
{
    // ── Fake infrastructure ───────────────────────────────────────────────────────────────────────

    private sealed class FakeSecret : IClientSecret { }

    private sealed class CapturingLogger : ILogger<InMemoryClientRepository>
    {
        private readonly List<string> _warnings = new();

        public IReadOnlyList<string> Warnings => _warnings;

        public IDisposable? BeginScope<TState>(TState state) where TState : notnull => null;
        public bool IsEnabled(LogLevel logLevel) => true;

        public void Log<TState>(
            LogLevel logLevel,
            EventId eventId,
            TState state,
            Exception? exception,
            Func<TState, Exception?, string> formatter)
        {
            if (logLevel == LogLevel.Warning)
                _warnings.Add(formatter(state, exception));
        }
    }

    private sealed class FakeHasher : IClientSecretHasher
    {
        public bool CanHandle(IClientSecret secret) => secret is FakeSecret;
        public bool Verify(IClientSecret stored, ReadOnlySpan<char> presented) => false;

        public IClientSecret Create(string plaintext)
        {
            // Mirror ClientSecretHasher<T>.Create: reject a null/empty/whitespace plaintext secret.
            if (string.IsNullOrWhiteSpace(plaintext))
                throw new ArgumentException("Plaintext secret must not be empty.", nameof(plaintext));

            return new FakeSecret();
        }
    }

    private static CompositeClientSecretHasher MakeHasher()
        => new CompositeClientSecretHasher(
            [new FakeHasher()],
            Options.Create(new ClientSecretHasherRegistrationOptions()));

    private static AuthorizationServerOptions DefaultServerOptions()
    {
        var opts = new AuthorizationServerOptions { Issuer = "https://test.example.com" };
        // Include "none" so public clients pass the subset validation check.
        opts.TokenEndpoint.AuthMethodsSupported.Add(TokenEndpointAuthMethod.None);
        return opts;
    }

    private static ClientRegistrationValidator MakeValidator(
        AuthorizationServerOptions? serverOptions = null)
        => new ClientRegistrationValidator(
            Options.Create(serverOptions ?? DefaultServerOptions()),
            MakeHasher(),
            NullLogger<ClientRegistrationValidator>.Instance);

    private static InMemoryClientRepository MakeRepository(
        InMemoryClientRegistrationOptions opts,
        AuthorizationServerOptions? serverOptions = null,
        ILogger<InMemoryClientRepository>? logger = null)
    {
        var so = serverOptions ?? DefaultServerOptions();
        return new InMemoryClientRepository(
            Options.Create(opts),
            MakeHasher(),
            MakeValidator(so),
            Options.Create(so),
            logger ?? NullLogger<InMemoryClientRepository>.Instance);
    }

    private static ClientRegistration ValidPublicClient(string clientId = "test-client") =>
        ClientRegistration.CreatePublic(
            clientId,
            ["https://app.example.com/cb"],
            [],
            ["openid"]);

    // ── FindByClientIdAsync ───────────────────────────────────────────────────────────────────────

    [Fact]
    public async Task FindByClientIdAsync_returns_registration_for_known_client()
    {
        var client = ValidPublicClient("my-app");
        var opts = new InMemoryClientRegistrationOptions();
        opts.PreBuilt.Add(client);
        var repo = MakeRepository(opts);

        var found = await repo.FindByClientIdAsync("my-app", TestContext.Current.CancellationToken);

        found.Should().NotBeNull();
        found!.ClientId.Should().Be("my-app");
    }

    [Fact]
    public async Task FindByClientIdAsync_returns_null_for_unknown_client_id()
    {
        var opts = new InMemoryClientRegistrationOptions();
        opts.PreBuilt.Add(ValidPublicClient("known-client"));
        var repo = MakeRepository(opts);

        var found = await repo.FindByClientIdAsync("unknown-client", TestContext.Current.CancellationToken);

        found.Should().BeNull();
    }

    [Fact]
    public async Task FindByClientIdAsync_does_not_throw_for_unknown_client_id()
    {
        var opts = new InMemoryClientRegistrationOptions();
        opts.PreBuilt.Add(ValidPublicClient("known-client"));
        var repo = MakeRepository(opts);

        var act = async () => await repo.FindByClientIdAsync("does-not-exist", TestContext.Current.CancellationToken);

        await act.Should().NotThrowAsync();
    }

    [Fact]
    public async Task FindByClientIdAsync_returns_null_without_throwing_for_null_client_id()
    {
        // Dictionary<string, T>.TryGetValue throws on a null key. The IClientRepository contract
        // requires returning null for an unknown or malformed client_id — never throwing.
        var opts = new InMemoryClientRegistrationOptions();
        opts.PreBuilt.Add(ValidPublicClient("known-client"));
        var repo = MakeRepository(opts);

        IClientRegistration? found = null;
        var act = async () => found = await repo.FindByClientIdAsync(null!, TestContext.Current.CancellationToken);

        await act.Should().NotThrowAsync();
        found.Should().BeNull();
    }

    [Fact]
    public async Task FindByClientIdAsync_returns_null_when_client_id_has_different_case()
    {
        // Ordinal lookup: "MyClient" != "myclient"
        var opts = new InMemoryClientRegistrationOptions();
        opts.PreBuilt.Add(ValidPublicClient("MyClient"));
        var repo = MakeRepository(opts);

        var found = await repo.FindByClientIdAsync("myclient", TestContext.Current.CancellationToken);

        found.Should().BeNull();
    }

    [Fact]
    public async Task FindByClientIdAsync_returns_client_for_exact_case_client_id()
    {
        var opts = new InMemoryClientRegistrationOptions();
        opts.PreBuilt.Add(ValidPublicClient("MyClient"));
        var repo = MakeRepository(opts);

        var found = await repo.FindByClientIdAsync("MyClient", TestContext.Current.CancellationToken);

        found.Should().NotBeNull();
    }

    // ── Duplicate detection ───────────────────────────────────────────────────────────────────────

    [Fact]
    public void Constructor_throws_ZeeKayDaConfigurationException_for_duplicate_client_id()
    {
        var opts = new InMemoryClientRegistrationOptions();
        opts.PreBuilt.Add(ValidPublicClient("duplicate-id"));
        opts.PreBuilt.Add(ValidPublicClient("duplicate-id"));

        var act = () => MakeRepository(opts);

        act.Should().Throw<ZeeKayDaConfigurationException>()
            .Which.AggregatedFailures.Should().Contain(f => f.Code == "client.client_id.duplicate");
    }

    // ── Validation on construction ────────────────────────────────────────────────────────────────

    [Fact]
    public void Constructor_throws_ZeeKayDaConfigurationException_for_invalid_client()
    {
        var opts = new InMemoryClientRegistrationOptions();
        // A client with a fragment in its redirect URI
        opts.PreBuilt.Add(new ClientRegistration
        {
            ClientId = "bad-client",
            Credentials = [],
            IsPublic = true,
            RedirectUris = new HashSet<string>(["https://app.example.com/cb#bad"], StringComparer.Ordinal),
            PostLogoutRedirectUris = new HashSet<string>(StringComparer.Ordinal),
            AllowedTokenEndpointAuthMethods = new HashSet<string>(
                [TokenEndpointAuthMethods.None], StringComparer.Ordinal)
        });

        var act = () => MakeRepository(opts);

        act.Should().Throw<ZeeKayDaConfigurationException>()
            .Which.AggregatedFailures.Should().Contain(f => f.Code == "client.redirect_uri.fragment");
    }

    // ── Multiple clients ──────────────────────────────────────────────────────────────────────────

    [Fact]
    public async Task Constructor_makes_all_clients_accessible_when_multiple_clients_are_registered()
    {
        var ct = TestContext.Current.CancellationToken;
        var opts = new InMemoryClientRegistrationOptions();
        opts.PreBuilt.Add(ValidPublicClient("client-a"));
        opts.PreBuilt.Add(ValidPublicClient("client-b"));
        opts.PreBuilt.Add(ValidPublicClient("client-c"));
        var repo = MakeRepository(opts);

        (await repo.FindByClientIdAsync("client-a", ct)).Should().NotBeNull();
        (await repo.FindByClientIdAsync("client-b", ct)).Should().NotBeNull();
        (await repo.FindByClientIdAsync("client-c", ct)).Should().NotBeNull();
    }

    // ── Confidential client via Pending spec ──────────────────────────────────────────────────────

    [Fact]
    public async Task Constructor_hashes_and_makes_accessible_pending_confidential_client()
    {
        var opts = new InMemoryClientRegistrationOptions();
        opts.Pending.Add(new PendingConfidentialClientSpec(
            "confidential-client",
            "super-secret",
            ["https://app.example.com/cb"],
            [],
            ["openid"]));

        var repo = MakeRepository(opts);

        var found = await repo.FindByClientIdAsync("confidential-client", TestContext.Current.CancellationToken);
        found.Should().NotBeNull();
        found!.IsPublic.Should().BeFalse();
        found.Credentials.Should().ContainSingle(c => c is IClientSecret);
    }

    // ── Aggregates failures from multiple invalid clients ─────────────────────────────────────────

    [Fact]
    public void Constructor_aggregates_all_failures_for_multiple_invalid_clients()
    {
        var opts = new InMemoryClientRegistrationOptions();
        opts.PreBuilt.Add(new ClientRegistration
        {
            ClientId = "bad-client-1",
            Credentials = [],
            IsPublic = true,
            RedirectUris = new HashSet<string>(["https://app.example.com/cb#frag1"], StringComparer.Ordinal),
            PostLogoutRedirectUris = new HashSet<string>(StringComparer.Ordinal),
            AllowedTokenEndpointAuthMethods = new HashSet<string>(
                [TokenEndpointAuthMethods.None], StringComparer.Ordinal)
        });
        opts.PreBuilt.Add(new ClientRegistration
        {
            ClientId = "bad-client-2",
            Credentials = [],
            IsPublic = true,
            RedirectUris = new HashSet<string>(["https://app.example.com/cb#frag2"], StringComparer.Ordinal),
            PostLogoutRedirectUris = new HashSet<string>(StringComparer.Ordinal),
            AllowedTokenEndpointAuthMethods = new HashSet<string>(
                [TokenEndpointAuthMethods.None], StringComparer.Ordinal)
        });

        var act = () => MakeRepository(opts);

        act.Should().Throw<ZeeKayDaConfigurationException>()
            .Which.AggregatedFailures.Count.Should().BeGreaterThanOrEqualTo(2);
    }

    // ── Empty plaintext secret is aggregated, not thrown bare ─────────────────────────────────────

    [Fact]
    public void Constructor_throws_aggregated_ZeeKayDaConfigurationException_for_pending_spec_with_empty_secret()
    {
        // hasher.Create throws ArgumentException on a blank secret. The repository must convert that
        // into a structured failure rather than letting the bare ArgumentException abort construction.
        var opts = new InMemoryClientRegistrationOptions();
        opts.Pending.Add(new PendingConfidentialClientSpec(
            "empty-secret-client",
            string.Empty,
            ["https://app.example.com/cb"],
            [],
            ["openid"]));

        var act = () => MakeRepository(opts);

        act.Should().Throw<ZeeKayDaConfigurationException>()
            .Which.AggregatedFailures.Should()
                .Contain(f => f.Code == "client.credentials.empty_plaintext_secret");
    }

    // ── Empty plaintext secret is aggregated, not thrown bare — part 2 ───────────────────────────

    [Fact]
    public void Constructor_aggregates_both_failures_in_one_exception_for_empty_secret_and_other_invalid_client()
    {
        // The empty-secret spec must not short-circuit construction: a second, separately invalid
        // client's problems must still be reported in the same exception.
        var opts = new InMemoryClientRegistrationOptions();
        opts.Pending.Add(new PendingConfidentialClientSpec(
            "empty-secret-client",
            "   ",
            ["https://app.example.com/cb"],
            [],
            ["openid"]));
        opts.PreBuilt.Add(new ClientRegistration
        {
            ClientId = "fragment-client",
            Credentials = [],
            IsPublic = true,
            RedirectUris = new HashSet<string>(["https://app.example.com/cb#frag"], StringComparer.Ordinal),
            PostLogoutRedirectUris = new HashSet<string>(StringComparer.Ordinal),
            AllowedTokenEndpointAuthMethods = new HashSet<string>(
                [TokenEndpointAuthMethods.None], StringComparer.Ordinal)
        });

        var act = () => MakeRepository(opts);

        var failures = act.Should().Throw<ZeeKayDaConfigurationException>()
            .Which.AggregatedFailures;
        failures.Should().Contain(f => f.Code == "client.credentials.empty_plaintext_secret");
        failures.Should().Contain(f => f.Code == "client.redirect_uri.fragment");
    }

    // ── None-advertised server-wide warning ───────────────────────────────────────────────────────

    [Fact]
    public void Constructor_logs_warning_when_none_is_advertised_but_no_public_clients_are_registered()
    {
        // Server advertises "none" but only confidential clients are registered → warning
        var logger = new CapturingLogger();
        var opts = new InMemoryClientRegistrationOptions();
        opts.Pending.Add(new PendingConfidentialClientSpec(
            "confidential-only",
            "super-secret",
            ["https://app.example.com/cb"],
            [],
            ["openid"]));

        MakeRepository(opts, logger: logger);

        logger.Warnings.Should().ContainSingle(w => w.Contains("none"));
    }

    [Fact]
    public void Constructor_does_not_log_warning_when_none_is_advertised_and_public_client_is_present()
    {
        // Server advertises "none" and at least one public client is registered → no warning
        var logger = new CapturingLogger();
        var opts = new InMemoryClientRegistrationOptions();
        opts.PreBuilt.Add(ValidPublicClient("public-client"));

        MakeRepository(opts, logger: logger);

        logger.Warnings.Should().NotContain(w => w.Contains("none"));
    }
}
