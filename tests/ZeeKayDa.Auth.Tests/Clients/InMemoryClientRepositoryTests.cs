using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using ZeeKayDa.Auth;
using ZeeKayDa.Auth.Clients;
using ZeeKayDa.Auth.Configuration;
using ZeeKayDa.Auth.Logging;
using ZeeKayDa.Auth.Tokens;

namespace ZeeKayDa.Auth.Tests.Clients;

public sealed class InMemoryClientRepositoryTests
{
    // ── Fake infrastructure ───────────────────────────────────────────────────────────────────────

    private static readonly ClientSecret FakeSecret = new("$fake-secret$x");

    private sealed class FakeHasher : IClientSecretHasher
    {
        public IReadOnlySet<string> AlgorithmIds { get; } = new HashSet<string> { "fake-secret" };
        public bool Verify(ReadOnlySpan<char> presented, ClientSecret stored) => false;

        public ClientSecret Create(ReadOnlySpan<char> plaintext) => FakeSecret;
    }

    private sealed class DelegatingValidator(Func<IClientWithCredentials, IReadOnlyList<ZeeKayDaConfigurationFailure>> onValidate)
        : IClientRegistrationValidator
    {
        public IReadOnlyList<ZeeKayDaConfigurationFailure> Validate(IClientWithCredentials client) => onValidate(client);
    }

    private static ClientSecretHasherRegistry MakeRegistry()
        => new([new FakeHasher()], Options.Create(new ClientSecretHasherRegistrationOptions()));

    private static ClientSecrets MakeSecrets()
        => new(MakeRegistry(), NullSanitizingLogger<ClientSecrets>.Instance);

    private static AuthorizationServerOptions DefaultServerOptions()
    {
        var opts = new AuthorizationServerOptions { Issuer = "https://test.example.com" };
        // Include "none" so public clients pass the subset validation check.
        opts.TokenEndpoint.AuthMethodsSupported.Add(TokenEndpointAuthMethods.None);
        return opts;
    }

    private static ClientRegistrationValidator MakeValidator(
        AuthorizationServerOptions? serverOptions = null)
        => new ClientRegistrationValidator(
            Options.Create(serverOptions ?? DefaultServerOptions()),
            MakeRegistry(),
            NullSanitizingLogger<ClientRegistrationValidator>.Instance,
            keyRing: null);

    private static InMemoryClientRepository MakeRepository(
        InMemoryClientRegistrationOptions opts,
        AuthorizationServerOptions? serverOptions = null,
        SanitizingLogger<InMemoryClientRepository>? logger = null)
    {
        var so = serverOptions ?? DefaultServerOptions();
        return InMemoryClientRepository.Build(
            opts,
            MakeSecrets(),
            MakeValidator(so),
            so,
            logger ?? NullSanitizingLogger<InMemoryClientRepository>.Instance);
    }

    private static InMemoryClientRepository MakeRepositoryWithValidator(
        InMemoryClientRegistrationOptions opts, IClientRegistrationValidator validator)
    {
        return InMemoryClientRepository.Build(
            opts,
            MakeSecrets(),
            validator,
            DefaultServerOptions(),
            NullSanitizingLogger<InMemoryClientRepository>.Instance);
    }

    private static Client ValidPublicClient(string clientId = "test-client") =>
        Client.CreatePublic(
            clientId,
            ["https://app.example.com/cb"],
            [],
            ["openid"]);

    private static PendingConfidentialClientSpec PendingSpec(
        string clientId, string plaintextSecret, bool requireConsent = true) =>
        new(
            new Client
            {
                ClientId = clientId,
                Secrets = [],
                IsPublic = false,
                RedirectUris = new HashSet<string>(["https://app.example.com/cb"], StringComparer.Ordinal),
                PostLogoutRedirectUris = new HashSet<string>(StringComparer.Ordinal),
                AllowedScopes = new HashSet<string>(["openid"], StringComparer.Ordinal),
                RequireConsent = requireConsent,
            },
            plaintextSecret);

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

        IClientWithCredentials? found = null;
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
    public void Build_throws_ZeeKayDaConfigurationException_for_duplicate_client_id()
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
    public void Build_throws_ZeeKayDaConfigurationException_for_invalid_client()
    {
        var opts = new InMemoryClientRegistrationOptions();
        // A client with a fragment in its redirect URI
        opts.PreBuilt.Add(new Client
        {
            ClientId = "bad-client",
            Secrets = [],
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

    [Fact]
    public void Build_failure_for_a_public_client_on_a_server_not_advertising_none_names_the_line_that_adds_it()
    {
        var opts = new InMemoryClientRegistrationOptions();
        opts.PreBuilt.Add(ValidPublicClient("spa"));
        // The default AuthMethodsSupported, which does not advertise "none".
        var serverOptions = new AuthorizationServerOptions { Issuer = "https://test.example.com" };

        var act = () => MakeRepository(opts, serverOptions);

        act.Should().Throw<ZeeKayDaConfigurationException>()
            .Which.AggregatedFailures.Should()
            .ContainSingle(f => f.Code == "client.token_endpoint_auth_methods.not_subset")
            .Which.Message.Should().Contain(
                "options.TokenEndpoint.AuthMethodsSupported.Add(TokenEndpointAuthMethods.None);");
    }

    [Fact]
    public void Build_failure_for_a_confidential_client_listing_none_does_not_suggest_advertising_none()
    {
        var opts = new InMemoryClientRegistrationOptions();
        opts.PreBuilt.Add(
            Client.CreateConfidential("web", FakeSecret, ["https://app.example.com/cb"], [], ["openid"])
            with
            {
                AllowedTokenEndpointAuthMethods = new HashSet<string>(
                    [TokenEndpointAuthMethods.None, TokenEndpointAuthMethods.ClientSecretBasic],
                    StringComparer.Ordinal),
            });
        // The default AuthMethodsSupported, which does not advertise "none".
        var serverOptions = new AuthorizationServerOptions { Issuer = "https://test.example.com" };

        var act = () => MakeRepository(opts, serverOptions);

        act.Should().Throw<ZeeKayDaConfigurationException>()
            .Which.AggregatedFailures.Should()
            .ContainSingle(f => f.Code == "client.token_endpoint_auth_methods.not_subset")
            .Which.Message.Should().NotContain(
                "Public clients",
                because: "a confidential client listing 'none' is fixed by removing it from the client, " +
                         "and advertising 'none' on the server would not make its registration valid");
    }

    // ── Multiple clients ──────────────────────────────────────────────────────────────────────────

    [Fact]
    public async Task Build_makes_all_clients_accessible_when_multiple_clients_are_registered()
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
    public async Task Build_hashes_and_makes_accessible_pending_confidential_client()
    {
        var opts = new InMemoryClientRegistrationOptions();
        opts.Pending.Add(PendingSpec("confidential-client", "super-secret"));

        var repo = MakeRepository(opts);

        var found = await repo.FindByClientIdAsync("confidential-client", TestContext.Current.CancellationToken);
        found.Should().NotBeNull();
        found!.IsPublic.Should().BeFalse();
        found.Secrets.Should().ContainSingle().Which.Should().Be(FakeSecret);
    }

    [Fact]
    public async Task Build_keeps_the_pending_registration_settings_when_it_adds_the_hashed_secret()
    {
        var opts = new InMemoryClientRegistrationOptions();
        opts.Pending.Add(PendingSpec("confidential-client", "super-secret", requireConsent: false));

        var repo = MakeRepository(opts);

        var found = await repo.FindByClientIdAsync("confidential-client", TestContext.Current.CancellationToken);
        found.Should().NotBeNull();
        found!.RequireConsent.Should().BeFalse();
        found.Secrets.Should().ContainSingle().Which.Should().Be(FakeSecret);
    }

    [Fact]
    public async Task Build_stored_credential_is_not_equal_to_original_plaintext()
    {
        // After hashing, the stored secret must be the FakeSecret produced by FakeHasher, not a
        // value equal to (or wrapping) the original plaintext. This verifies that the
        // repository does not short-circuit the hasher and stash the plaintext directly.
        var ct = TestContext.Current.CancellationToken;
        const string plaintext = "super-secret";
        var opts = new InMemoryClientRegistrationOptions();
        opts.Pending.Add(PendingSpec("confidential-client", plaintext));

        var repo = MakeRepository(opts);

        var found = await repo.FindByClientIdAsync("confidential-client", ct);
        found.Should().NotBeNull();
        found!.Secrets.Single().Should().Be(FakeSecret);
    }

    // ── Aggregates failures from multiple invalid clients ─────────────────────────────────────────

    [Fact]
    public void Build_aggregates_all_failures_for_multiple_invalid_clients()
    {
        var opts = new InMemoryClientRegistrationOptions();
        opts.PreBuilt.Add(new Client
        {
            ClientId = "bad-client-1",
            Secrets = [],
            IsPublic = true,
            RedirectUris = new HashSet<string>(["https://app.example.com/cb#frag1"], StringComparer.Ordinal),
            PostLogoutRedirectUris = new HashSet<string>(StringComparer.Ordinal),
            AllowedTokenEndpointAuthMethods = new HashSet<string>(
                [TokenEndpointAuthMethods.None], StringComparer.Ordinal)
        });
        opts.PreBuilt.Add(new Client
        {
            ClientId = "bad-client-2",
            Secrets = [],
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

    // ── A custom validator's failures are aggregated ──────────────────────────────────────────────

    [Fact]
    public void Build_aggregates_every_failure_a_validator_returns_across_all_clients()
    {
        var opts = new InMemoryClientRegistrationOptions();
        opts.PreBuilt.Add(ValidPublicClient("c1"));
        opts.PreBuilt.Add(ValidPublicClient("c2"));
        var validator = new DelegatingValidator(client =>
            [new ZeeKayDaConfigurationFailure("host.rule", $"Failed for {client.ClientId}.")]);

        var act = () => MakeRepositoryWithValidator(opts, validator);

        act.Should().Throw<ZeeKayDaConfigurationException>()
            .Which.AggregatedFailures.Select(f => f.Message)
            .Should().Equal("Failed for c1.", "Failed for c2.");
    }

    [Fact]
    public async Task Build_serves_every_client_when_the_validator_returns_no_failures()
    {
        var opts = new InMemoryClientRegistrationOptions();
        opts.PreBuilt.Add(ValidPublicClient("c1"));

        var repository = MakeRepositoryWithValidator(opts, new DelegatingValidator(_ => []));

        (await repository.FindByClientIdAsync("c1", TestContext.Current.CancellationToken)).Should().NotBeNull();
    }

    [Fact]
    public void Build_names_a_validator_that_returns_a_null_failure_instead_of_a_bare_null_reference()
    {
        var opts = new InMemoryClientRegistrationOptions();
        opts.PreBuilt.Add(ValidPublicClient("c1"));

        var act = () => MakeRepositoryWithValidator(opts, new DelegatingValidator(_ => [null!]));

        act.Should().Throw<InvalidOperationException>().WithMessage("*DelegatingValidator*null failure*'c1'*");
    }

    // ── Empty plaintext secret is aggregated, not thrown bare ─────────────────────────────────────

    [Fact]
    public void Build_throws_aggregated_ZeeKayDaConfigurationException_for_pending_spec_with_empty_secret()
    {
        // hasher.Create throws ArgumentException on a blank secret. The repository must convert that
        // into a structured failure rather than letting the bare ArgumentException abort construction.
        var opts = new InMemoryClientRegistrationOptions();
        opts.Pending.Add(PendingSpec("empty-secret-client", string.Empty));

        var act = () => MakeRepository(opts);

        act.Should().Throw<ZeeKayDaConfigurationException>()
            .Which.AggregatedFailures.Should()
                .Contain(f => f.Code == "client.credentials.empty_plaintext_secret");
    }

    // ── Empty plaintext secret is aggregated, not thrown bare — part 2 ───────────────────────────

    [Fact]
    public void Build_aggregates_both_failures_in_one_exception_for_empty_secret_and_other_invalid_client()
    {
        // The empty-secret spec must not short-circuit construction: a second, separately invalid
        // client's problems must still be reported in the same exception.
        var opts = new InMemoryClientRegistrationOptions();
        opts.Pending.Add(PendingSpec("empty-secret-client", "   "));
        opts.PreBuilt.Add(new Client
        {
            ClientId = "fragment-client",
            Secrets = [],
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
    public void Build_logs_warning_when_none_is_advertised_but_no_public_clients_are_registered()
    {
        // Server advertises "none" but only confidential clients are registered → warning
        var logger = new CapturingSanitizingLogger<InMemoryClientRepository>();
        var opts = new InMemoryClientRegistrationOptions();
        opts.Pending.Add(PendingSpec("confidential-only", "super-secret"));

        MakeRepository(opts, logger: logger);

        logger.Entries.Should().ContainSingle(e => e.Level == LogLevel.Warning && e.Message.Contains("none"));
    }

    [Fact]
    public void Build_does_not_log_warning_when_none_is_advertised_and_public_client_is_present()
    {
        // Server advertises "none" and at least one public client is registered → no warning
        var logger = new CapturingSanitizingLogger<InMemoryClientRepository>();
        var opts = new InMemoryClientRegistrationOptions();
        opts.PreBuilt.Add(ValidPublicClient("public-client"));

        MakeRepository(opts, logger: logger);

        logger.Entries.Should().NotContain(e => e.Level == LogLevel.Warning && e.Message.Contains("none"));
    }
}
