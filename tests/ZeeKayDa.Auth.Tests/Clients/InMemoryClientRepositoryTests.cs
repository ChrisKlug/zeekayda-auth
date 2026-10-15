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

    private static ClientSecretHasherRegistry MakeRegistry()
        => new([new FakeHasher()], Options.Create(new ClientSecretHasherRegistrationOptions()));

    private static ClientSecrets MakeSecrets()
        => new(MakeRegistry(), NullSanitizingLogger<ClientSecrets>.Instance);

    private static AuthorizationServerOptions DefaultServerOptions()
        => new() { Issuer = "https://test.example.com" };

    private static ClientRegistrationValidator MakeValidator(
        AuthorizationServerOptions? serverOptions = null)
    {
        var options = serverOptions ?? DefaultServerOptions();
        return new ClientRegistrationValidator(
            Options.Create(options),
            TestAuthMethods.Advertised(options),
            MakeRegistry(),
            NullSanitizingLogger<ClientRegistrationValidator>.Instance,
            keyRing: null);
    }

    private static InMemoryClientRepository MakeRepository(
        InMemoryClientRegistrationOptions opts,
        AuthorizationServerOptions? serverOptions = null)
    {
        return InMemoryClientRepository.Build(opts, MakeSecrets(), MakeValidator(serverOptions));
    }

    private static Client ValidPublicClient(string clientId = "test-client") =>
        Client.CreatePublic(
            clientId,
            ["https://app.example.com/cb"],
            [],
            ["openid"]);

    private static PendingConfidentialClientSpec PendingSpec(
        string clientId, string? plaintextSecret, bool requireConsent = true, string? secretHash = null) =>
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
            plaintextSecret,
            secretHash);

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
    public void Build_failure_for_a_public_client_on_a_server_whose_filter_withholds_none_names_the_filter()
    {
        var opts = new InMemoryClientRegistrationOptions();
        opts.PreBuilt.Add(ValidPublicClient("spa"));
        var serverOptions = DefaultServerOptions();
        serverOptions.TokenEndpoint.AdvertisedAuthMethods = [TokenEndpointAuthMethods.ClientSecretBasic];

        var act = () => MakeRepository(opts, serverOptions);

        act.Should().Throw<ZeeKayDaConfigurationException>()
            .Which.AggregatedFailures.Should()
            .ContainSingle(f => f.Code == "client.token_endpoint_auth_methods.not_subset")
            .Which.Message.Should().Contain("TokenEndpoint.AdvertisedAuthMethods leaves 'none' out");
    }

    [Fact]
    public void A_confidential_client_listing_none_fails_as_none_on_confidential_although_none_is_advertised()
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
        var act = () => MakeRepository(opts);

        act.Should().Throw<ZeeKayDaConfigurationException>()
            .Which.AggregatedFailures.Select(f => f.Code).Should().Equal(
                ["client.token_endpoint_auth_methods.none_on_confidential"],
                "the server advertising 'none' must not let a confidential client be called without credentials");
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

    [Fact]
    public async Task Build_stores_a_pending_secret_hash_as_given()
    {
        var opts = new InMemoryClientRegistrationOptions();
        opts.Pending.Add(PendingSpec("confidential-client", plaintextSecret: null, secretHash: "$fake-secret$stored"));

        var repo = MakeRepository(opts);

        var found = await repo.FindByClientIdAsync("confidential-client", TestContext.Current.CancellationToken);
        found!.Secrets.Should().ContainSingle().Which.Should().Be(new ClientSecret("$fake-secret$stored"));
    }

    [Fact]
    public void Build_rejects_a_pending_client_with_neither_a_secret_nor_a_secret_hash()
    {
        var opts = new InMemoryClientRegistrationOptions();
        opts.Pending.Add(PendingSpec("no-secret-client", plaintextSecret: null));

        var act = () => MakeRepository(opts);

        act.Should().Throw<ZeeKayDaConfigurationException>()
            .Which.AggregatedFailures.Should().ContainSingle(f => f.Code == "client.credentials.no_secret")
            .Which.Message.Should().Contain("no-secret-client");
    }

    [Fact]
    public void Build_rejects_a_pending_client_with_both_a_secret_and_a_secret_hash()
    {
        var opts = new InMemoryClientRegistrationOptions();
        opts.Pending.Add(PendingSpec("two-secret-client", "super-secret", secretHash: "$fake-secret$stored"));

        var act = () => MakeRepository(opts);

        act.Should().Throw<ZeeKayDaConfigurationException>()
            .Which.AggregatedFailures.Should().ContainSingle(f => f.Code == "client.credentials.secret_and_secret_hash")
            .Which.Message.Should().Contain("two-secret-client");
    }

    [Fact]
    public void Build_rejects_a_pending_client_with_a_whitespace_secret_hash()
    {
        var opts = new InMemoryClientRegistrationOptions();
        opts.Pending.Add(PendingSpec("blank-hash-client", plaintextSecret: null, secretHash: "  "));

        var act = () => MakeRepository(opts);

        act.Should().Throw<ZeeKayDaConfigurationException>()
            .Which.AggregatedFailures.Should().ContainSingle(f => f.Code == "client.credentials.empty_secret_hash")
            .Which.Message.Should().Contain("blank-hash-client");
    }

    [Fact]
    public void Build_releases_the_pending_plaintext_secrets_once_the_repository_is_built()
    {
        var opts = new InMemoryClientRegistrationOptions();
        opts.Pending.Add(PendingSpec("confidential-client", "super-secret"));

        MakeRepository(opts);

        opts.Pending.Should().BeEmpty();
    }

    [Fact]
    public void Build_keeps_the_pending_secrets_when_it_fails_so_building_again_fails_the_same_way()
    {
        var opts = new InMemoryClientRegistrationOptions();
        opts.Pending.Add(PendingSpec("confidential-client", "super-secret"));
        opts.Pending.Add(PendingSpec("no-secret-client", plaintextSecret: null));

        var act = () => MakeRepository(opts);

        act.Should().Throw<ZeeKayDaConfigurationException>();
        act.Should().Throw<ZeeKayDaConfigurationException>()
            .Which.AggregatedFailures.Should().ContainSingle(f => f.Code == "client.credentials.no_secret");
        opts.Pending.Should().HaveCount(2);
    }

    [Fact]
    public void A_pending_spec_prints_its_type_name_and_never_its_plaintext_secret()
    {
        PendingSpec("confidential-client", "super-secret").ToString()
            .Should().Be(nameof(PendingConfidentialClientSpec));
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

    // ── Failures are aggregated across clients ────────────────────────────────────────────────────

    [Fact]
    public void Build_aggregates_every_validation_failure_across_all_clients()
    {
        var opts = new InMemoryClientRegistrationOptions();
        var fragment = new HashSet<string>(["https://app.example.com/cb#fragment"], StringComparer.Ordinal);
        opts.PreBuilt.Add(ValidPublicClient("c1") with { RedirectUris = fragment });
        opts.PreBuilt.Add(ValidPublicClient("c2") with { RedirectUris = fragment });

        var act = () => MakeRepository(opts);

        act.Should().Throw<ZeeKayDaConfigurationException>()
            .Which.AggregatedFailures.Where(f => f.Code == "client.redirect_uri.fragment")
            .Should().HaveCount(2, "operators see every client's problems in one pass");
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
}
