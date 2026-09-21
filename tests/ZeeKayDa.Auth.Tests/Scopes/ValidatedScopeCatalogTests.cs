using ZeeKayDa.Auth.Scopes;

namespace ZeeKayDa.Auth.Tests.Scopes;

public sealed class ValidatedScopeCatalogTests
{
    private static ValidatedScopeCatalog Catalog(params ScopeDefinition[] scopes) =>
        new(new StubRepository(scopes));

    private static async Task<IReadOnlyList<string>> CodesFrom(ValidatedScopeCatalog catalog)
    {
        var act = async () => await catalog.GetScopesAsync(TestContext.Current.CancellationToken);

        var thrown = await act.Should().ThrowAsync<ZeeKayDaConfigurationException>();
        return [.. thrown.Which.AggregatedFailures.Select(failure => failure.Code)];
    }

    // ── A repository that keeps the contract ──────────────────────────────────────────────────

    [Fact]
    public async Task GetScopesAsync_returns_the_scopes_a_well_formed_repository_serves()
    {
        var catalog = Catalog(StandardScopes.OpenId, StandardScopes.Profile);

        var scopes = await catalog.GetScopesAsync(TestContext.Current.CancellationToken);

        scopes.Select(scope => scope.Name).Should().BeEquivalentTo(["openid", "profile"]);
    }

    [Fact]
    public async Task GetScopesAsync_accepts_the_shipped_standard_scopes()
    {
        var catalog = new ValidatedScopeCatalog(new InMemoryScopeRepository(StandardScopes.All));

        var act = async () => await catalog.GetScopesAsync(TestContext.Current.CancellationToken);

        await act.Should().NotThrowAsync();
    }

    [Fact]
    public async Task GetScopesAsync_propagates_the_cancellation_token_to_the_repository()
    {
        var repository = new CapturingRepository();
        var catalog = new ValidatedScopeCatalog(repository);
        using var cts = new CancellationTokenSource();

        await catalog.GetScopesAsync(cts.Token);

        repository.ObservedToken.Should().Be(cts.Token);
    }

    // ── What is validated is what is served ───────────────────────────────────────────────────

    [Fact]
    public async Task GetScopesAsync_returns_copies_so_a_repository_mutating_a_definition_afterwards_changes_nothing()
    {
        // The whole point of copying: a repository free to edit what it handed back would have one
        // set of claims approved and a different set used to issue a token.
        var claims = new List<string> { "email" };
        var repository = new StubRepository(
            [StandardScopes.OpenId, new ScopeDefinition { Name = "custom", UserInfoClaims = claims }]);
        var catalog = new ValidatedScopeCatalog(repository);

        var scopes = await catalog.GetScopesAsync(TestContext.Current.CancellationToken);
        claims.Add("");

        scopes.Single(scope => scope.Name == "custom").UserInfoClaims.Should().BeEquivalentTo(["email"]);
    }

    [Fact]
    public async Task GetScopesAsync_validates_every_call_so_a_repository_that_breaks_later_is_caught()
    {
        // Startup alone would not catch this: the repository answered correctly when it was asked
        // at startup and only then began serving a scope with no name.
        var repository = new MutableRepository([StandardScopes.OpenId]);
        var catalog = new ValidatedScopeCatalog(repository);
        await catalog.GetScopesAsync(TestContext.Current.CancellationToken);

        repository.Scopes = [StandardScopes.OpenId, new ScopeDefinition { Name = " " }];

        (await CodesFrom(catalog)).Should().Contain("scopes.name.blank");
    }

    // ── The collection itself ─────────────────────────────────────────────────────────────────

    [Fact]
    public async Task GetScopesAsync_fails_with_scopes_null_when_the_repository_returns_null()
    {
        var catalog = new ValidatedScopeCatalog(new NullReturningRepository());

        (await CodesFrom(catalog)).Should().Contain("scopes.null");
    }

    [Fact]
    public async Task GetScopesAsync_fails_with_scopes_element_null_when_an_element_is_null()
    {
        var catalog = Catalog(StandardScopes.OpenId, null!);

        (await CodesFrom(catalog)).Should().BeEquivalentTo(["scopes.element.null"]);
    }

    [Fact]
    public async Task GetScopesAsync_still_validates_the_scopes_beside_a_null_element()
    {
        // A null element must not stop the pass; an operator fixing one failure per restart is
        // exactly what aggregating them avoids.
        var catalog = Catalog(StandardScopes.OpenId, null!, new ScopeDefinition { Name = "api", Audience = "not-a-uri" });

        (await CodesFrom(catalog)).Should().BeEquivalentTo(["scopes.element.null", "scopes.audience.invalid"]);
    }

    // ── Names ─────────────────────────────────────────────────────────────────────────────────

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("   ")]
    public async Task GetScopesAsync_fails_with_scopes_name_blank_when_a_scope_has_no_name(string? name)
    {
        var catalog = Catalog(StandardScopes.OpenId, new ScopeDefinition { Name = name! });

        (await CodesFrom(catalog)).Should().BeEquivalentTo(["scopes.name.blank"]);
    }

    [Fact]
    public async Task GetScopesAsync_fails_with_scopes_name_duplicate_when_two_scopes_share_a_name()
    {
        // Both are published to scopes_supported and one wins the resolution, deciding the claims
        // unlocked and the audience the access token carries.
        var catalog = Catalog(
            StandardScopes.OpenId,
            new ScopeDefinition { Name = "api", Audience = "https://api.example.com" },
            new ScopeDefinition { Name = "api", Audience = "https://other.example.com" });

        (await CodesFrom(catalog)).Should().BeEquivalentTo(["scopes.name.duplicate"]);
    }

    [Fact]
    public async Task GetScopesAsync_reports_one_duplicate_failure_per_name_not_per_extra_scope()
    {
        var catalog = Catalog(
            StandardScopes.OpenId,
            new ScopeDefinition { Name = "api" },
            new ScopeDefinition { Name = "api" },
            new ScopeDefinition { Name = "api" });

        (await CodesFrom(catalog)).Should().BeEquivalentTo(["scopes.name.duplicate"]);
    }

    [Fact]
    public async Task GetScopesAsync_compares_names_ordinally_so_two_casings_are_two_scopes()
    {
        // A requested scope is matched ordinally, so "api" and "API" genuinely are two scopes and
        // reporting them as a duplicate would refuse a valid configuration.
        var catalog = Catalog(StandardScopes.OpenId, new ScopeDefinition { Name = "api" }, new ScopeDefinition { Name = "API" });

        var act = async () => await catalog.GetScopesAsync(TestContext.Current.CancellationToken);

        await act.Should().NotThrowAsync();
    }

    // ── Claim lists ───────────────────────────────────────────────────────────────────────────

    [Fact]
    public async Task GetScopesAsync_fails_with_scopes_claims_blank_for_each_null_claim_list()
    {
        var catalog = Catalog(
            StandardScopes.OpenId,
            new ScopeDefinition { Name = "custom", IdTokenClaims = null!, UserInfoClaims = null!, AccessTokenClaims = null! });

        (await CodesFrom(catalog)).Should().BeEquivalentTo(
            ["scopes.claims.blank", "scopes.claims.blank", "scopes.claims.blank"]);
    }

    [Fact]
    public async Task GetScopesAsync_names_the_property_an_operator_must_fix_for_a_null_claim_list()
    {
        var catalog = Catalog(StandardScopes.OpenId, new ScopeDefinition { Name = "custom", UserInfoClaims = null! });

        var act = async () => await catalog.GetScopesAsync(TestContext.Current.CancellationToken);

        var thrown = await act.Should().ThrowAsync<ZeeKayDaConfigurationException>();
        thrown.Which.AggregatedFailures.Single().Message.Should().Contain("UserInfoClaims");
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("   ")]
    public async Task GetScopesAsync_fails_with_scopes_claims_blank_when_a_claim_has_no_name(string? claim)
    {
        var catalog = Catalog(StandardScopes.OpenId, new ScopeDefinition { Name = "custom", IdTokenClaims = [claim!] });

        (await CodesFrom(catalog)).Should().BeEquivalentTo(["scopes.claims.blank"]);
    }

    [Fact]
    public async Task GetScopesAsync_reports_a_scope_listing_several_unnamed_claims_once()
    {
        // One fix, one failure: repeating it per blank entry tells the operator nothing new.
        var catalog = Catalog(
            StandardScopes.OpenId,
            new ScopeDefinition { Name = "custom", IdTokenClaims = ["", " "], UserInfoClaims = [null!] });

        (await CodesFrom(catalog)).Should().BeEquivalentTo(["scopes.claims.blank"]);
    }

    [Theory]
    [InlineData("nonce")]
    [InlineData("Aud")]
    [InlineData("zkd:sid")]
    public async Task GetScopesAsync_fails_with_scopes_claims_reserved_for_a_protocol_claim(string claim)
    {
        var catalog = Catalog(StandardScopes.OpenId, new ScopeDefinition { Name = "custom", AccessTokenClaims = [claim] });

        (await CodesFrom(catalog)).Should().BeEquivalentTo(["scopes.claims.reserved"]);
    }

    [Fact]
    public async Task GetScopesAsync_accepts_sub_as_the_standard_openid_scope_writes_it()
    {
        var catalog = Catalog(StandardScopes.OpenId, new ScopeDefinition { Name = "custom", UserInfoClaims = ["sub", "tenant"] });

        var act = async () => await catalog.GetScopesAsync(TestContext.Current.CancellationToken);

        await act.Should().NotThrowAsync();
    }

    // ── Audience ──────────────────────────────────────────────────────────────────────────────

    [Theory]
    [InlineData("not-a-uri")]
    [InlineData("/relative/path")]
    [InlineData("https://api.example.com/#fragment")]
    public async Task GetScopesAsync_fails_with_scopes_audience_invalid_when_an_audience_is_not_a_resource_indicator(string audience)
    {
        var catalog = Catalog(StandardScopes.OpenId, new ScopeDefinition { Name = "api", Audience = audience });

        (await CodesFrom(catalog)).Should().BeEquivalentTo(["scopes.audience.invalid"]);
    }

    [Fact]
    public async Task GetScopesAsync_accepts_an_absolute_URI_without_a_fragment_as_an_audience()
    {
        var catalog = Catalog(StandardScopes.OpenId, new ScopeDefinition { Name = "api", Audience = "https://api.example.com/orders" });

        var act = async () => await catalog.GetScopesAsync(TestContext.Current.CancellationToken);

        await act.Should().NotThrowAsync();
    }

    // ── The openid scope ──────────────────────────────────────────────────────────────────────

    [Fact]
    public async Task GetScopesAsync_fails_with_scopes_openid_missing_when_the_openid_scope_is_absent()
    {
        var catalog = Catalog(StandardScopes.Profile);

        (await CodesFrom(catalog)).Should().BeEquivalentTo(["scopes.openid_missing"]);
    }

    [Fact]
    public async Task GetScopesAsync_fails_with_scopes_openid_missing_when_the_repository_serves_nothing()
    {
        var catalog = Catalog();

        (await CodesFrom(catalog)).Should().BeEquivalentTo(["scopes.openid_missing"]);
    }

    // ── Every breach at once ──────────────────────────────────────────────────────────────────

    [Fact]
    public async Task GetScopesAsync_reports_every_broken_rule_at_once_not_only_the_first()
    {
        // One restart per failure is what an operator must not be made to pay.
        var catalog = Catalog(
            new ScopeDefinition { Name = "api", Audience = "not-a-uri" },
            new ScopeDefinition { Name = "api", AccessTokenClaims = ["nonce"] },
            new ScopeDefinition { Name = " " });

        (await CodesFrom(catalog)).Should().BeEquivalentTo(
        [
            "scopes.name.blank",
            "scopes.name.duplicate",
            "scopes.claims.reserved",
            "scopes.audience.invalid",
            "scopes.openid_missing",
        ]);
    }

    private sealed class StubRepository(IReadOnlyCollection<ScopeDefinition> scopes) : IScopeRepository
    {
        public ValueTask<IReadOnlyCollection<ScopeDefinition>> GetScopesAsync(CancellationToken cancellationToken = default)
            => ValueTask.FromResult(scopes);
    }

    private sealed class MutableRepository(IReadOnlyCollection<ScopeDefinition> scopes) : IScopeRepository
    {
        public IReadOnlyCollection<ScopeDefinition> Scopes { get; set; } = scopes;

        public ValueTask<IReadOnlyCollection<ScopeDefinition>> GetScopesAsync(CancellationToken cancellationToken = default)
            => ValueTask.FromResult(Scopes);
    }

    private sealed class NullReturningRepository : IScopeRepository
    {
        public ValueTask<IReadOnlyCollection<ScopeDefinition>> GetScopesAsync(CancellationToken cancellationToken = default)
            => ValueTask.FromResult<IReadOnlyCollection<ScopeDefinition>>(null!);
    }

    private sealed class CapturingRepository : IScopeRepository
    {
        public CancellationToken ObservedToken { get; private set; }

        public ValueTask<IReadOnlyCollection<ScopeDefinition>> GetScopesAsync(CancellationToken cancellationToken = default)
        {
            ObservedToken = cancellationToken;
            return ValueTask.FromResult<IReadOnlyCollection<ScopeDefinition>>([StandardScopes.OpenId]);
        }
    }
}
