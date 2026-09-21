using ZeeKayDa.Auth.Scopes;

namespace ZeeKayDa.Auth.Tests.Scopes;

public sealed class InMemoryScopeRepositoryTests
{
    [Fact]
    public async Task GetScopes_returns_configured_scopes_and_claims()
    {
        var repository = new InMemoryScopeRepository(
        [
            new ScopeDefinition
            {
                Name = StandardScopes.OpenId.Name,
                IdTokenClaims = ["sub"],
                AccessTokenClaims = ["scope"],
            },
            new ScopeDefinition
            {
                Name = StandardScopes.Profile.Name,
                IdTokenClaims = ["name", "family_name"],
                AccessTokenClaims = ["name"],
            },
        ]);

        var scopes = await repository.GetScopesAsync(TestContext.Current.CancellationToken);

        scopes.Select(scope => scope.Name).Should().Equal(StandardScopes.OpenId.Name, StandardScopes.Profile.Name);
        scopes.Single(scope => scope.Name == StandardScopes.Profile.Name).IdTokenClaims.Should().Equal("name", "family_name");
        scopes.Single(scope => scope.Name == StandardScopes.Profile.Name).AccessTokenClaims.Should().Equal("name");
    }

    [Fact]
    public async Task GetScopes_preserves_IsDiscoverable_flag()
    {
        var repository = new InMemoryScopeRepository(
        [
            new ScopeDefinition
            {
                Name = "internal.admin",
                IsDiscoverable = false,
            },
        ]);

        var scopes = await repository.GetScopesAsync(TestContext.Current.CancellationToken);

        scopes.Single().IsDiscoverable.Should().BeFalse();
    }

    [Theory]
    [MemberData(nameof(ShapesTheCatalogRefuses))]
    public async Task The_constructor_judges_nothing_leaving_every_rule_to_the_catalog(ScopeDefinition scope)
    {
        // This type used to enforce a subset of the scope rules itself, throwing ArgumentException
        // on the first problem with no code an operator could search for, and never checking
        // openid at all. ValidatedScopeCatalog is the single authority now, and holds an in-memory
        // host to exactly the rules a custom repository is held to.
        var act = () => new InMemoryScopeRepository([scope]);

        act.Should().NotThrow();

        var repository = new InMemoryScopeRepository([scope]);
        (await repository.GetScopesAsync(TestContext.Current.CancellationToken)).Should().ContainSingle();
    }

    public static TheoryData<ScopeDefinition> ShapesTheCatalogRefuses() =>
    [
        new ScopeDefinition { Name = "  " },
        new ScopeDefinition { Name = StandardScopes.Profile.Name, IdTokenClaims = ["name", " "] },
        new ScopeDefinition { Name = StandardScopes.Profile.Name, AccessTokenClaims = ["role", " "] },
        new ScopeDefinition { Name = StandardScopes.Profile.Name, UserInfoClaims = ["name", " "] },
        new ScopeDefinition { Name = "api", Audience = "not-a-uri" },
    ];

    [Fact]
    public void The_constructor_still_refuses_a_null_collection()
    {
        // Its own argument, not the repository's output: nothing downstream can report this.
        var act = () => new InMemoryScopeRepository(null!);

        act.Should().Throw<ArgumentNullException>();
    }

    [Fact]
    public async Task GetScopes_is_unaffected_by_a_list_the_caller_edits_after_construction()
    {
        var scopes = new List<ScopeDefinition> { StandardScopes.OpenId };
        var repository = new InMemoryScopeRepository(scopes);

        scopes.Add(StandardScopes.Profile);

        (await repository.GetScopesAsync(TestContext.Current.CancellationToken)).Should().ContainSingle();
    }

    [Fact]
    public async Task GetScopes_preserves_UserInfoClaims_and_Audience()
    {
        var repository = new InMemoryScopeRepository(
        [
            new ScopeDefinition
            {
                Name = "orders.read",
                Audience = "https://orders.example.com/",
                UserInfoClaims = ["customer_number"],
            },
        ]);

        var scope = (await repository.GetScopesAsync(TestContext.Current.CancellationToken)).Single();

        scope.Audience.Should().Be("https://orders.example.com/");
        scope.UserInfoClaims.Should().Equal("customer_number");
    }

    [Fact]
    public async Task GetScopesAsync_throws_when_token_is_already_cancelled()
    {
        var repository = new InMemoryScopeRepository(
        [
            new ScopeDefinition { Name = StandardScopes.OpenId.Name },
        ]);

        using var cts = new CancellationTokenSource();
        await cts.CancelAsync();

        var act = async () => await repository.GetScopesAsync(cts.Token);

        await act.Should().ThrowAsync<OperationCanceledException>();
    }
}
