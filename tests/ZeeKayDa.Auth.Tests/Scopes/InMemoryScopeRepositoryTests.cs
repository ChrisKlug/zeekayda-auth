#pragma warning disable ZKD001 // Tests exercise the experimental IdTokenClaims / AccessTokenClaims API by design.
using ZeeKayDa.Auth.Scopes;

namespace ZeeKayDa.Auth.Tests.Scopes;

public sealed class InMemoryScopeRepositoryTests
{
    [Fact]
    public void Constructor_throws_ArgumentNullException_when_scopes_is_null()
    {
        var act = () => new InMemoryScopeRepository(null!);

        act.Should().Throw<ArgumentNullException>().WithParameterName("scopes");
    }

    [Fact]
    public void Constructor_throws_when_scopes_collection_contains_null_element()
    {
        var act = () => new InMemoryScopeRepository([null!]);

        act.Should().Throw<ArgumentNullException>();
    }

    [Theory]
    [InlineData("")]
    [InlineData("   ")]
    public void Constructor_throws_ArgumentException_when_scope_name_is_blank(string name)
    {
        var act = () => new InMemoryScopeRepository([new ScopeDefinition { Name = name }]);

        act.Should().Throw<ArgumentException>().WithMessage("*whitespace*");
    }

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

    [Fact]
    public void Constructor_throws_when_scope_names_are_duplicated()
    {
        var act = () => new InMemoryScopeRepository(
        [
            new ScopeDefinition { Name = StandardScopes.OpenId.Name },
            new ScopeDefinition { Name = StandardScopes.OpenId.Name },
        ]);

        act.Should().Throw<ArgumentException>()
            .WithMessage("*Duplicate scope name*");
    }

    [Fact]
    public void Constructor_throws_when_IdTokenClaim_name_is_whitespace()
    {
        var act = () => new InMemoryScopeRepository(
        [
            new ScopeDefinition { Name = StandardScopes.Profile.Name, IdTokenClaims = ["name", " "] },
        ]);

        act.Should().Throw<ArgumentException>()
            .WithMessage("*whitespace ID token claim name*");
    }

    [Fact]
    public void Constructor_throws_when_AccessTokenClaim_name_is_whitespace()
    {
        var act = () => new InMemoryScopeRepository(
        [
            new ScopeDefinition { Name = StandardScopes.Profile.Name, AccessTokenClaims = ["scope", " "] },
        ]);

        act.Should().Throw<ArgumentException>()
            .WithMessage("*whitespace access token claim name*");
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
