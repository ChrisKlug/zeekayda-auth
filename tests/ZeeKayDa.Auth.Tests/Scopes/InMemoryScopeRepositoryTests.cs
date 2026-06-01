using ZeeKayDa.Auth.Scopes;

namespace ZeeKayDa.Auth.Tests.Scopes;

public sealed class InMemoryScopeRepositoryTests
{
    [Fact]
    public void Constructor_NullScopes_ThrowsArgumentNullException()
    {
        var act = () => new InMemoryScopeRepository(null!);

        act.Should().Throw<ArgumentNullException>().WithParameterName("scopes");
    }

    [Fact]
    public void Constructor_NullScopeElement_Throws()
    {
        var act = () => new InMemoryScopeRepository([null!]);

        act.Should().Throw<ArgumentNullException>();
    }

    [Theory]
    [InlineData("")]
    [InlineData("   ")]
    public void Constructor_BlankScopeName_ThrowsArgumentException(string name)
    {
        var act = () => new InMemoryScopeRepository([new ScopeDefinition { Name = name }]);

        act.Should().Throw<ArgumentException>().WithMessage("*whitespace*");
    }

    [Fact]
    public async Task GetScopes_ReturnsConfiguredScopesAndClaims()
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
    public async Task GetScopes_PreservesDiscoverabilityFlag()
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
    public void Constructor_DuplicateScopeNames_Throws()
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
    public void Constructor_WhitespaceIdTokenClaimName_Throws()
    {
        var act = () => new InMemoryScopeRepository(
        [
            new ScopeDefinition { Name = StandardScopes.Profile.Name, IdTokenClaims = ["name", " "] },
        ]);

        act.Should().Throw<ArgumentException>()
            .WithMessage("*whitespace ID token claim name*");
    }

    [Fact]
    public void Constructor_WhitespaceAccessTokenClaimName_Throws()
    {
        var act = () => new InMemoryScopeRepository(
        [
            new ScopeDefinition { Name = StandardScopes.Profile.Name, AccessTokenClaims = ["scope", " "] },
        ]);

        act.Should().Throw<ArgumentException>()
            .WithMessage("*whitespace access token claim name*");
    }
}
