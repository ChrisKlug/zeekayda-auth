using ZeeKayDa.Auth.Scopes;

namespace ZeeKayDa.Auth.Tests.Scopes;

public sealed class InMemoryScopeRepositoryTests
{
    [Fact]
    public void GetScopes_ReturnsConfiguredScopesAndClaims()
    {
        var repository = new InMemoryScopeRepository(
        [
            new ScopeDefinition
            {
                Name = ScopeNames.OpenId,
                IdTokenClaims = ["sub"],
                AccessTokenClaims = ["scope"],
            },
            new ScopeDefinition
            {
                Name = ScopeNames.Profile,
                IdTokenClaims = ["name", "family_name"],
                AccessTokenClaims = ["name"],
            },
        ]);

        var scopes = repository.GetScopes();

        scopes.Select(scope => scope.Name).Should().Equal(ScopeNames.OpenId, ScopeNames.Profile);
        scopes.Single(scope => scope.Name == ScopeNames.Profile).IdTokenClaims.Should().Equal("name", "family_name");
        scopes.Single(scope => scope.Name == ScopeNames.Profile).AccessTokenClaims.Should().Equal("name");
    }

    [Fact]
    public void GetScopes_PreservesDiscoverabilityFlag()
    {
        var repository = new InMemoryScopeRepository(
        [
            new ScopeDefinition
            {
                Name = "internal.admin",
                IsDiscoverable = false,
            },
        ]);

        repository.GetScopes().Single().IsDiscoverable.Should().BeFalse();
    }

    [Fact]
    public void Constructor_DuplicateScopeNames_Throws()
    {
        var act = () => new InMemoryScopeRepository(
        [
            new ScopeDefinition { Name = ScopeNames.OpenId },
            new ScopeDefinition { Name = ScopeNames.OpenId },
        ]);

        act.Should().Throw<ArgumentException>()
            .WithMessage("*Duplicate scope name*");
    }

    [Fact]
    public void Constructor_WhitespaceIdTokenClaimName_Throws()
    {
        var act = () => new InMemoryScopeRepository(
        [
            new ScopeDefinition { Name = ScopeNames.Profile, IdTokenClaims = ["name", " "] },
        ]);

        act.Should().Throw<ArgumentException>()
            .WithMessage("*whitespace ID token claim name*");
    }

    [Fact]
    public void Constructor_WhitespaceAccessTokenClaimName_Throws()
    {
        var act = () => new InMemoryScopeRepository(
        [
            new ScopeDefinition { Name = ScopeNames.Profile, AccessTokenClaims = ["scope", " "] },
        ]);

        act.Should().Throw<ArgumentException>()
            .WithMessage("*whitespace access token claim name*");
    }
}
