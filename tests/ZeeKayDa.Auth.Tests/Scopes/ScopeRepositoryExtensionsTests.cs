using ZeeKayDa.Auth.Scopes;

namespace ZeeKayDa.Auth.Tests.Scopes;

public sealed class ScopeRepositoryExtensionsTests
{
    [Fact]
    public async Task AddDefaultScopes_AddsMissingStandardScopes()
    {
        var repository = new InMemoryScopeRepository(
        [
            new ScopeDefinition
            {
                Name = "api.read",
                AccessTokenClaims = ["scope"],
            },
        ]);

        var scopes = await repository.AddDefaultScopes().GetScopesAsync(TestContext.Current.CancellationToken);

        scopes.Select(scope => scope.Name).Should().Equal(
            "api.read",
            StandardScopes.OpenId.Name,
            StandardScopes.Profile.Name,
            StandardScopes.Email.Name,
            StandardScopes.Phone.Name,
            StandardScopes.Address.Name);
    }

    [Fact]
    public async Task AddDefaultScopes_IsIdempotent()
    {
        var repository = new InMemoryScopeRepository(
        [
            StandardScopes.OpenId,
            StandardScopes.Profile,
        ]);

        var scopes = await repository
            .AddDefaultScopes()
            .AddDefaultScopes()
            .GetScopesAsync(TestContext.Current.CancellationToken);

        scopes.Select(scope => scope.Name).Should().OnlyHaveUniqueItems();
        scopes.Should().HaveCount(5);
    }
}
