namespace ZeeKayDa.Auth.Scopes;

internal sealed class DefaultScopeRepository : IScopeRepository
{
    private static readonly IReadOnlyCollection<ScopeDefinition> DefaultScopes =
    [
        new ScopeDefinition { Name = ScopeNames.OpenId },
        new ScopeDefinition { Name = ScopeNames.Profile },
    ];

    public IReadOnlyCollection<ScopeDefinition> GetScopes() => DefaultScopes;
}
