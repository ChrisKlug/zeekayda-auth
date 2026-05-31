namespace ZeeKayDa.Auth.Scopes;

internal sealed class DefaultScopeRepository : IScopeRepository
{
    private static readonly IReadOnlyCollection<ScopeDefinition> DefaultScopes =
    [
        new ScopeDefinition { Name = ScopeNames.OpenId },
        new ScopeDefinition { Name = ScopeNames.Profile },
    ];

    public ValueTask<IReadOnlyCollection<ScopeDefinition>> GetScopesAsync(CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();

        return ValueTask.FromResult(DefaultScopes);
    }
}
