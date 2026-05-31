namespace ZeeKayDa.Auth.Scopes;

/// <summary>
/// Provides scope definitions used by the authorization server.
/// </summary>
public interface IScopeRepository
{
    /// <summary>
    /// Returns the scopes known to the authorization server.
    /// </summary>
    /// <returns>The configured scope definitions.</returns>
    IReadOnlyCollection<ScopeDefinition> GetScopes();
}
