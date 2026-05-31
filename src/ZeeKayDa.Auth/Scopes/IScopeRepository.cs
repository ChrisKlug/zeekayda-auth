namespace ZeeKayDa.Auth.Scopes;

/// <summary>
/// Provides scope definitions used by the authorization server.
/// </summary>
public interface IScopeRepository
{
    /// <summary>
    /// Returns the scopes known to the authorization server.
    /// </summary>
    /// <param name="cancellationToken">A token that can be used to cancel the operation.</param>
    /// <returns>The configured scope definitions.</returns>
    ValueTask<IReadOnlyCollection<ScopeDefinition>> GetScopesAsync(CancellationToken cancellationToken = default);
}
