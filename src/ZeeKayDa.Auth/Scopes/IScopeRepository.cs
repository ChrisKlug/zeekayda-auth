namespace ZeeKayDa.Auth.Scopes;

/// <summary>
/// Provides scope definitions used by the authorization server.
/// </summary>
public interface IScopeRepository
{
    /// <summary>
    /// Asynchronously returns the scopes known to the authorization server.
    /// </summary>
    /// <param name="cancellationToken">
    /// A token used to cancel the operation. Implementations must honour this token.
    /// </param>
    /// <returns>
    /// A <see cref="ValueTask{TResult}"/> that yields the configured scope definitions.
    /// </returns>
    ValueTask<IReadOnlyCollection<ScopeDefinition>> GetScopesAsync(CancellationToken cancellationToken = default);
}
