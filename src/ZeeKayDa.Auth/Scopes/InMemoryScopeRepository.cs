namespace ZeeKayDa.Auth.Scopes;

/// <summary>
/// An in-memory <see cref="IScopeRepository"/> implementation.
/// </summary>
public sealed class InMemoryScopeRepository : IScopeRepository
{
    private readonly IReadOnlyCollection<ScopeDefinition> _scopes;

    /// <summary>
    /// Initialises a new <see cref="InMemoryScopeRepository"/> instance.
    /// </summary>
    /// <param name="scopes">The scopes to expose from this repository.</param>
    /// <exception cref="ArgumentNullException">
    /// Thrown when <paramref name="scopes"/> is <see langword="null"/>.
    /// </exception>
    /// <remarks>
    /// Copied but not judged: every scope rule belongs to the catalog that holds every repository to the same
    /// rules, so a mistake surfaces at startup with every problem at once. The list is materialised and wrapped
    /// read-only.
    /// </remarks>
    public InMemoryScopeRepository(IEnumerable<ScopeDefinition> scopes)
    {
        ArgumentNullException.ThrowIfNull(scopes);

        _scopes = scopes.ToList().AsReadOnly();
    }

    /// <inheritdoc />
    public Task<IReadOnlyCollection<ScopeDefinition>> GetScopesAsync(CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();

        return Task.FromResult(_scopes);
    }
}
