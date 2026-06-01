namespace ZeeKayDa.Auth.Scopes;

/// <summary>
/// Extension methods for working with <see cref="IScopeRepository"/>.
/// </summary>
public static class ScopeRepositoryExtensions
{
    /// <summary>
    /// Wraps the repository so it always includes the standard OpenID Connect scopes.
    /// </summary>
    /// <param name="repository">The source repository.</param>
    /// <returns>A repository view that includes the standard scopes.</returns>
    /// <exception cref="ArgumentNullException">Thrown when <paramref name="repository"/> is <see langword="null"/>.</exception>
    public static IScopeRepository AddDefaultScopes(this IScopeRepository repository)
    {
        ArgumentNullException.ThrowIfNull(repository);

        return repository is DefaultScopesRepository ? repository : new DefaultScopesRepository(repository);
    }

    private sealed class DefaultScopesRepository(IScopeRepository innerRepository) : IScopeRepository
    {
        public async ValueTask<IReadOnlyCollection<ScopeDefinition>> GetScopesAsync(CancellationToken cancellationToken = default)
        {
            var scopes = await innerRepository.GetScopesAsync(cancellationToken);
            var result = new List<ScopeDefinition>(scopes.Count + StandardScopes.All.Count);
            var names = new HashSet<string>(StringComparer.Ordinal);

            foreach (var scope in scopes)
            {
                if (names.Add(scope.Name))
                {
                    result.Add(scope);
                }
            }

            foreach (var scope in StandardScopes.All)
            {
                if (names.Add(scope.Name))
                {
                    result.Add(scope);
                }
            }

            return result.AsReadOnly();
        }
    }
}
