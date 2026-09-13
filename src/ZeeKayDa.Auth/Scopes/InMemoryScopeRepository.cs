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
    /// <exception cref="ArgumentException">
    /// Thrown when a scope name is blank, duplicated, or contains blank claim names.
    /// </exception>
    public InMemoryScopeRepository(IEnumerable<ScopeDefinition> scopes)
    {
        ArgumentNullException.ThrowIfNull(scopes);

        var materializedScopes = new List<ScopeDefinition>();
        var seenNames = new HashSet<string>(StringComparer.Ordinal);

        foreach (var scope in scopes)
        {
            ArgumentNullException.ThrowIfNull(scope);

            if (string.IsNullOrWhiteSpace(scope.Name))
            {
                throw new ArgumentException("Scope names must not be null, empty, or whitespace.", nameof(scopes));
            }

            if (!seenNames.Add(scope.Name))
            {
                throw new ArgumentException(
                    $"Duplicate scope name '{scope.Name}' is not allowed.",
                    nameof(scopes));
            }

            RequireClaimNames(scope, scope.IdTokenClaims, "ID token");
            RequireClaimNames(scope, scope.UserInfoClaims, "userinfo");
            RequireClaimNames(scope, scope.AccessTokenClaims, "access token");

            materializedScopes.Add(new ScopeDefinition
            {
                Name = scope.Name,
                IsDiscoverable = scope.IsDiscoverable,
                IdTokenClaims = [.. scope.IdTokenClaims],
                UserInfoClaims = [.. scope.UserInfoClaims],
                AccessTokenClaims = [.. scope.AccessTokenClaims],
                Audience = scope.Audience,
            });
        }

        _scopes = materializedScopes.AsReadOnly();
    }

    /// <inheritdoc />
    public ValueTask<IReadOnlyCollection<ScopeDefinition>> GetScopesAsync(CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();

        return ValueTask.FromResult(_scopes);
    }

    private static void RequireClaimNames(ScopeDefinition scope, IReadOnlyCollection<string> claims, string destination)
    {
        if (claims is null || claims.Any(string.IsNullOrWhiteSpace))
        {
            throw new ArgumentException(
                $"Scope '{scope.Name}' contains a null, empty, or whitespace {destination} claim name.",
                "scopes");
        }
    }
}
