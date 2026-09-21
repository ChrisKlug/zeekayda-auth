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
    /// <para>
    /// <strong>The scopes are copied but not judged here.</strong> Every rule a scope must keep —
    /// a name, no duplicate name, claim lists that exist and are named, an audience that is a
    /// resource indicator, the presence of <c>openid</c> — belongs to
    /// <c>ValidatedScopeCatalog</c>, which is the one path from any
    /// <see cref="IScopeRepository"/> to a definition and holds a custom repository to exactly the
    /// same rules. Enforcing a subset of them a second time here made this type a second
    /// authority that disagreed with the first in three ways: it reported through
    /// <see cref="ArgumentException"/> rather than a named
    /// <see cref="ZeeKayDaConfigurationFailure"/> an operator can search for, it threw on the
    /// first problem rather than reporting every one at once, and it never checked
    /// <c>openid</c> at all.
    /// </para>
    /// <para>
    /// The cost is that a mistake surfaces at startup rather than at the
    /// <c>AddInMemoryScopes</c> call. That is the better trade: the operator gets every problem
    /// in one pass, under the codes the documentation lists, and an in-memory host and a
    /// database-backed one fail the same way.
    /// </para>
    /// <para>
    /// The enumerable is materialised so that a lazy sequence is not re-run on every read. The
    /// definitions themselves are not deep-copied: <c>ValidatedScopeCatalog</c> copies each one,
    /// claim lists included, on every read, so what the protocol sees is already insulated from a
    /// caller that edits a list it passed in.
    /// </para>
    /// </remarks>
    public InMemoryScopeRepository(IEnumerable<ScopeDefinition> scopes)
    {
        ArgumentNullException.ThrowIfNull(scopes);

        _scopes = [.. scopes];
    }

    /// <inheritdoc />
    public ValueTask<IReadOnlyCollection<ScopeDefinition>> GetScopesAsync(CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();

        return ValueTask.FromResult(_scopes);
    }
}
