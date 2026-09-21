namespace ZeeKayDa.Auth.Scopes;

/// <summary>
/// Resolves scope names against the repository's definitions, and derives the one audience a
/// set of granted scopes names.
/// </summary>
internal static class ScopeResolution
{
    /// <summary>
    /// The definition of every name in <paramref name="names"/>, in that order, compared
    /// ordinally. Fails on the first name with no definition, which has no audience to correlate
    /// to and no claims to unlock.
    /// </summary>
    public static bool TryResolve(
        IReadOnlyCollection<ScopeDefinition> definitions,
        IReadOnlyList<string> names,
        out IReadOnlyList<ScopeDefinition> resolved,
        out string? undefined)
    {
        ArgumentNullException.ThrowIfNull(definitions);
        ArgumentNullException.ThrowIfNull(names);

        var byName = new Dictionary<string, ScopeDefinition>(StringComparer.Ordinal);
        foreach (var definition in definitions)
            byName.TryAdd(definition.Name, definition);

        var found = new List<ScopeDefinition>(names.Count);
        foreach (var name in names)
        {
            if (!byName.TryGetValue(name, out var definition))
            {
                resolved = [];
                undefined = name;
                return false;
            }

            found.Add(definition);
        }

        resolved = found;
        undefined = null;
        return true;
    }

    /// <summary>
    /// The resource server the granted scopes are for: the one distinct <see cref="ScopeDefinition.Audience"/>
    /// among them, compared ordinally (RFC 7519 §4.1.3), or <see langword="null"/> when none has one.
    /// Fails when two distinct values are present, since without a <c>resource</c> parameter
    /// there is nothing to choose between them (RFC 9068 §3). Whether the one value is a
    /// resource indicator is the caller's separate question, since the two answers are refused
    /// differently: an ambiguous request is the client's, a malformed audience the operator's.
    /// </summary>
    public static bool TryResolveAudience(IEnumerable<ScopeDefinition> granted, out string? audience)
    {
        ArgumentNullException.ThrowIfNull(granted);

        var audiences = granted
            .Select(scope => scope.Audience)
            .OfType<string>()
            .Distinct(StringComparer.Ordinal)
            .ToList();

        audience = audiences.Count == 1 ? audiences[0] : null;
        return audiences.Count <= 1;
    }
}
