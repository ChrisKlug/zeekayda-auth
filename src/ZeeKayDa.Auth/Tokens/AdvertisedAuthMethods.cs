namespace ZeeKayDa.Auth.Tokens;

/// <summary>
/// The one derivation of <c>token_endpoint_auth_methods_supported</c>: every method a registered
/// authenticator performs, plus <c>none</c>, narrowed by the operator's filter. Every consumer reads it.
/// </summary>
internal sealed class AdvertisedAuthMethods
{
    private readonly HashSet<string> _methods;

    /// <summary>Resolves what to advertise from what the server performs and the operator's filter.</summary>
    /// <param name="performable">The methods the authenticators declare; malformed entries are dropped and fail startup elsewhere.</param>
    /// <param name="filter"><see cref="TokenEndpointOptions.AdvertisedAuthMethods"/>; <see langword="null"/> advertises them all.</param>
    public AdvertisedAuthMethods(IEnumerable<string> performable, ICollection<string>? filter)
    {
        var all = new SortedSet<string>(performable.Where(TokenEndpointAuthMethodRules.IsWellFormed), StringComparer.Ordinal)
        {
            TokenEndpointAuthMethods.None,
        };

        // Read-only wrappers, not arrays: discovery hands Methods out, and a cast-back array could drift.
        Performable = all.ToList().AsReadOnly();
        Methods = (filter is null ? all : all.Where(method => filter.Contains(method, StringComparer.Ordinal)))
            .ToList().AsReadOnly();
        Unperformable = (filter ?? []).Where(method => !all.Contains(method)).Distinct(StringComparer.Ordinal)
            .ToList().AsReadOnly();
        _methods = new HashSet<string>(Methods, StringComparer.Ordinal);
    }

    /// <summary>Every method the server performs, <c>none</c> included, before the filter, in ordinal order.</summary>
    public IReadOnlyList<string> Performable { get; }

    /// <summary>The advertised methods, in ordinal order.</summary>
    public IReadOnlyList<string> Methods { get; }

    /// <summary>Filter entries no authenticator performs, so never advertised whatever the filter says.</summary>
    public IReadOnlyList<string> Unperformable { get; }

    /// <summary>Whether <paramref name="method"/> is advertised, compared ordinally.</summary>
    public bool Contains(string method) => _methods.Contains(method);
}
