namespace ZeeKayDa.Auth.Tokens;

/// <summary>
/// The single derivation of what <c>token_endpoint_auth_methods_supported</c> advertises: every
/// method a registered client authenticator performs, plus <c>none</c>, narrowed by the operator's
/// optional filter.
/// </summary>
/// <remarks>
/// Every consumer — the discovery document, the client registration subset check, the token
/// endpoint's per-request check, and the startup checks on the result — reads this one instance, so
/// no caller can derive a different answer from the same inputs. <c>none</c> is always performable
/// because the framework handles it itself; a client that may use it is still only ever a public
/// client, held to PKCE S256 on the code grant.
/// </remarks>
internal sealed class AdvertisedAuthMethods
{
    private readonly HashSet<string> _methods;

    /// <param name="performable">
    /// The methods the registered authenticators declare; <c>none</c> is added here, never by them.
    /// </param>
    /// <param name="filter">
    /// <see cref="TokenEndpointOptions.AdvertisedAuthMethods"/>; <see langword="null"/> advertises
    /// every performable method.
    /// </param>
    public AdvertisedAuthMethods(IEnumerable<string> performable, ICollection<string>? filter)
    {
        var all = new SortedSet<string>(performable, StringComparer.Ordinal) { TokenEndpointAuthMethods.None };

        Methods = [.. filter is null ? all : all.Where(method => filter.Contains(method, StringComparer.Ordinal))];
        Unperformable = filter is null
            ? []
            : [.. filter.Where(method => !all.Contains(method)).Distinct(StringComparer.Ordinal)];
        _methods = new HashSet<string>(Methods, StringComparer.Ordinal);
    }

    /// <summary>The advertised methods, in ordinal order.</summary>
    public IReadOnlyList<string> Methods { get; }

    /// <summary>Filter entries no authenticator performs, so never advertised whatever the filter says.</summary>
    public IReadOnlyList<string> Unperformable { get; }

    /// <summary>Whether <paramref name="method"/> is advertised, compared ordinally.</summary>
    public bool Contains(string method) => _methods.Contains(method);
}
