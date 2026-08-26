namespace ZeeKayDa.Auth.Configuration;

/// <summary>
/// One CORS allowlist entry, checked against the rules every allowlist option
/// (<see cref="Discovery.DiscoveryOptions.CorsOrigins"/>,
/// <see cref="Discovery.JwksEndpointOptions.CorsOrigins"/>) shares. Construction runs every rule
/// once; the properties expose the outcome.
/// </summary>
internal sealed class CorsOrigin
{
    private readonly string? _origin;
    private readonly bool _allowInsecureIssuer;
    private readonly Uri? _uri;

    public CorsOrigin(string? origin, bool allowInsecureIssuer)
    {
        _origin = origin;
        _allowInsecureIssuer = allowInsecureIssuer;
        _uri = origin is not null && Uri.TryCreate(origin, UriKind.Absolute, out var parsed)
            ? parsed
            : null;

        // The rules in evaluation order; the first that finds a problem wins, so at most one
        // problem is reported per entry. Scheme rules run only for the error message — an entry
        // is canonicalizable on the structural rules alone, which is what lets canonicalization
        // stay ignorant of AllowInsecureIssuer while validation enforces it.
        var structuralProblem =
            HasNullOrigin() ??
            HasEmptyOrigin() ??
            HasCrOrLfCharacters() ??
            HasNullLiteral() ??
            HasWildcardCharacters() ??
            HasNoAbsoluteUri() ??
            HasUserInfo() ??
            HasQueryComponent() ??
            HasFragmentComponent() ??
            HasPathComponent() ??
            HasInvalidIdnHost();

        ErrorMessage = structuralProblem ?? HasForbiddenScheme() ?? HasHttpNonLoopbackHost();
        Canonical = structuralProblem is null ? BuildCanonicalForm() : null;
    }

    private string? HasNullOrigin()
        => _origin is null ? "A null value is not a valid CORS origin." : null;

    private string? HasEmptyOrigin()
        => _origin!.Length == 0 ? "An empty string is not a valid CORS origin." : null;

    private string? HasCrOrLfCharacters()
        => _origin!.IndexOfAny(['\r', '\n']) >= 0
            ? $"CORS origin '{_origin}' must not contain CR or LF characters."
            : null;

    private string? HasNullLiteral()
        => string.Equals(_origin, "null", StringComparison.Ordinal)
            ? "'null' is not a valid CORS origin."
            : null;

    private string? HasWildcardCharacters()
        => _origin!.Contains('*')
            ? $"CORS origin '{_origin}' must not contain wildcard characters."
            : null;

    private string? HasNoAbsoluteUri()
        => _uri is null ? $"CORS origin '{_origin}' is not a valid absolute URI." : null;

    private string? HasUserInfo()
        => _uri!.UserInfo.Length > 0
            ? $"CORS origin '{_origin}' must not contain user information."
            : null;

    private string? HasQueryComponent()
        => _uri!.Query.Length > 0
            ? $"CORS origin '{_origin}' must not contain a query component."
            : null;

    private string? HasFragmentComponent()
        => _uri!.Fragment.Length > 0
            ? $"CORS origin '{_origin}' must not contain a fragment component."
            : null;

    // An origin is scheme + host + port only; path must be empty or just "/".
    private string? HasPathComponent()
        => _uri!.AbsolutePath.Length > 1
            ? $"CORS origin '{_origin}' must not contain a path component. Use 'scheme://host[:port]' only."
            : null;

    // A host that is not a valid IDN cannot be canonicalized to the punycode form a browser's
    // Origin header carries, so the entry could never match a request. (IPv6 literals are exempt:
    // IdnHost does not apply to them.)
    private string? HasInvalidIdnHost()
    {
        if (_uri!.HostNameType == UriHostNameType.IPv6)
            return null;

        try
        {
            _ = _uri.IdnHost;
            return null;
        }
        catch (UriFormatException)
        {
            return $"CORS origin '{_origin}' does not contain a valid host name.";
        }
    }

    // CORS origins must use HTTPS in production. AllowInsecureIssuer permits HTTP only for
    // loopback addresses (local development). This mirrors the issuer scheme rules.
    private string? HasForbiddenScheme()
    {
        if (IsHttps || (IsHttp && _allowInsecureIssuer))
            return null;

        return $"CORS origin '{_origin}' uses scheme '{_uri!.Scheme}'. " +
            "Only 'https' is permitted in production. Set AllowInsecureIssuer = true to " +
            "permit HTTP CORS origins for local development and testing only.";
    }

    // Only reached when HasForbiddenScheme passed, so an HTTP scheme here implies
    // AllowInsecureIssuer is set — what remains to check is the loopback restriction.
    private string? HasHttpNonLoopbackHost()
        => IsHttp && !LoopbackHelper.IsLoopbackHost(_uri!.Host)
            ? $"CORS origin '{_origin}' uses HTTP for a non-loopback host. " +
                "AllowInsecureIssuer only permits HTTP loopback CORS origins for local development and testing."
            : null;

    // IdnHost, not Host: browsers serialize the Origin header with the punycode (A-label) form of
    // an internationalized host. IPv6 literals keep Host, whose brackets IdnHost strips.
    private string BuildCanonicalForm()
    {
        var host = _uri!.HostNameType == UriHostNameType.IPv6 ? _uri.Host : _uri.IdnHost;
        var port = _uri.IsDefaultPort ? string.Empty : $":{_uri.Port}";
        return $"{_uri.Scheme}://{host}{port}".ToLowerInvariant();
    }

    /// <summary>
    /// Gets the first problem that makes this entry unusable as a CORS allowlist origin, or
    /// <see langword="null"/> for a valid one.
    /// </summary>
    public string? ErrorMessage { get; }

    /// <summary>Gets a value indicating whether <see cref="ErrorMessage"/> found a problem.</summary>
    public bool HasProblem => ErrorMessage is not null;

    /// <summary>
    /// Gets the canonical <c>scheme://host[:port]</c> form a browser's <c>Origin</c> header will
    /// carry — lowercased, punycode (A-label) for an internationalized host, brackets preserved
    /// for an IPv6 literal, port only when non-default — or <see langword="null"/> when the entry
    /// is not structurally valid and should be left as-is for validation to name.
    /// </summary>
    public string? Canonical { get; }

    private bool IsHttps
        => string.Equals(_uri!.Scheme, Uri.UriSchemeHttps, StringComparison.OrdinalIgnoreCase);

    private bool IsHttp
        => string.Equals(_uri!.Scheme, Uri.UriSchemeHttp, StringComparison.OrdinalIgnoreCase);
}
