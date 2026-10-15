namespace ZeeKayDa.Auth.Configuration;

/// <summary>One <see cref="AuthorizationServerOptions.CorsOrigins"/> entry, checked once on construction.</summary>
internal sealed class CorsOrigin
{
    // Canonicalization needs only these, so it can ignore AllowHttpLoopbackCorsOrigins.
    private static readonly Func<CorsOrigin, string?>[] StructuralRules =
    [
        origin => origin.HasNullOrigin(),
        origin => origin.HasEmptyOrigin(),
        origin => origin.HasCrOrLfCharacters(),
        origin => origin.HasNullLiteral(),
        origin => origin.HasWildcardCharacters(),
        origin => origin.HasNoAbsoluteUri(),
        origin => origin.HasUserInfo(),
        origin => origin.HasQueryComponent(),
        origin => origin.HasFragmentComponent(),
        origin => origin.HasPathComponent(),
        origin => origin.HasInvalidIdnHost(),
    ];

    private static readonly Func<CorsOrigin, string?>[] SchemeRules =
    [
        origin => origin.HasForbiddenScheme(),
        origin => origin.HasHttpNonLoopbackHost(),
    ];

    private readonly string? _origin;
    private readonly bool _allowHttpLoopback;
    private readonly Uri? _uri;

    public CorsOrigin(string? origin, bool allowHttpLoopback)
    {
        _origin = origin;
        _allowHttpLoopback = allowHttpLoopback;
        _uri = origin is not null && Uri.TryCreate(origin, UriKind.Absolute, out var parsed)
            ? parsed
            : null;

        var structuralProblem = FirstProblem(StructuralRules);
        ErrorMessage = structuralProblem ?? FirstProblem(SchemeRules);
        Canonical = structuralProblem is null ? BuildCanonicalForm() : null;
    }

    /// <summary>The canonical form of an entry startup validation has already accepted.</summary>
    /// <exception cref="InvalidOperationException">
    /// <paramref name="origin"/> has no canonical form, which only an unvalidated entry can lack.
    /// </exception>
    public static string Canonicalize(string? origin) =>
        // The flag feeds only the scheme rules, which canonicalization ignores.
        new CorsOrigin(origin, allowHttpLoopback: true).Canonical
            ?? throw new InvalidOperationException(
                "A CORS origin has no canonical form; startup validation did not run.");

    private string? FirstProblem(Func<CorsOrigin, string?>[] rules)
        => rules
            .Select(rule => rule(this))
            .FirstOrDefault(problem => problem is not null);

    private string? HasNullOrigin()
        => _origin is null ? "A null value is not a valid CORS origin." : null;

    private string? HasEmptyOrigin()
        => _origin!.Length == 0 ? "An empty string is not a valid CORS origin." : null;

    private string? HasCrOrLfCharacters()
        => _origin!.IndexOfAny(['\r', '\n']) >= 0
            ? "A CORS origin must not contain CR or LF characters."
            : null;

    private string? HasNullLiteral()
        => string.Equals(_origin, "null", StringComparison.Ordinal)
            ? "'null' is not a valid CORS origin."
            : null;

    private string? HasWildcardCharacters()
        => _origin!.Contains('*')
            ? "A CORS origin must not contain wildcard characters."
            : null;

    private string? HasNoAbsoluteUri()
        => _uri is null ? "A CORS origin must be a valid absolute URI." : null;

    private string? HasUserInfo()
        => _uri!.UserInfo.Length > 0
            ? $"CORS origin '{Shown}' must not contain user information."
            : null;

    private string? HasQueryComponent()
        => _uri!.Query.Length > 0
            ? $"CORS origin '{Shown}' must not contain a query component."
            : null;

    private string? HasFragmentComponent()
        => _uri!.Fragment.Length > 0
            ? $"CORS origin '{Shown}' must not contain a fragment component."
            : null;

    private string? HasPathComponent()
        => _uri!.AbsolutePath.Length > 1
            ? $"CORS origin '{Shown}' must not contain a path component. Use 'scheme://host[:port]' only."
            : null;

    // An invalid IDN has no punycode form, so it could never match a browser's Origin header.
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
            return "A CORS origin must contain a valid host name.";
        }
    }

    private string? HasForbiddenScheme()
    {
        if (IsHttps)
            return null;
        if (IsHttp && _allowHttpLoopback)
            return null;

        return $"CORS origin '{Shown}' uses scheme '{_uri!.Scheme}'. " +
            "Only 'https' is permitted in production. Set Development.AllowHttpLoopbackCorsOrigins = true to " +
            "permit HTTP loopback CORS origins for local development and testing only.";
    }

    // Runs after HasForbiddenScheme, so HTTP here means AllowHttpLoopbackCorsOrigins is set.
    private string? HasHttpNonLoopbackHost()
        => IsHttp && !LoopbackHelper.IsLoopbackHost(_uri!.Host)
            ? $"CORS origin '{Shown}' uses HTTP for a non-loopback host. " +
                "Development.AllowHttpLoopbackCorsOrigins only permits HTTP loopback CORS origins for local development and testing."
            : null;

    // Browsers send the punycode host; IPv6 literals keep Host, whose brackets IdnHost strips.
    private string BuildCanonicalForm()
    {
        var host = _uri!.HostNameType == UriHostNameType.IPv6 ? _uri.Host : _uri.IdnHost;
        var port = _uri.IsDefaultPort ? string.Empty : $":{_uri.Port}";
        return $"{_uri.Scheme}://{host}{port}".ToLowerInvariant();
    }

    /// <summary>Gets the first problem with this entry, or <see langword="null"/> for a valid one.</summary>
    public string? ErrorMessage { get; }

    /// <summary>Gets a value indicating whether <see cref="ErrorMessage"/> found a problem.</summary>
    public bool HasProblem => ErrorMessage is not null;

    /// <summary>
    /// Gets the lowercased <c>scheme://host[:port]</c> a browser's <c>Origin</c> header carries, or
    /// <see langword="null"/> for a structurally invalid entry.
    /// </summary>
    public string? Canonical { get; }

    // Only for rules after parsing: the raw value may hold a CR/LF pair.
    private string Shown => ConfiguredUri.Display(_origin!, _uri!);

    private bool IsHttps
        => string.Equals(_uri!.Scheme, Uri.UriSchemeHttps, StringComparison.OrdinalIgnoreCase);

    private bool IsHttp
        => string.Equals(_uri!.Scheme, Uri.UriSchemeHttp, StringComparison.OrdinalIgnoreCase);
}
