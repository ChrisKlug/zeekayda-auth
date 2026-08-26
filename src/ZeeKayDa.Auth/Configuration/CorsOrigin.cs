namespace ZeeKayDa.Auth.Configuration;

/// <summary>
/// The rules for a CORS allowlist origin, shared by every allowlist option
/// (<see cref="Discovery.DiscoveryOptions.CorsOrigins"/>,
/// <see cref="Discovery.JwksEndpointOptions.CorsOrigins"/>): what makes an entry valid, and the
/// canonical <c>scheme://host[:port]</c> form a browser's <c>Origin</c> header will carry.
/// </summary>
internal static class CorsOrigin
{
    /// <summary>
    /// Returns the first problem that makes <paramref name="origin"/> unusable as a CORS
    /// allowlist entry, or <see langword="null"/> for a valid origin — at most one problem is
    /// reported per entry.
    /// </summary>
    /// <param name="origin">The allowlist entry to check.</param>
    /// <param name="allowInsecureIssuer">
    /// Whether HTTP loopback origins are permitted (local development only).
    /// </param>
    public static string? FindProblem(string? origin, bool allowInsecureIssuer)
    {
        if (origin is null)
            return "A null value is not a valid CORS origin.";
        if (origin.Length == 0)
            return "An empty string is not a valid CORS origin.";
        if (origin.IndexOfAny(['\r', '\n']) >= 0)
            return $"CORS origin '{origin}' must not contain CR or LF characters.";
        if (string.Equals(origin, "null", StringComparison.Ordinal))
            return "'null' is not a valid CORS origin.";
        if (origin.Contains('*'))
            return $"CORS origin '{origin}' must not contain wildcard characters.";
        if (!Uri.TryCreate(origin, UriKind.Absolute, out var originUri))
            return $"CORS origin '{origin}' is not a valid absolute URI.";

        return FindUriProblem(origin, originUri)
            ?? FindSchemeProblem(origin, originUri, allowInsecureIssuer);
    }

    /// <summary>
    /// Canonicalizes <paramref name="origin"/> to the exact form a browser's <c>Origin</c> header
    /// carries: lowercased, punycode (A-label) for an internationalized host, brackets preserved
    /// for an IPv6 literal, port only when non-default. Returns <see langword="false"/> for an
    /// entry that cannot be canonicalized, leaving it for <see cref="FindProblem"/> to name —
    /// scheme rules are deliberately not applied here, so validation stays the validator's job.
    /// </summary>
    /// <param name="origin">The allowlist entry to canonicalize.</param>
    /// <param name="canonical">The canonical form, when the return value is <see langword="true"/>.</param>
    public static bool TryCanonicalize(string? origin, out string canonical)
    {
        canonical = string.Empty;

        return origin is not null &&
            origin.IndexOfAny(['\r', '\n']) < 0 &&
            !origin.Contains('*') &&
            Uri.TryCreate(origin, UriKind.Absolute, out var uri) &&
            IsStructurallyValid(uri) &&
            TryBuildCanonicalForm(uri, out canonical);
    }

    private static string? FindUriProblem(string origin, Uri originUri)
    {
        if (originUri.UserInfo.Length > 0)
            return $"CORS origin '{origin}' must not contain user information.";
        if (originUri.Query.Length > 0)
            return $"CORS origin '{origin}' must not contain a query component.";
        if (originUri.Fragment.Length > 0)
            return $"CORS origin '{origin}' must not contain a fragment component.";

        // An origin is scheme + host + port only; path must be empty or just "/".
        if (originUri.AbsolutePath.Length > 1)
            return $"CORS origin '{origin}' must not contain a path component. Use 'scheme://host[:port]' only.";

        // A host that is not a valid IDN cannot be canonicalized to the punycode form a
        // browser's Origin header carries, so the entry could never match a request.
        // (IPv6 literals are exempt: IdnHost does not apply to them.)
        if (originUri.HostNameType != UriHostNameType.IPv6 && !HasValidIdnHost(originUri))
            return $"CORS origin '{origin}' does not contain a valid host name.";

        return null;
    }

    // CORS origins must use HTTPS in production. AllowInsecureIssuer permits HTTP only for
    // loopback addresses (local development). This mirrors the issuer scheme rules.
    private static string? FindSchemeProblem(string origin, Uri originUri, bool allowInsecureIssuer)
    {
        var isHttpsOrigin = string.Equals(originUri.Scheme, Uri.UriSchemeHttps, StringComparison.OrdinalIgnoreCase);
        var isHttpOrigin = string.Equals(originUri.Scheme, Uri.UriSchemeHttp, StringComparison.OrdinalIgnoreCase);

        if (!isHttpsOrigin && !(isHttpOrigin && allowInsecureIssuer))
        {
            return $"CORS origin '{origin}' uses scheme '{originUri.Scheme}'. " +
                "Only 'https' is permitted in production. Set AllowInsecureIssuer = true to " +
                "permit HTTP CORS origins for local development and testing only.";
        }

        if (isHttpOrigin && allowInsecureIssuer && !LoopbackHelper.IsLoopbackHost(originUri.Host))
        {
            return $"CORS origin '{origin}' uses HTTP for a non-loopback host. " +
                "AllowInsecureIssuer only permits HTTP loopback CORS origins for local development and testing.";
        }

        return null;
    }

    private static bool IsStructurallyValid(Uri uri)
        => uri.UserInfo.Length == 0 &&
            uri.Query.Length == 0 &&
            uri.Fragment.Length == 0 &&
            uri.AbsolutePath.Length <= 1;

    // IdnHost, not Host: browsers serialize the Origin header with the punycode (A-label) form of
    // an internationalized host. IPv6 literals keep Host, whose brackets IdnHost strips.
    private static bool TryBuildCanonicalForm(Uri uri, out string canonical)
    {
        try
        {
            var host = uri.HostNameType == UriHostNameType.IPv6 ? uri.Host : uri.IdnHost;
            var port = uri.IsDefaultPort ? string.Empty : $":{uri.Port}";
            canonical = $"{uri.Scheme}://{host}{port}".ToLowerInvariant();
            return true;
        }
        catch (UriFormatException)
        {
            canonical = string.Empty;
            return false;
        }
    }

    private static bool HasValidIdnHost(Uri uri)
    {
        try
        {
            _ = uri.IdnHost;
            return true;
        }
        catch (UriFormatException)
        {
            return false;
        }
    }
}
