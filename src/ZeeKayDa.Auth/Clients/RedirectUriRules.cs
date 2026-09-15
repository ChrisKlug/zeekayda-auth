using System.Linq;

namespace ZeeKayDa.Auth.Clients;

/// <summary>
/// Pure redirect URI security rules: side-effect-free predicates over a URI or its raw string.
/// Turning a broken rule into a configuration failure is <see cref="RedirectUriValidator"/>'s job.
/// </summary>
internal static class RedirectUriRules
{
    internal static bool HasFragment(Uri uri) => uri.Fragment.Length > 0;

    internal static bool HasUserInfo(Uri uri) => uri.UserInfo.Length > 0;

    internal static bool IsHttp(Uri uri)
        => string.Equals(uri.Scheme, "http", StringComparison.OrdinalIgnoreCase);

    /// <summary>
    /// Whether the string parses as an absolute <c>http</c> URI whose host is the name
    /// <c>localhost</c> — the shape of a native app's loopback redirect (RFC 8252 §7.3).
    /// A string that does not parse is not one.
    /// </summary>
    internal static bool IsHttpLocalhost(string uriString)
        => Uri.TryCreate(uriString, UriKind.Absolute, out var uri)
           && IsHttp(uri)
           && string.Equals(uri.Host, "localhost", StringComparison.OrdinalIgnoreCase);

    internal static bool HasPathTraversal(string uriString)
    {
        // The .NET Uri parser normalises '..' and '.' away so we must inspect the original string.
        // We split on '/' to avoid false positives (e.g. "..foo" is not a traversal segment).
        if (GetRawPath(uriString) is not { } pathPart)
            return false;

        // Truncate at the query or fragment before splitting, otherwise a trailing "?..." or "#..."
        // would be glued onto the final segment (e.g. "..?x=1") and slip past the segment match.
        var queryOrFragment = pathPart.IndexOfAny(['?', '#']);
        if (queryOrFragment >= 0)
            pathPart = pathPart[..queryOrFragment];

        // Percent-decode once (case-insensitively handles both %2E and %2e, and mixed forms
        // like ".%2e" or "%2e.") so encoded traversal segments are caught.
        return pathPart
            .Split('/')
            .Select(Uri.UnescapeDataString)
            .Any(decoded => decoded is "." or "..");
    }

    /// <summary>
    /// The raw, undecoded path of the string without its leading slash, or <see langword="null"/>
    /// when there is no path component to inspect.
    /// </summary>
    private static string? GetRawPath(string uriString)
    {
        var schemeEnd = uriString.IndexOf("://", StringComparison.Ordinal);
        if (schemeEnd >= 0)
        {
            // Standard form: scheme://authority/path?query — skip the authority and the leading slash.
            var afterScheme = uriString[(schemeEnd + 3)..];
            var slashAfterAuthority = afterScheme.IndexOf('/');
            return slashAfterAuthority < 0 ? null : afterScheme[(slashAfterAuthority + 1)..];
        }

        // Private-use single-slash form (RFC 8252 §7.1): scheme:/path — no authority to skip.
        var colonSlash = uriString.IndexOf(":/", StringComparison.Ordinal);
        return colonSlash < 0 ? null : uriString[(colonSlash + 2)..];
    }

    internal static bool IsSchemeAllowed(Uri uri)
    {
        if (string.Equals(uri.Scheme, "https", StringComparison.OrdinalIgnoreCase))
            return true;

        if (IsHttp(uri))
        {
            // HTTP is permitted only for loopback hosts. IPv6 zone IDs are rejected separately
            // and scheme-neutrally by RedirectUriValidator.
            return IsLoopbackHost(uri.Host);
        }

        // Private-use scheme: must contain a dot (RFC 8252 §7.1 reverse-domain convention)
        if (uri.Scheme.Contains('.'))
            return true;

        return false;
    }

    /// <summary>
    /// Detects IPv6 zone IDs in the authority portion of the raw URI string.
    /// .NET's <see cref="Uri"/> strips zone IDs at parse time, so we check the raw input.
    /// </summary>
    internal static bool HasIpv6ZoneId(string uriString)
    {
        // A zone ID appears as %25 (percent-encoded '%') or literally '%' inside '[...]'.
        // Find the authority: starts after "://" and ends at the next '/' or end.
        var schemeEnd = uriString.IndexOf("://", StringComparison.Ordinal);
        if (schemeEnd < 0) return false;

        var authorityStart = schemeEnd + 3;
        // The authority ends at the first '/', '?' or '#'. Stopping at '?'/'#' too prevents a
        // percent-encoded '%' in the query (e.g. "?a=[b%25c]") being mistaken for a zone ID.
        var authorityEnd = uriString.IndexOfAny(['/', '?', '#'], authorityStart);
        var authority = authorityEnd < 0
            ? uriString[authorityStart..]
            : uriString[authorityStart..authorityEnd];

        // IPv6 literals are wrapped in '[' ... ']'. Check for '%' inside them.
        var bracketOpen = authority.IndexOf('[');
        var bracketClose = authority.IndexOf(']');

        if (bracketOpen < 0 || bracketClose <= bracketOpen)
            return false;

        var ipv6Part = authority[(bracketOpen + 1)..bracketClose];
        return ipv6Part.Contains('%');
    }

    internal static bool IsLoopbackHost(string host)
        => LoopbackHelper.IsLoopbackHost(host);
}
