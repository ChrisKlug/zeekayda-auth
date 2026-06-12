using System.Linq;
using System.Net;

namespace ZeeKayDa.Auth.Clients;

/// <summary>
/// Pure URI predicate helpers used by <see cref="ClientRegistrationValidator"/> to evaluate
/// redirect URI security rules.
/// </summary>
internal static class RedirectUriValidator
{
    internal static bool HasPathTraversal(string uriString)
    {
        // The .NET Uri parser normalises '..' and '.' away so we must inspect the original string.
        // Find the path start (after the authority) and check each segment.
        // We split on '/' to avoid false positives (e.g. "..foo" is not a traversal segment).
        string pathPart;

        var schemeEnd = uriString.IndexOf("://", StringComparison.Ordinal);
        if (schemeEnd >= 0)
        {
            // Standard form: scheme://authority/path?query
            var afterScheme = uriString[(schemeEnd + 3)..];
            var slashAfterAuthority = afterScheme.IndexOf('/');
            if (slashAfterAuthority < 0)
                return false; // no path component

            pathPart = afterScheme[(slashAfterAuthority + 1)..]; // skip leading slash
        }
        else
        {
            // Private-use single-slash form (RFC 8252 §7.1): scheme:/path — no authority to skip.
            var colonSlash = uriString.IndexOf(":/", StringComparison.Ordinal);
            if (colonSlash < 0)
                return false;

            pathPart = uriString[(colonSlash + 2)..]; // skip ":/"
        }

        // Truncate at the query or fragment before splitting, otherwise a trailing "?..." or "#..."
        // would be glued onto the final segment (e.g. "..?x=1") and slip past the segment match.
        var queryOrFragment = pathPart.IndexOfAny(['?', '#']);
        if (queryOrFragment >= 0)
            pathPart = pathPart[..queryOrFragment];

        foreach (var decoded in pathPart.Split('/').Select(Uri.UnescapeDataString))
        {
            // Percent-decode once (case-insensitively handles both %2E and %2e, and mixed forms
            // like ".%2e" or "%2e.") so encoded traversal segments are caught.
            if (decoded is "." or "..")
                return true;
        }

        return false;
    }

    internal static bool IsSchemeAllowed(Uri uri)
    {
        if (string.Equals(uri.Scheme, "https", StringComparison.OrdinalIgnoreCase))
            return true;

        if (string.Equals(uri.Scheme, "http", StringComparison.OrdinalIgnoreCase))
        {
            // HTTP is permitted only for loopback hosts. IPv6 zone IDs are rejected separately
            // and scheme-neutrally in ValidateRedirectUriSet.
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
    {
        if (string.Equals(host, "localhost", StringComparison.OrdinalIgnoreCase))
            return true;

        // Strip IPv6 brackets for parsing
        var hostToParse = host.StartsWith('[') && host.EndsWith(']')
            ? host[1..^1]
            : host;

        return IPAddress.TryParse(hostToParse, out var ip) && IPAddress.IsLoopback(ip);
    }
}
