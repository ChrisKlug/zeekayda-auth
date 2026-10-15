using System.Diagnostics.CodeAnalysis;

namespace ZeeKayDa.Auth.Authorization;

/// <summary>
/// Matches a presented <c>redirect_uri</c> against a client's registered set: exact ordinal
/// string comparison, with the RFC 8252 §7.3 loopback port variance as the single exception.
/// </summary>
internal static class AuthorizeRedirectUriMatcher
{
    /// <summary>
    /// Matches <paramref name="presented"/> ordinally against <paramref name="registered"/>, whatever
    /// the set's comparer, yielding a target built from the registered URI, never the presented one.
    /// </summary>
    public static bool TryMatch(string presented, IReadOnlySet<string> registered, out string redirectTarget)
    {
        var exact = registered.FirstOrDefault(
            candidate => string.Equals(presented, candidate, StringComparison.Ordinal));

        if (exact is not null)
        {
            redirectTarget = exact;
            return true;
        }

        return TryMatchLoopback(presented, registered, out redirectTarget);
    }

    private static bool TryMatchLoopback(string presented, IReadOnlySet<string> registered, out string redirectTarget)
    {
        redirectTarget = string.Empty;

        if (!TryParseLoopbackHttp(presented, out var presentedUri))
            return false;

        var match = registered
            .Select(candidate => TryParseLoopbackHttp(candidate, out var uri) ? uri : null)
            .Where(uri => uri is not null)
            .FirstOrDefault(uri => IsSameLoopbackTarget(presentedUri, uri!));

        if (match is null)
            return false;

        // Only the port comes from the presented string, so nothing unvetted reaches Location.
        redirectTarget = new UriBuilder(match) { Port = presentedUri.Port }
            .Uri.GetComponents(UriComponents.AbsoluteUri, UriFormat.UriEscaped);
        return true;
    }

    /// <summary>
    /// Parses <paramref name="value"/> only when it is <c>http</c> on a loopback host — the sole
    /// registrable combination whose port varies at runtime.
    /// </summary>
    private static bool TryParseLoopbackHttp(string value, [NotNullWhen(true)] out Uri? uri)
    {
        uri = null;

        if (!Uri.TryCreate(value, UriKind.Absolute, out var parsed))
            return false;

        if (!string.Equals(parsed.Scheme, Uri.UriSchemeHttp, StringComparison.OrdinalIgnoreCase))
            return false;

        if (!LoopbackHelper.IsLoopbackHost(parsed.Host))
            return false;

        uri = parsed;
        return true;
    }

    /// <summary>Compares everything except the port, which is allowed to vary.</summary>
    private static bool IsSameLoopbackTarget(Uri presented, Uri registered) =>
        string.Equals(presented.Host, registered.Host, StringComparison.Ordinal)
        && string.Equals(
            presented.GetComponents(UriComponents.Path | UriComponents.Query, UriFormat.UriEscaped),
            registered.GetComponents(UriComponents.Path | UriComponents.Query, UriFormat.UriEscaped),
            StringComparison.Ordinal);
}
