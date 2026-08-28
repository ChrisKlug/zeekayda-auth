using System.Diagnostics.CodeAnalysis;

namespace ZeeKayDa.Auth.Authorization;

/// <summary>
/// Matches a presented <c>redirect_uri</c> against a client's registered set: exact ordinal
/// string comparison, with the RFC 8252 §7.3 loopback port variance as the single exception.
/// </summary>
internal static class AuthorizeRedirectUriMatcher
{
    /// <summary>
    /// Attempts to match <paramref name="presented"/> against a member of
    /// <paramref name="registered"/>, yielding in <paramref name="redirectTarget"/> the URI that
    /// is safe to use as the redirect destination.
    /// </summary>
    /// <remarks>
    /// <para>
    /// Membership is checked with explicit <see cref="StringComparer.Ordinal"/> semantics per the
    /// <see cref="Clients.IClientMetadata"/> string-set invariant — the set's own comparer is not
    /// trusted. The loopback exception compares scheme, host, path and query exactly and ignores
    /// only the port, and applies only when both URIs are <c>http</c> on a loopback host — the
    /// sole registrable combination where the port varies at runtime.
    /// </para>
    /// <para>
    /// <strong>The yielded target is derived from the registered URI, never the raw presented
    /// string.</strong> For an exact match the two are byte-identical; for a loopback match the
    /// target is the registered URI with the presented port substituted. This guarantees the
    /// redirect destination carries only components a client-registration validator already
    /// vetted — a raw presented string could smuggle control characters, userinfo, or dot
    /// segments past the canonicalizing comparison and into the <c>Location</c> header.
    /// </para>
    /// </remarks>
    public static bool TryMatch(string presented, IReadOnlySet<string> registered, out string redirectTarget)
    {
        foreach (var candidate in registered)
        {
            if (string.Equals(presented, candidate, StringComparison.Ordinal))
            {
                redirectTarget = candidate;
                return true;
            }
        }

        return TryMatchLoopback(presented, registered, out redirectTarget);
    }

    private static bool TryMatchLoopback(string presented, IReadOnlySet<string> registered, out string redirectTarget)
    {
        redirectTarget = string.Empty;

        if (!TryParseLoopbackHttp(presented, out var presentedUri))
            return false;

        foreach (var candidate in registered)
        {
            if (!TryParseLoopbackHttp(candidate, out var registeredUri))
                continue;

            if (!IsSameLoopbackTarget(presentedUri, registeredUri))
                continue;

            // Rebuild from the trusted registered URI, substituting only the presented port, so
            // nothing from the raw presented string reaches the response.
            redirectTarget = new UriBuilder(registeredUri) { Port = presentedUri.Port }
                .Uri.GetComponents(UriComponents.AbsoluteUri, UriFormat.UriEscaped);
            return true;
        }

        return false;
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
