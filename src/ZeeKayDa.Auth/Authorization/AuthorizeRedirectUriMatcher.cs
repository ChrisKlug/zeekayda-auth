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

        if (Uri.TryCreate(presented, UriKind.Absolute, out var presentedUri) &&
            string.Equals(presentedUri.Scheme, Uri.UriSchemeHttp, StringComparison.OrdinalIgnoreCase) &&
            LoopbackHelper.IsLoopbackHost(presentedUri.Host))
        {
            foreach (var candidate in registered)
            {
                if (Uri.TryCreate(candidate, UriKind.Absolute, out var registeredUri) &&
                    string.Equals(registeredUri.Scheme, Uri.UriSchemeHttp, StringComparison.OrdinalIgnoreCase) &&
                    LoopbackHelper.IsLoopbackHost(registeredUri.Host) &&
                    string.Equals(presentedUri.Host, registeredUri.Host, StringComparison.Ordinal) &&
                    string.Equals(
                        presentedUri.GetComponents(UriComponents.Path | UriComponents.Query, UriFormat.UriEscaped),
                        registeredUri.GetComponents(UriComponents.Path | UriComponents.Query, UriFormat.UriEscaped),
                        StringComparison.Ordinal))
                {
                    // Rebuild from the trusted registered URI, substituting only the presented
                    // port, so nothing from the raw presented string reaches the response.
                    redirectTarget = new UriBuilder(registeredUri) { Port = presentedUri.Port }
                        .Uri.GetComponents(UriComponents.AbsoluteUri, UriFormat.UriEscaped);
                    return true;
                }
            }
        }

        redirectTarget = string.Empty;
        return false;
    }
}
