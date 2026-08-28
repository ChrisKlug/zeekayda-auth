namespace ZeeKayDa.Auth.Authorization;

/// <summary>
/// Matches a presented <c>redirect_uri</c> against a client's registered set: exact ordinal
/// string comparison, with the RFC 8252 §7.3 loopback port variance as the single exception.
/// </summary>
internal static class AuthorizeRedirectUriMatcher
{
    /// <summary>
    /// Returns <see langword="true"/> when <paramref name="presented"/> matches a member of
    /// <paramref name="registered"/>.
    /// </summary>
    /// <remarks>
    /// Membership is checked with explicit <see cref="StringComparer.Ordinal"/> semantics per
    /// the <see cref="Clients.IClientMetadata"/> string-set invariant — the set's own comparer
    /// is not trusted. The loopback exception compares scheme, host, path and query exactly and
    /// ignores only the port, and applies only when both URIs are <c>http</c> on a loopback
    /// host — the sole registrable combination where the port varies at runtime.
    /// </remarks>
    public static bool Matches(string presented, IReadOnlySet<string> registered)
    {
        foreach (var candidate in registered)
        {
            if (string.Equals(presented, candidate, StringComparison.Ordinal))
                return true;
        }

        if (!Uri.TryCreate(presented, UriKind.Absolute, out var presentedUri) ||
            !string.Equals(presentedUri.Scheme, Uri.UriSchemeHttp, StringComparison.OrdinalIgnoreCase) ||
            !LoopbackHelper.IsLoopbackHost(presentedUri.Host))
        {
            return false;
        }

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
                return true;
            }
        }

        return false;
    }
}
