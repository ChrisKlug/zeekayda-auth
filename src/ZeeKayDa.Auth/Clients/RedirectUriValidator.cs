namespace ZeeKayDa.Auth.Clients;

/// <summary>
/// Applies <see cref="RedirectUriRules"/> to a single registered redirect URI and records a
/// <see cref="ZeeKayDaConfigurationFailure"/> for every rule it breaks.
/// </summary>
internal static class RedirectUriValidator
{
    /// <summary>
    /// Validates one URI from a client's redirect URI set, appending a failure per broken rule.
    /// </summary>
    /// <returns><see langword="true"/> when the URI broke no rule.</returns>
    internal static bool ValidateRedirectUri(
        string clientId,
        string uriString,
        string propertyName,
        List<ZeeKayDaConfigurationFailure> failures)
    {
        if (!Uri.TryCreate(uriString, UriKind.Absolute, out var uri))
        {
            failures.Add(new ZeeKayDaConfigurationFailure(
                "client.redirect_uri.invalid",
                $"Client '{clientId}' has an invalid URI in {propertyName}: '{uriString}'. " +
                "The value could not be parsed as an absolute URI."));
            return false;
        }

        var failuresBefore = failures.Count;

        // IPv6 zone-ID check: .NET strips zone IDs from uri.Host at parse time, so we must
        // inspect the original string. A URI with an IPv6 zone ID (e.g. [::1%25eth0]) binds
        // to a specific network interface, not the loopback stack, and must not be trusted.
        // This is scheme-neutral: an https:// URI with a zone ID is just as prohibited as an
        // http:// one, so it is checked here rather than inside the http branch of
        // IsSchemeAllowed.
        if (RedirectUriRules.HasIpv6ZoneId(uriString))
        {
            Fail("client.redirect_uri.ipv6_zone_id", "with an IPv6 zone ID",
                "Zone IDs bind to a specific network interface rather than the loopback stack and are prohibited in redirect URIs.");
        }

        if (RedirectUriRules.HasFragment(uri))
        {
            Fail("client.redirect_uri.fragment", "with a fragment component",
                "Fragment components are prohibited in redirect URIs (RFC 9700 §2.1).");
        }

        if (RedirectUriRules.HasUserInfo(uri))
        {
            Fail("client.redirect_uri.userinfo", "with a userinfo component",
                "Userinfo components are prohibited in redirect URIs.");
        }

        // Path traversal check — must inspect the original string because .NET's Uri parser
        // normalises '..' and '.' away during construction (AbsolutePath will not contain them).
        if (RedirectUriRules.HasPathTraversal(uriString))
        {
            Fail("client.redirect_uri.path_traversal", "with a path traversal segment",
                "Path traversal segments ('.' or '..') are prohibited in redirect URIs.");
        }

        if (!RedirectUriRules.IsSchemeAllowed(uri))
        {
            if (RedirectUriRules.IsHttp(uri))
            {
                Fail("client.redirect_uri.scheme_http_non_loopback", "using HTTP for a non-loopback host",
                    "HTTP redirect URIs are only permitted for loopback addresses (RFC 8252 §8.3).");
            }
            else
            {
                Fail("client.redirect_uri.scheme_not_allowed", "with a disallowed scheme",
                    "Permitted schemes are 'https', 'http' (loopback only), and private-use schemes containing a dot.");
            }
        }

        return failures.Count == failuresBefore;

        void Fail(string code, string problem, string reason)
            => failures.Add(new ZeeKayDaConfigurationFailure(
                code,
                $"Client '{clientId}' has a redirect URI in {propertyName} {problem}: '{uriString}'. {reason}"));
    }
}
