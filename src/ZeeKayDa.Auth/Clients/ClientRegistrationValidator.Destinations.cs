using Microsoft.Extensions.Logging;

namespace ZeeKayDa.Auth.Clients;

// Where the framework may send a browser on the client's behalf: its redirect URIs, post-logout
// redirect URIs, and initiate-login URI.
internal sealed partial class ClientRegistrationValidator
{
    private const int MaxUrisPerSet = 32;

    private IEnumerable<ZeeKayDaConfigurationFailure> ValidateDestinations(IClientWithCredentials client) =>
    [
        .. ValidateRedirectUriSet(client.ClientId, client.RedirectUris, "RedirectUris"),
        .. ValidateRedirectUriSet(client.ClientId, client.PostLogoutRedirectUris, "PostLogoutRedirectUris"),
        .. ValidateInitiateLoginUri(client),
    ];

    private IEnumerable<ZeeKayDaConfigurationFailure> ValidateRedirectUriSet(
        string clientId,
        IReadOnlySet<string> uriSet,
        string propertyName)
    {
        // Count what the set yields, not what its Count property claims: a custom registration's
        // set may enumerate more entries than it reports, and the cap must see every one of them.
        var count = 0;

        foreach (var uriString in uriSet)
        {
            count++;

            var uriFailures = ValidateRedirectUri(clientId, uriString, propertyName).ToList();
            foreach (var failure in uriFailures)
                yield return failure;

            // RFC 8252 §8.3, http only: a native app's loopback redirect is http (§7.3), while
            // https://localhost is a web client on a dev certificate, where TLS already rules out
            // the name-resolution risk. A URI rejected anyway gets no advisory on top.
            var isValidHttpLocalhost = uriFailures.Count == 0 && RedirectUriRules.IsHttpLocalhost(uriString);
            if (isValidHttpLocalhost && FirstTime(clientId, "localhost-" + propertyName, uriString))
            {
                logger.LogWarning(
                    "Client '{ClientId}' uses 'localhost' in {PropertyName}: '{Uri}'. " +
                    "RFC 8252 §8.3 recommends using the IP literal '127.0.0.1' instead of 'localhost' " +
                    "to avoid DNS rebinding and cross-platform compatibility issues.",
                    clientId, propertyName, uriString);
            }
        }

        if (count > MaxUrisPerSet)
        {
            yield return new ZeeKayDaConfigurationFailure(
                "client.redirect_uri.count_exceeded",
                $"Client '{clientId}' has {count} URIs in {propertyName}, which exceeds the maximum of {MaxUrisPerSet}.");
        }
    }

    private static IEnumerable<ZeeKayDaConfigurationFailure> ValidateRedirectUri(
        string clientId,
        string uriString,
        string propertyName)
    {
        if (!Uri.TryCreate(uriString, UriKind.Absolute, out var uri))
        {
            yield return new ZeeKayDaConfigurationFailure(
                "client.redirect_uri.invalid",
                $"Client '{clientId}' has an invalid URI in {propertyName}: '{uriString}'. " +
                "The value could not be parsed as an absolute URI.");
            yield break;
        }

        // Checked on the original string: .NET strips a zone ID from uri.Host at parse time. A zone
        // ID binds to one network interface rather than the loopback stack, whatever the scheme.
        if (RedirectUriRules.HasIpv6ZoneId(uriString))
        {
            yield return Fail("client.redirect_uri.ipv6_zone_id", "with an IPv6 zone ID",
                "Zone IDs bind to a specific network interface rather than the loopback stack and are prohibited in redirect URIs.");
        }

        if (RedirectUriRules.HasFragment(uri))
        {
            yield return Fail("client.redirect_uri.fragment", "with a fragment component",
                "Fragment components are prohibited in redirect URIs (RFC 9700 §2.1).");
        }

        if (RedirectUriRules.HasUserInfo(uri))
        {
            yield return Fail("client.redirect_uri.userinfo", "with a userinfo component",
                "Userinfo components are prohibited in redirect URIs.");
        }

        // Checked on the original string: .NET's parser normalises '.' and '..' away.
        if (RedirectUriRules.HasPathTraversal(uriString))
        {
            yield return Fail("client.redirect_uri.path_traversal", "with a path traversal segment",
                "Path traversal segments ('.' or '..') are prohibited in redirect URIs.");
        }

        if (!RedirectUriRules.IsSchemeAllowed(uri))
        {
            yield return RedirectUriRules.IsHttp(uri)
                ? Fail("client.redirect_uri.scheme_http_non_loopback", "using HTTP for a non-loopback host",
                    "HTTP redirect URIs are only permitted for loopback addresses (RFC 8252 §8.3).")
                : Fail("client.redirect_uri.scheme_not_allowed", "with a disallowed scheme",
                    "Permitted schemes are 'https', 'http' (loopback only), and private-use schemes containing a dot.");
        }

        ZeeKayDaConfigurationFailure Fail(string code, string problem, string reason) => new(
            code,
            $"Client '{clientId}' has a redirect URI in {propertyName} {problem}: '{uriString}'. {reason}");
    }

    /// <summary>
    /// Stricter than a redirect URI: OpenID Connect requires <c>https</c> for it, and nothing about
    /// a login restart calls for loopback <c>http</c> or a private-use scheme.
    /// </summary>
    private static IEnumerable<ZeeKayDaConfigurationFailure> ValidateInitiateLoginUri(IClientWithCredentials client)
    {
        if (client.InitiateLoginUri is not { } uriString)
            yield break;

        if (!IsAbsoluteAsWritten(uriString, out var uri))
        {
            yield return Fail("client.initiate_login_uri.invalid", "The value could not be parsed as an absolute URI.");
            yield break;
        }

        if (uri.Scheme != Uri.UriSchemeHttps)
            yield return Fail("client.initiate_login_uri.scheme", "It must use the https scheme (OpenID Connect Registration §2).");

        if (RedirectUriRules.HasFragment(uri))
            yield return Fail("client.initiate_login_uri.fragment", "Fragment components are prohibited.");

        if (RedirectUriRules.HasUserInfo(uri))
            yield return Fail("client.initiate_login_uri.userinfo", "Userinfo components are prohibited.");

        if (RedirectUriRules.HasIpv6ZoneId(uriString))
            yield return Fail("client.initiate_login_uri.ipv6_zone_id", "IPv6 zone IDs are prohibited.");

        if (RedirectUriRules.HasPathTraversal(uriString))
            yield return Fail("client.initiate_login_uri.path_traversal", "Path traversal segments ('.' or '..') are prohibited.");

        ZeeKayDaConfigurationFailure Fail(string code, string reason) => new(
            code,
            $"Client '{client.ClientId}' has an invalid InitiateLoginUri: '{uriString}'. {reason}");
    }

    /// <summary>
    /// Parses as absolute and says so itself, authority and all: on Linux and macOS a rooted path
    /// such as <c>/login</c> parses as a <c>file</c> URI, and a scheme-only form such as
    /// <c>https:/login</c> parses as absolute while naming no origin at all.
    /// </summary>
    private static bool IsAbsoluteAsWritten(string uriString, out Uri uri) =>
        Uri.TryCreate(uriString, UriKind.Absolute, out uri!)
        && uriString.StartsWith(uri.Scheme + Uri.SchemeDelimiter, StringComparison.OrdinalIgnoreCase)
        && !uriString.Any(c => char.IsControl(c) || char.IsWhiteSpace(c));
}
