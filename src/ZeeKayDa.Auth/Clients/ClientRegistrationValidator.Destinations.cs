using Microsoft.Extensions.Logging;

namespace ZeeKayDa.Auth.Clients;

// Where the framework may send a browser for the client: redirect, post-logout and initiate-login URIs.
internal sealed partial class ClientRegistrationValidator
{
    private const int MaxUrisPerSet = 32;

    private IEnumerable<ZeeKayDaConfigurationFailure> ValidateDestinations(IClientWithCredentials client) =>
        ValidateRedirectUriSet(client.ClientId, client.RedirectUris, "RedirectUris")
            .Concat(ValidateRedirectUriSet(client.ClientId, client.PostLogoutRedirectUris, "PostLogoutRedirectUris"))
            .Concat(ValidateInitiateLoginUri(client));

    private IEnumerable<ZeeKayDaConfigurationFailure> ValidateRedirectUriSet(
        string clientId,
        IReadOnlySet<string> uriSet,
        string propertyName)
    {
        // Counted by enumerating: a custom set may yield more than its Count reports.
        var count = 0;

        foreach (var uriString in uriSet)
        {
            count++;

            var uriFailures = ValidateRedirectUri(new RedirectUriEntry(clientId, propertyName, uriString)).ToList();
            foreach (var failure in uriFailures)
                yield return failure;

            // RFC 8252 §8.3, http only: https://localhost is a dev certificate, where TLS rules out the risk.
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

    /// <summary>A redirect URI rule: its code, the problem as the message names it, and why.</summary>
    private sealed record RedirectUriRule(string Code, string Problem, string Reason);

    private static readonly RedirectUriRule ZoneIdRule = new(
        "client.redirect_uri.ipv6_zone_id", "with an IPv6 zone ID",
        "Zone IDs bind to a specific network interface rather than the loopback stack and are prohibited in redirect URIs.");

    private static readonly RedirectUriRule FragmentRule = new(
        "client.redirect_uri.fragment", "with a fragment component",
        "Fragment components are prohibited in redirect URIs (RFC 9700 §2.1).");

    private static readonly RedirectUriRule UserInfoRule = new(
        "client.redirect_uri.userinfo", "with a userinfo component",
        "Userinfo components are prohibited in redirect URIs.");

    private static readonly RedirectUriRule PathTraversalRule = new(
        "client.redirect_uri.path_traversal", "with a path traversal segment",
        "Path traversal segments ('.' or '..') are prohibited in redirect URIs.");

    private static readonly RedirectUriRule HttpNonLoopbackRule = new(
        "client.redirect_uri.scheme_http_non_loopback", "using HTTP for a non-loopback host",
        "HTTP redirect URIs are only permitted for loopback addresses (RFC 8252 §8.3).");

    private static readonly RedirectUriRule SchemeRule = new(
        "client.redirect_uri.scheme_not_allowed", "with a disallowed scheme",
        "Permitted schemes are 'https', 'http' (loopback only), and private-use schemes containing a dot.");

    /// <summary>One URI of a client's redirect URI set.</summary>
    private sealed record RedirectUriEntry(string ClientId, string PropertyName, string Uri)
    {
        public ZeeKayDaConfigurationFailure Broke(RedirectUriRule rule) => new(
            rule.Code,
            $"Client '{ClientId}' has a redirect URI in {PropertyName} {rule.Problem}: '{Uri}'. {rule.Reason}");
    }

    private static IEnumerable<ZeeKayDaConfigurationFailure> ValidateRedirectUri(RedirectUriEntry entry)
    {
        var uriString = entry.Uri;
        if (!Uri.TryCreate(uriString, UriKind.Absolute, out var uri))
        {
            yield return new ZeeKayDaConfigurationFailure(
                "client.redirect_uri.invalid",
                $"Client '{entry.ClientId}' has an invalid URI in {entry.PropertyName}: '{uriString}'. " +
                "The value could not be parsed as an absolute URI.");
            yield break;
        }

        // On the original string: .NET strips a zone ID from uri.Host at parse time.
        if (RedirectUriRules.HasIpv6ZoneId(uriString))
            yield return entry.Broke(ZoneIdRule);

        if (RedirectUriRules.HasFragment(uri))
            yield return entry.Broke(FragmentRule);

        if (RedirectUriRules.HasUserInfo(uri))
            yield return entry.Broke(UserInfoRule);

        // Checked on the original string: .NET's parser normalises '.' and '..' away.
        if (RedirectUriRules.HasPathTraversal(uriString))
            yield return entry.Broke(PathTraversalRule);

        if (!RedirectUriRules.IsSchemeAllowed(uri))
            yield return entry.Broke(RedirectUriRules.IsHttp(uri) ? HttpNonLoopbackRule : SchemeRule);
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
    /// Absolute as written, authority and all: on Unix <c>/login</c> parses as a <c>file</c> URI, and
    /// <c>https:/login</c> parses while naming no origin.
    /// </summary>
    private static bool IsAbsoluteAsWritten(string uriString, out Uri uri) =>
        Uri.TryCreate(uriString, UriKind.Absolute, out uri!)
        && uriString.StartsWith(uri.Scheme + Uri.SchemeDelimiter, StringComparison.OrdinalIgnoreCase)
        && !uriString.Any(c => char.IsControl(c) || char.IsWhiteSpace(c));
}
