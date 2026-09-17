namespace ZeeKayDa.Auth.Clients;

/// <summary>
/// Validates a client's <see cref="IClientMetadata.InitiateLoginUri"/>: absent, or an absolute
/// <c>https</c> URI the framework can send a browser to without it becoming anything else.
/// </summary>
/// <remarks>
/// Stricter than a redirect URI: OpenID Connect requires <c>https</c> for it, and nothing about a
/// login restart calls for loopback <c>http</c> or a private-use scheme.
/// </remarks>
internal static class InitiateLoginUriValidator
{
    private const string PropertyName = "InitiateLoginUri";

    internal static void Validate(IClientRegistration client, List<ZeeKayDaConfigurationFailure> failures)
    {
        if (client.InitiateLoginUri is not { } uriString)
            return;

        if (!IsAbsoluteAsWritten(uriString, out var uri))
        {
            Fail("client.initiate_login_uri.invalid", "The value could not be parsed as an absolute URI.");
            return;
        }

        if (uri.Scheme != Uri.UriSchemeHttps)
            Fail("client.initiate_login_uri.scheme", "It must use the https scheme (OpenID Connect Registration §2).");

        if (RedirectUriRules.HasFragment(uri))
            Fail("client.initiate_login_uri.fragment", "Fragment components are prohibited.");

        if (RedirectUriRules.HasUserInfo(uri))
            Fail("client.initiate_login_uri.userinfo", "Userinfo components are prohibited.");

        if (RedirectUriRules.HasIpv6ZoneId(uriString))
            Fail("client.initiate_login_uri.ipv6_zone_id", "IPv6 zone IDs are prohibited.");

        if (RedirectUriRules.HasPathTraversal(uriString))
            Fail("client.initiate_login_uri.path_traversal", "Path traversal segments ('.' or '..') are prohibited.");

        void Fail(string code, string reason) => failures.Add(new ZeeKayDaConfigurationFailure(
            code,
            $"Client '{client.ClientId}' has an invalid {PropertyName}: '{uriString}'. {reason}"));
    }

    /// <summary>
    /// Parses as absolute and says so itself, authority and all: on Linux and macOS a rooted path
    /// such as <c>/login</c> parses as a <c>file</c> URI, which is a relative value rather than a
    /// URI with a scheme the rules below could judge, and a scheme-only form such as
    /// <c>https:/login</c> parses as absolute while naming no origin at all.
    /// </summary>
    private static bool IsAbsoluteAsWritten(string uriString, out Uri uri) =>
        Uri.TryCreate(uriString, UriKind.Absolute, out uri!)
        && uriString.StartsWith(uri.Scheme + Uri.SchemeDelimiter, StringComparison.OrdinalIgnoreCase)
        && !uriString.Any(IsControlOrWhitespace);

    private static bool IsControlOrWhitespace(char c) => char.IsControl(c) || char.IsWhiteSpace(c);
}
