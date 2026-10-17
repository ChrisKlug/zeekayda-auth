using ZeeKayDa.Auth.Configuration;

namespace ZeeKayDa.Auth;

// The issuer, against RFC 8414 §2 and OIDC Discovery 1.0 §4.
internal static partial class AuthorizationServerOptionsValidation
{
    /// <summary>The issuer as an absolute URI, or the one failure reported when it is not.</summary>
    private static ZeeKayDaConfigurationFailure? ParseIssuer(AuthorizationServerOptions options, out Uri issuerUri)
    {
        issuerUri = null!;

        if (string.IsNullOrWhiteSpace(options.Issuer))
        {
            return new(
                "configuration.issuer.missing",
                "AuthorizationServerOptions.Issuer must be set to a non-empty value.");
        }

        if (!Uri.TryCreate(options.Issuer, UriKind.Absolute, out var uri))
        {
            return new(
                "configuration.issuer.invalid",
                "AuthorizationServerOptions.Issuer is not a valid absolute URI.");
        }

        issuerUri = uri;
        return null;
    }

    private static IEnumerable<ZeeKayDaConfigurationFailure> ValidateIssuer(AuthorizationServerOptions options, Uri uri)
    {
        var issuer = options.Issuer!;
        var shown = ConfiguredUri.Display(issuer, uri);

        return ValidateIssuerComponents(issuer, shown, uri)
            .Concat(ValidateIssuerScheme(options, shown, uri))
            .Concat(ValidateIssuerCanonicalForm(issuer, shown, uri));
    }

    private static IEnumerable<ZeeKayDaConfigurationFailure> ValidateIssuerComponents(string issuer, string shown, Uri uri)
    {
        // RFC 8414 §2 and OIDC Discovery 1.0 §4.1 prohibit a query and a fragment.
        if (uri.Query.Length > 0)
        {
            yield return new(
                "configuration.issuer.query",
                $"AuthorizationServerOptions.Issuer '{shown}' must not contain a query component ('?').");
        }

        if (uri.Fragment.Length > 0)
        {
            yield return new(
                "configuration.issuer.fragment",
                $"AuthorizationServerOptions.Issuer '{shown}' must not contain a fragment component ('#').");
        }

        if (uri.UserInfo.Length > 0)
        {
            yield return new(
                "configuration.issuer.userinfo",
                $"AuthorizationServerOptions.Issuer '{shown}' must not contain user information.");
        }

        // The route drops a trailing slash the document keeps, breaking the identity Discovery §4.3 requires.
        if (issuer.EndsWith('/'))
        {
            yield return new(
                "configuration.issuer.trailing_slash",
                $"AuthorizationServerOptions.Issuer '{shown}' must not have a trailing slash. " +
                "Use 'https://auth.example.com' rather than 'https://auth.example.com/', and " +
                "'https://auth.example.com/tenant1' rather than 'https://auth.example.com/tenant1/'. " +
                "OIDC Discovery 1.0 §4.3 requires the published issuer to be identical to the URL " +
                "used to derive the discovery address.");
        }
    }

    private static IEnumerable<ZeeKayDaConfigurationFailure> ValidateIssuerScheme(AuthorizationServerOptions options, string shown, Uri uri)
    {
        if (!ServerUriRules.IsSchemePermitted(uri, options.Development.AllowHttpLoopbackIssuer))
        {
            yield return new(
                "configuration.issuer.not_https",
                $"AuthorizationServerOptions.Issuer '{shown}' uses an unsupported scheme '{uri.Scheme}'. " +
                "Only 'https' is permitted in production. " +
                "Set Development.AllowHttpLoopbackIssuer = true to permit 'http' loopback issuers for local development and testing only.");
        }

        if (ServerUriRules.IsInsecureNonLoopback(uri, options.Development.AllowHttpLoopbackIssuer))
        {
            yield return new(
                "configuration.issuer.http_non_loopback",
                $"AuthorizationServerOptions.Issuer '{shown}' uses HTTP for a non-loopback host. " +
                "Development.AllowHttpLoopbackIssuer only permits HTTP loopback issuers for local development and testing.");
        }

        if (options.Development.AllowHttpLoopbackIssuer && IsHttps(uri))
        {
            yield return new(
                "configuration.development.allow_http_loopback_issuer.https_issuer",
                $"Development.AllowHttpLoopbackIssuer is true, but AuthorizationServerOptions.Issuer '{shown}' uses https. " +
                "The flag exists only for an http loopback issuer, and on an https issuer it would still let every " +
                "request arriving from a loopback address, such as through a reverse proxy on the same host, bypass " +
                "the HTTPS requirement. Remove Development.AllowHttpLoopbackIssuer = true.");
        }
    }

    private static bool IsHttps(Uri uri) => string.Equals(uri.Scheme, Uri.UriSchemeHttps, StringComparison.OrdinalIgnoreCase);

    private static IEnumerable<ZeeKayDaConfigurationFailure> ValidateIssuerCanonicalForm(string issuer, string shown, Uri uri)
    {
        var canonicalIssuer = BuildCanonicalIssuer(uri);
        if (!string.Equals(NormalizeRootIssuer(issuer, uri), canonicalIssuer, StringComparison.Ordinal))
        {
            yield return new(
                "configuration.issuer.not_canonical",
                $"AuthorizationServerOptions.Issuer '{shown}' is not canonical. " +
                (ConfiguredUri.CanShowVerbatim(uri)
                    ? $"Use '{canonicalIssuer}'."
                    : "Use a lowercase scheme and host, and leave out a default port."));
        }
    }

    private static string BuildCanonicalIssuer(Uri issuerUri)
    {
        var scheme = issuerUri.Scheme.ToLowerInvariant();
        var host = issuerUri.Host.ToLowerInvariant();
        var isDefaultPort =
            (string.Equals(scheme, Uri.UriSchemeHttps, StringComparison.Ordinal) && issuerUri.Port == 443) ||
            (string.Equals(scheme, Uri.UriSchemeHttp, StringComparison.Ordinal) && issuerUri.Port == 80);

        var builder = new UriBuilder(issuerUri)
        {
            Scheme = scheme,
            Host = host,
            Port = isDefaultPort ? -1 : issuerUri.Port,
        };

        var canonical = builder.Uri.AbsoluteUri;
        return issuerUri.AbsolutePath == "/" && canonical.EndsWith("/", StringComparison.Ordinal)
            ? canonical[..^1]
            : canonical;
    }

    private static string NormalizeRootIssuer(string issuer, Uri parsedIssuer)
        => parsedIssuer.AbsolutePath == "/" && issuer.EndsWith("/", StringComparison.Ordinal)
            ? issuer[..^1]
            : issuer;
}
