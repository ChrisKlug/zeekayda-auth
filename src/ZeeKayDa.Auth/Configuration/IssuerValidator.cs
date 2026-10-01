namespace ZeeKayDa.Auth.Configuration;

/// <summary>
/// Validates the root <see cref="AuthorizationServerOptions.Issuer"/> against RFC 8414 §2 and
/// OIDC Discovery 1.0 §4, recording a failure for every rule it breaks.
/// </summary>
internal static class IssuerValidator
{
    /// <summary>
    /// The issuer must be a non-empty absolute URI before anything else is asked of it; either
    /// failure is reported alone, since every later rule reads the parsed URI.
    /// </summary>
    internal static bool TryParse(AuthorizationServerOptions options, ICollection<ZeeKayDaConfigurationFailure> failures, out Uri issuerUri)
    {
        if (string.IsNullOrWhiteSpace(options.Issuer))
        {
            failures.Add(new(
                "configuration.issuer.missing",
                "AuthorizationServerOptions.Issuer must be set to a non-empty value."));
            issuerUri = null!;
            return false;
        }

        if (!Uri.TryCreate(options.Issuer, UriKind.Absolute, out var uri))
        {
            failures.Add(new(
                "configuration.issuer.invalid",
                "AuthorizationServerOptions.Issuer is not a valid absolute URI."));
            issuerUri = null!;
            return false;
        }

        issuerUri = uri;
        return true;
    }

    /// <summary>Validates the shape, scheme and canonical form of the parsed issuer.</summary>
    internal static void Validate(AuthorizationServerOptions options, Uri uri, ICollection<ZeeKayDaConfigurationFailure> failures)
    {
        var shown = ConfiguredUri.Display(options.Issuer!, uri);
        ValidateComponents(options.Issuer!, shown, uri, failures);
        ValidateScheme(options, shown, uri, failures);
        ValidateCanonicalForm(options.Issuer!, shown, uri, failures);
    }

    private static void ValidateComponents(string issuer, string shown, Uri uri, ICollection<ZeeKayDaConfigurationFailure> failures)
    {
        // RFC 8414 §2 and OIDC Discovery 1.0 §4.1 prohibit query strings in the issuer.
        if (uri.Query.Length > 0)
        {
            failures.Add(new(
                "configuration.issuer.query",
                $"AuthorizationServerOptions.Issuer '{shown}' must not contain a query component ('?')."));
        }

        // RFC 8414 §2 and OIDC Discovery 1.0 §4.1 prohibit fragment components in the issuer.
        if (uri.Fragment.Length > 0)
        {
            failures.Add(new(
                "configuration.issuer.fragment",
                $"AuthorizationServerOptions.Issuer '{shown}' must not contain a fragment component ('#')."));
        }

        if (uri.UserInfo.Length > 0)
        {
            failures.Add(new(
                "configuration.issuer.userinfo",
                $"AuthorizationServerOptions.Issuer '{shown}' must not contain user information."));
        }

        // OIDC Discovery 1.0 §4.3 and RFC 8414 §3.3 require the published issuer to be
        // byte-identical to the URL used to derive the discovery address. A trailing slash
        // creates an asymmetry because the route is registered without the slash but the
        // document preserves it verbatim — on the root issuer too, where RFC 8414 §3.1 strips
        // the terminating '/' before building the metadata URL.
        if (issuer.EndsWith('/'))
        {
            failures.Add(new(
                "configuration.issuer.trailing_slash",
                $"AuthorizationServerOptions.Issuer '{shown}' must not have a trailing slash. " +
                "Use 'https://auth.example.com' rather than 'https://auth.example.com/', and " +
                "'https://auth.example.com/tenant1' rather than 'https://auth.example.com/tenant1/'. " +
                "OIDC Discovery 1.0 §4.3 requires the published issuer to be identical to the URL " +
                "used to derive the discovery address."));
        }
    }

    private static void ValidateScheme(AuthorizationServerOptions options, string shown, Uri uri, ICollection<ZeeKayDaConfigurationFailure> failures)
    {
        // The OIDC specification requires the issuer to be an HTTPS URI in production.
        if (!ServerUriRules.IsSchemePermitted(uri, options.Development.AllowHttpLoopbackIssuer))
        {
            failures.Add(new(
                "configuration.issuer.not_https",
                $"AuthorizationServerOptions.Issuer '{shown}' uses an unsupported scheme '{uri.Scheme}'. " +
                "Only 'https' is permitted in production. " +
                "Set Development.AllowHttpLoopbackIssuer = true to permit 'http' loopback issuers for local development and testing only."));
        }

        if (ServerUriRules.IsInsecureNonLoopback(uri, options.Development.AllowHttpLoopbackIssuer))
        {
            failures.Add(new(
                "configuration.issuer.http_non_loopback",
                $"AuthorizationServerOptions.Issuer '{shown}' uses HTTP for a non-loopback host. " +
                "Development.AllowHttpLoopbackIssuer only permits HTTP loopback issuers for local development and testing."));
        }
    }

    private static void ValidateCanonicalForm(string issuer, string shown, Uri uri, ICollection<ZeeKayDaConfigurationFailure> failures)
    {
        var canonicalIssuer = BuildCanonicalIssuer(uri);
        var normalizedInputIssuer = NormalizeRootIssuer(issuer, uri);
        if (!string.Equals(normalizedInputIssuer, canonicalIssuer, StringComparison.Ordinal))
        {
            failures.Add(new(
                "configuration.issuer.not_canonical",
                $"AuthorizationServerOptions.Issuer '{shown}' is not canonical. " +
                (ConfiguredUri.CanShowVerbatim(uri)
                    ? $"Use '{canonicalIssuer}'."
                    : "Use a lowercase scheme and host, and leave out a default port.")));
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
