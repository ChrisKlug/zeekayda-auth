namespace ZeeKayDa.Auth.Configuration;

/// <summary>
/// Validates the root <see cref="AuthorizationServerOptions.Issuer"/> against RFC 8414 §2 and
/// OIDC Discovery 1.0 §4, recording an error for every rule it breaks.
/// </summary>
internal static class IssuerValidator
{
    /// <summary>
    /// The issuer must be a non-empty absolute URI before anything else is asked of it; either
    /// failure is reported alone, since every later rule reads the parsed URI.
    /// </summary>
    internal static bool TryParse(AuthorizationServerOptions options, List<string> errors, out Uri issuerUri)
    {
        if (string.IsNullOrWhiteSpace(options.Issuer))
        {
            errors.Add("AuthorizationServerOptions.Issuer must be set to a non-empty value.");
            issuerUri = null!;
            return false;
        }

        if (!Uri.TryCreate(options.Issuer, UriKind.Absolute, out var uri))
        {
            errors.Add(
                $"AuthorizationServerOptions.Issuer '{options.Issuer}' is not a valid absolute URI.");
            issuerUri = null!;
            return false;
        }

        issuerUri = uri;
        return true;
    }

    /// <summary>Validates the shape, scheme and canonical form of the parsed issuer.</summary>
    internal static void Validate(AuthorizationServerOptions options, Uri uri, List<string> errors)
    {
        ValidateComponents(options.Issuer!, uri, errors);
        ValidateScheme(options, uri, errors);
        ValidateCanonicalForm(options.Issuer!, uri, errors);
    }

    private static void ValidateComponents(string issuer, Uri uri, List<string> errors)
    {
        // RFC 8414 §2 and OIDC Discovery 1.0 §4.1 prohibit query strings in the issuer.
        if (uri.Query.Length > 0)
        {
            errors.Add(
                $"AuthorizationServerOptions.Issuer '{issuer}' must not contain a query component ('?').");
        }

        // RFC 8414 §2 and OIDC Discovery 1.0 §4.1 prohibit fragment components in the issuer.
        if (uri.Fragment.Length > 0)
        {
            errors.Add(
                $"AuthorizationServerOptions.Issuer '{issuer}' must not contain a fragment component ('#').");
        }

        if (uri.UserInfo.Length > 0)
        {
            errors.Add(
                $"AuthorizationServerOptions.Issuer '{issuer}' must not contain user information.");
        }

        // OIDC Discovery 1.0 §4.3 and RFC 8414 §3.3 require the published issuer to be
        // byte-identical to the URL used to derive the discovery address. A trailing slash
        // creates an asymmetry because the route is registered without the slash but the
        // document preserves it verbatim — on the root issuer too, where RFC 8414 §3.1 strips
        // the terminating '/' before building the metadata URL.
        if (issuer.EndsWith('/'))
        {
            errors.Add(
                $"AuthorizationServerOptions.Issuer '{issuer}' must not have a trailing slash. " +
                "Use 'https://auth.example.com' rather than 'https://auth.example.com/', and " +
                "'https://auth.example.com/tenant1' rather than 'https://auth.example.com/tenant1/'. " +
                "OIDC Discovery 1.0 §4.3 requires the published issuer to be identical to the URL " +
                "used to derive the discovery address.");
        }
    }

    private static void ValidateScheme(AuthorizationServerOptions options, Uri uri, List<string> errors)
    {
        // The OIDC specification requires the issuer to be an HTTPS URI in production.
        // AllowInsecureIssuer permits only HTTP loopback issuers for local development.
        if (!ServerUriRules.IsSchemePermitted(uri, options.AllowInsecureIssuer))
        {
            errors.Add(
                $"AuthorizationServerOptions.Issuer '{options.Issuer}' uses an unsupported scheme '{uri.Scheme}'. " +
                "Only 'https' is permitted in production. " +
                "Set AllowInsecureIssuer = true to permit 'http' loopback issuers for local development and testing only.");
        }

        if (ServerUriRules.IsInsecureNonLoopback(uri, options.AllowInsecureIssuer))
        {
            errors.Add(
                $"AuthorizationServerOptions.Issuer '{options.Issuer}' uses HTTP for a non-loopback host. " +
                "AllowInsecureIssuer only permits HTTP loopback issuers for local development and testing.");
        }
    }

    private static void ValidateCanonicalForm(string issuer, Uri uri, List<string> errors)
    {
        var canonicalIssuer = BuildCanonicalIssuer(uri);
        var normalizedInputIssuer = NormalizeRootIssuer(issuer, uri);
        if (!string.Equals(normalizedInputIssuer, canonicalIssuer, StringComparison.Ordinal))
        {
            errors.Add(
                $"AuthorizationServerOptions.Issuer '{issuer}' is not canonical. Use '{canonicalIssuer}'.");
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
