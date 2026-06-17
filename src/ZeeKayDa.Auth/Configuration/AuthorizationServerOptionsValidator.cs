using Microsoft.Extensions.Options;
using ZeeKayDa.Auth;

namespace ZeeKayDa.Auth.Configuration;

/// <summary>
/// Validates <see cref="AuthorizationServerOptions"/> at startup according to the rules mandated
/// by the OIDC Discovery 1.0 and RFC 8414 specifications.
/// </summary>
/// <remarks>
/// This validator is registered via <c>AddZeeKayDaAuth()</c> and activated by
/// <c>ValidateOnStart()</c> so that misconfigured servers fail loudly at startup rather than
/// silently at the first request. It is a pure read-only check: CORS-origin canonicalization is
/// handled by <see cref="AuthorizationServerOptionsPostConfigurer"/> (which runs before this
/// validator), and async checks (e.g. scope presence) are handled by hosted services.
/// </remarks>
internal sealed class AuthorizationServerOptionsValidator : IValidateOptions<AuthorizationServerOptions>
{
    private const string TokenEndpointAuthMethodsRequiredMessage =
        "AuthorizationServerOptions.TokenEndpoint.AuthMethodsSupported must not be null or empty. " +
        "Specify at least one client authentication method (e.g., TokenEndpointAuthMethods.ClientSecretBasic). " +
        "See OAuth 2.0 Security BCP §2.6 (RFC 9700).";

    /// <summary>
    /// Startup validation error for the ADR 0002 §4 Rule 2 cross-group constraint that forbids
    /// advertising the <c>client_credentials</c> grant with only <c>none</c> token endpoint auth.
    /// </summary>
    /// <remarks>
    /// RFC 6749 §4.4 requires client authentication for the client credentials grant and RFC 9700
    /// §2.6 requires strong token endpoint client authentication.
    /// </remarks>
    private const string ClientCredentialsRequiresNonNoneTokenAuthMethodMessage =
        "GrantTypesSupported includes 'client_credentials', which requires confidential clients. " +
        "TokenEndpoint.AuthMethodsSupported must contain at least one method other than 'none'. " +
        "See RFC 6749 §4.4 and OAuth 2.0 Security BCP §2.6 (RFC 9700).";

    /// <inheritdoc/>
    public ValidateOptionsResult Validate(string? name, AuthorizationServerOptions options)
    {
        var errors = new List<string>();

        if (string.IsNullOrWhiteSpace(options.Issuer))
        {
            errors.Add("AuthorizationServerOptions.Issuer must be set to a non-empty value.");
            return ValidateOptionsResult.Fail(errors);
        }

        if (!Uri.TryCreate(options.Issuer, UriKind.Absolute, out var uri))
        {
            errors.Add(
                $"AuthorizationServerOptions.Issuer '{options.Issuer}' is not a valid absolute URI.");
            return ValidateOptionsResult.Fail(errors);
        }

        // RFC 8414 §2 and OIDC Discovery 1.0 §4.1 prohibit query strings in the issuer.
        if (uri.Query.Length > 0)
        {
            errors.Add(
                $"AuthorizationServerOptions.Issuer '{options.Issuer}' must not contain a query component ('?').");
        }

        // RFC 8414 §2 and OIDC Discovery 1.0 §4.1 prohibit fragment components in the issuer.
        if (uri.Fragment.Length > 0)
        {
            errors.Add(
                $"AuthorizationServerOptions.Issuer '{options.Issuer}' must not contain a fragment component ('#').");
        }

        if (uri.UserInfo.Length > 0)
        {
            errors.Add(
                $"AuthorizationServerOptions.Issuer '{options.Issuer}' must not contain user information.");
        }

        // OIDC Discovery 1.0 §4.3 and RFC 8414 §3.3 require the published issuer to be
        // byte-identical to the URL used to derive the discovery address. A trailing slash
        // on a path-bearing issuer creates an asymmetry because the route is registered
        // without the slash but the document preserves it verbatim.
        if (uri.AbsolutePath.EndsWith('/') && uri.AbsolutePath.Length > 1)
        {
            errors.Add(
                $"AuthorizationServerOptions.Issuer '{options.Issuer}' must not have a trailing slash. " +
                "Use 'https://auth.example.com/tenant1' rather than 'https://auth.example.com/tenant1/'. " +
                "OIDC Discovery 1.0 §4.3 requires the published issuer to be identical to the URL " +
                "used to derive the discovery address.");
        }

        // The OIDC specification requires the issuer to be an HTTPS URI in production.
        // AllowInsecureIssuer permits only HTTP loopback issuers for local development.
        var isHttps = string.Equals(uri.Scheme, Uri.UriSchemeHttps, StringComparison.OrdinalIgnoreCase);
        var isHttp = string.Equals(uri.Scheme, Uri.UriSchemeHttp, StringComparison.OrdinalIgnoreCase);

        if (!isHttps && !(isHttp && options.AllowInsecureIssuer))
        {
            errors.Add(
                $"AuthorizationServerOptions.Issuer '{options.Issuer}' uses an unsupported scheme '{uri.Scheme}'. " +
                "Only 'https' is permitted in production. " +
                "Set AllowInsecureIssuer = true to permit 'http' loopback issuers for local development and testing only.");
        }

        if (isHttp && options.AllowInsecureIssuer && !LoopbackHelper.IsLoopbackHost(uri.Host))
        {
            errors.Add(
                $"AuthorizationServerOptions.Issuer '{options.Issuer}' uses HTTP for a non-loopback host. " +
                "AllowInsecureIssuer only permits HTTP loopback issuers for local development and testing.");
        }

        var canonicalIssuer = BuildCanonicalIssuer(uri);
        var normalizedInputIssuer = NormalizeRootIssuer(options.Issuer!, uri);
        if (!string.Equals(normalizedInputIssuer, canonicalIssuer, StringComparison.Ordinal))
        {
            errors.Add(
                $"AuthorizationServerOptions.Issuer '{options.Issuer}' is not canonical. Use '{canonicalIssuer}'.");
        }

        // Validate Response group
        if (options.Response.TypesSupported is null)
        {
            errors.Add("AuthorizationServerOptions.Response.TypesSupported must not be null.");
        }
        else if (options.Response.TypesSupported.Count == 0)
        {
            errors.Add("AuthorizationServerOptions.Response.TypesSupported must contain at least one value.");
        }

        if (options.Response.ModesSupported is null)
        {
            errors.Add("AuthorizationServerOptions.Response.ModesSupported must not be null.");
        }

        // Validate root-level GrantTypesSupported
        if (options.GrantTypesSupported is null)
        {
            errors.Add("AuthorizationServerOptions.GrantTypesSupported must not be null.");
        }
        else
        {
            foreach (var grantType in options.GrantTypesSupported)
            {
                if (!Enum.IsDefined(grantType))
                    errors.Add(
                        $"AuthorizationServerOptions.GrantTypesSupported contains invalid value '{(int)grantType}'. " +
                        $"Expected a valid {nameof(GrantType)} enum member.");
            }
        }

        // Validate Token group
        if (options.TokenEndpoint.AuthMethodsSupported is null ||
            options.TokenEndpoint.AuthMethodsSupported.Count == 0)
        {
            errors.Add(TokenEndpointAuthMethodsRequiredMessage);
        }
        else
        {
            foreach (var authMethod in options.TokenEndpoint.AuthMethodsSupported)
            {
                if (string.IsNullOrWhiteSpace(authMethod))
                {
                    errors.Add(
                        "AuthorizationServerOptions.TokenEndpoint.AuthMethodsSupported contains an invalid entry: " +
                        "each entry must be a non-empty, non-whitespace string.");
                    continue;
                }
                if (authMethod != authMethod.Trim())
                {
                    errors.Add(
                        "AuthorizationServerOptions.TokenEndpoint.AuthMethodsSupported contains an invalid entry: " +
                        $"'{authMethod}' has leading or trailing whitespace.");
                    continue;
                }
                if (authMethod.Any(char.IsControl))
                {
                    errors.Add(
                        "AuthorizationServerOptions.TokenEndpoint.AuthMethodsSupported contains an invalid entry: " +
                        $"'{authMethod}' contains one or more control characters.");
                }
            }

            // ADR 0002 §4: If client_credentials grant is supported, must have at least one non-None auth method
            if (options.GrantTypesSupported is not null &&
                options.GrantTypesSupported.Contains(GrantType.ClientCredentials) &&
                options.TokenEndpoint.AuthMethodsSupported.All(m => string.Equals(m, TokenEndpointAuthMethods.None, StringComparison.Ordinal)))
            {
                errors.Add(ClientCredentialsRequiresNonNoneTokenAuthMethodMessage);
            }
        }

        // Validate IdToken group
        if (options.IdToken.SigningAlgValuesSupported is null)
        {
            errors.Add("AuthorizationServerOptions.IdToken.SigningAlgValuesSupported must not be null.");
        }
        else if (options.IdToken.SigningAlgValuesSupported.Count == 0)
        {
            errors.Add("AuthorizationServerOptions.IdToken.SigningAlgValuesSupported must contain at least one value.");
        }

        // Validate Discovery group
        if (options.DiscoveryDocument.CacheMaxAgeSeconds < 0)
        {
            errors.Add("AuthorizationServerOptions.DiscoveryDocument.CacheMaxAgeSeconds must not be negative.");
        }

        // Validate DiscoveryDocument.CorsOrigins — each entry must be a strict absolute origin
        // (scheme://host[:port]) with no path (other than "/"), query, fragment, userinfo, wildcards,
        // or CRLF. Invalid entries fail startup.
        foreach (var origin in options.DiscoveryDocument.CorsOrigins)
        {
            if (origin is null)
            {
                errors.Add("A null value is not a valid CORS origin.");
                continue;
            }
            if (origin.Length == 0)
            {
                errors.Add("An empty string is not a valid CORS origin.");
                continue;
            }
            if (origin.IndexOfAny(['\r', '\n']) >= 0)
            {
                errors.Add($"CORS origin '{origin}' must not contain CR or LF characters.");
                continue;
            }
            if (string.Equals(origin, "null", StringComparison.Ordinal))
            {
                errors.Add("'null' is not a valid CORS origin.");
                continue;
            }
            if (origin.Contains('*'))
            {
                errors.Add($"CORS origin '{origin}' must not contain wildcard characters.");
                continue;
            }
            if (!Uri.TryCreate(origin, UriKind.Absolute, out var originUri))
            {
                errors.Add($"CORS origin '{origin}' is not a valid absolute URI.");
                continue;
            }
            if (originUri.UserInfo.Length > 0)
            {
                errors.Add($"CORS origin '{origin}' must not contain user information.");
                continue;
            }
            if (originUri.Query.Length > 0)
            {
                errors.Add($"CORS origin '{origin}' must not contain a query component.");
                continue;
            }
            if (originUri.Fragment.Length > 0)
            {
                errors.Add($"CORS origin '{origin}' must not contain a fragment component.");
                continue;
            }
            // An origin is scheme + host + port only; path must be empty or just "/".
            if (originUri.AbsolutePath.Length > 1)
            {
                errors.Add($"CORS origin '{origin}' must not contain a path component. Use 'scheme://host[:port]' only.");
                continue;
            }

            // CORS origins must use HTTPS in production. AllowInsecureIssuer permits HTTP only
            // for loopback addresses (local development). This mirrors the issuer scheme rules.
            var isHttpsOrigin = string.Equals(originUri.Scheme, Uri.UriSchemeHttps, StringComparison.OrdinalIgnoreCase);
            var isHttpOrigin = string.Equals(originUri.Scheme, Uri.UriSchemeHttp, StringComparison.OrdinalIgnoreCase);

            if (!isHttpsOrigin && !(isHttpOrigin && options.AllowInsecureIssuer))
            {
                errors.Add(
                    $"CORS origin '{origin}' uses scheme '{originUri.Scheme}'. " +
                    "Only 'https' is permitted in production. Set AllowInsecureIssuer = true to " +
                    "permit HTTP CORS origins for local development and testing only.");
                continue;
            }

            if (isHttpOrigin && options.AllowInsecureIssuer && !LoopbackHelper.IsLoopbackHost(originUri.Host))
            {
                errors.Add(
                    $"CORS origin '{origin}' uses HTTP for a non-loopback host. " +
                    "AllowInsecureIssuer only permits HTTP loopback CORS origins for local development and testing.");
            }
        }

        // Validate SecurityHeaders enum values at startup so an out-of-range cast produces a startup
        // failure consistent with all other misconfiguration, rather than a 500 at request time.
        if (!Enum.IsDefined(options.SecurityHeaders.ReferrerPolicy))
        {
            errors.Add(
                $"AuthorizationServerOptions.SecurityHeaders.ReferrerPolicy value " +
                $"'{(int)options.SecurityHeaders.ReferrerPolicy}' is not a valid {nameof(ReferrerPolicy)} enum member.");
        }

        if (!Enum.IsDefined(options.SecurityHeaders.CrossOriginResourcePolicy))
        {
            errors.Add(
                $"AuthorizationServerOptions.SecurityHeaders.CrossOriginResourcePolicy value " +
                $"'{(int)options.SecurityHeaders.CrossOriginResourcePolicy}' is not a valid {nameof(CrossOriginResourcePolicy)} enum member.");
        }

        // Validate AuthorizationEndpoint group
        if (options.AuthorizationEndpoint.CodeChallengeMethodsSupported is { Count: 0 })
        {
            errors.Add(
                "AuthorizationServerOptions.AuthorizationEndpoint.CodeChallengeMethodsSupported " +
                "must not be an empty collection. Either set it to null to omit the field from the " +
                "discovery document, or provide at least one value (e.g. CodeChallengeMethod.S256). " +
                "See RFC 7636 §4.3 and RFC 8414 §2.");
        }

        // Validate endpoint URI overrides — RFC 8414 §2 requires all metadata URLs to use HTTPS.
        static ValidateOptionsResult? ValidateEndpointUri(
            string propertyName,
            string? value,
            bool allowInsecure,
            Uri issuerUri,
            string issuerValue,
            bool rejectQuery = false,
            bool rejectFragment = false)
        {
            if (value is null) return null;

            if (!Uri.TryCreate(value, UriKind.Absolute, out var uri))
                return ValidateOptionsResult.Fail(
                    $"AuthorizationServerOptions.{propertyName} '{value}' is not a valid absolute URI.");

            if (uri.UserInfo.Length > 0)
                return ValidateOptionsResult.Fail(
                    $"AuthorizationServerOptions.{propertyName} '{value}' must not contain user information.");

            var isHttps = string.Equals(uri.Scheme, Uri.UriSchemeHttps, StringComparison.OrdinalIgnoreCase);
            var isHttp = string.Equals(uri.Scheme, Uri.UriSchemeHttp, StringComparison.OrdinalIgnoreCase);

            if (!isHttps && !(isHttp && allowInsecure))
                return ValidateOptionsResult.Fail(
                    $"AuthorizationServerOptions.{propertyName} '{value}' must use HTTPS. " +
                    "Set AllowInsecureIssuer = true to permit HTTP loopback endpoints for local development only.");

            if (isHttp && allowInsecure && !LoopbackHelper.IsLoopbackHost(uri.Host))
                return ValidateOptionsResult.Fail(
                    $"AuthorizationServerOptions.{propertyName} '{value}' uses HTTP for a non-loopback host. " +
                    "AllowInsecureIssuer only permits HTTP loopback endpoints for local development and testing.");

            if (!HasSameAuthority(uri, issuerUri))
                return ValidateOptionsResult.Fail(
                    $"AuthorizationServerOptions.{propertyName} '{value}' must use the same authority as " +
                    $"AuthorizationServerOptions.Issuer '{issuerValue}'.");

            if (rejectQuery && uri.Query.Length > 0)
                return ValidateOptionsResult.Fail(
                    $"AuthorizationServerOptions.{propertyName} '{value}' must not contain a query component ('?').");

            if (rejectFragment && uri.Fragment.Length > 0)
                return ValidateOptionsResult.Fail(
                    $"AuthorizationServerOptions.{propertyName} '{value}' must not contain a fragment component ('#').");

            return null;
        }

        // RFC 6749 §3.1 and §3.2: authorization and token endpoint URIs MUST NOT include a fragment.
        // Query components are explicitly permitted on the authorization endpoint (RFC 6749 §3.1)
        // and are not prohibited on the token endpoint.
        if (ValidateEndpointUri(
                nameof(options.AuthorizationEndpoint.Uri),
                options.AuthorizationEndpoint.Uri,
                options.AllowInsecureIssuer,
                uri,
                options.Issuer!,
                rejectFragment: true) is { } aeError)
            errors.Add(aeError.FailureMessage!);

        if (ValidateEndpointUri(
                nameof(options.TokenEndpoint.Uri),
                options.TokenEndpoint.Uri,
                options.AllowInsecureIssuer,
                uri,
                options.Issuer!,
                rejectFragment: true) is { } teError)
            errors.Add(teError.FailureMessage!);

        if (ValidateEndpointUri(
                nameof(options.JwksEndpoint.Uri),
                options.JwksEndpoint.Uri,
                options.AllowInsecureIssuer,
                uri,
                options.Issuer!,
                rejectQuery: true,
                rejectFragment: true) is { } jwksError)
            errors.Add(jwksError.FailureMessage!);

        return errors.Count > 0 ? ValidateOptionsResult.Fail(errors) : ValidateOptionsResult.Success;
    }

    private static bool HasSameAuthority(Uri endpointUri, Uri issuerUri)
        => Uri.Compare(
            endpointUri,
            issuerUri,
            UriComponents.SchemeAndServer,
            UriFormat.SafeUnescaped,
            StringComparison.OrdinalIgnoreCase) == 0;

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
