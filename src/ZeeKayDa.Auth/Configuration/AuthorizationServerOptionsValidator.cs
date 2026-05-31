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
/// silently at the first request.
/// </remarks>
internal sealed class AuthorizationServerOptionsValidator : IValidateOptions<AuthorizationServerOptions>
{
    /// <inheritdoc/>
    public ValidateOptionsResult Validate(string? name, AuthorizationServerOptions options)
    {
        if (string.IsNullOrWhiteSpace(options.Issuer))
        {
            return ValidateOptionsResult.Fail(
                "AuthorizationServerOptions.Issuer must be set to a non-empty value.");
        }

        if (!Uri.TryCreate(options.Issuer, UriKind.Absolute, out var uri))
        {
            return ValidateOptionsResult.Fail(
                $"AuthorizationServerOptions.Issuer '{options.Issuer}' is not a valid absolute URI.");
        }

        // RFC 8414 §2 and OIDC Discovery 1.0 §4.1 prohibit query strings in the issuer.
        if (uri.Query.Length > 0)
        {
            return ValidateOptionsResult.Fail(
                $"AuthorizationServerOptions.Issuer '{options.Issuer}' must not contain a query component ('?').");
        }

        // RFC 8414 §2 and OIDC Discovery 1.0 §4.1 prohibit fragment components in the issuer.
        if (uri.Fragment.Length > 0)
        {
            return ValidateOptionsResult.Fail(
                $"AuthorizationServerOptions.Issuer '{options.Issuer}' must not contain a fragment component ('#').");
        }

        // OIDC Discovery 1.0 §4.3 and RFC 8414 §3.3 require the published issuer to be
        // byte-identical to the URL used to derive the discovery address. A trailing slash
        // on a path-bearing issuer creates an asymmetry because the route is registered
        // without the slash but the document preserves it verbatim.
        if (uri.AbsolutePath.EndsWith('/') && uri.AbsolutePath.Length > 1)
        {
            return ValidateOptionsResult.Fail(
                $"AuthorizationServerOptions.Issuer '{options.Issuer}' must not have a trailing slash. " +
                "Use 'https://auth.example.com/tenant1' rather than 'https://auth.example.com/tenant1/'. " +
                "OIDC Discovery 1.0 §4.3 requires the published issuer to be identical to the URL " +
                "used to derive the discovery address.");
        }

        // The OIDC specification requires the issuer to be an HTTPS URI in production.
        // AllowInsecureIssuer permits only http (not arbitrary schemes) for local development.
        var isHttps = string.Equals(uri.Scheme, Uri.UriSchemeHttps, StringComparison.OrdinalIgnoreCase);
        var isHttp = string.Equals(uri.Scheme, Uri.UriSchemeHttp, StringComparison.OrdinalIgnoreCase);

        if (!isHttps && !(isHttp && options.AllowInsecureIssuer))
        {
            return ValidateOptionsResult.Fail(
                $"AuthorizationServerOptions.Issuer '{options.Issuer}' uses an unsupported scheme '{uri.Scheme}'. " +
                "Only 'https' is permitted in production. " +
                "Set AllowInsecureIssuer = true to permit 'http' for local development and testing only.");
        }

        if (options.ResponseTypesSupported is null)
        {
            return ValidateOptionsResult.Fail(
                "AuthorizationServerOptions.ResponseTypesSupported must not be null.");
        }

        if (options.ResponseTypesSupported.Count == 0)
        {
            return ValidateOptionsResult.Fail(
                "AuthorizationServerOptions.ResponseTypesSupported must contain at least one value.");
        }

        if (options.ResponseModesSupported is null)
        {
            return ValidateOptionsResult.Fail(
                "AuthorizationServerOptions.ResponseModesSupported must not be null.");
        }

        if (options.GrantTypesSupported is null)
        {
            return ValidateOptionsResult.Fail(
                "AuthorizationServerOptions.GrantTypesSupported must not be null.");
        }

        if (options.TokenEndpointAuthMethodsSupported is null)
        {
            return ValidateOptionsResult.Fail(
                "AuthorizationServerOptions.TokenEndpointAuthMethodsSupported must not be null.");
        }

        if (options.IdTokenSigningAlgValuesSupported is null)
        {
            return ValidateOptionsResult.Fail(
                "AuthorizationServerOptions.IdTokenSigningAlgValuesSupported must not be null.");
        }

        if (options.IdTokenSigningAlgValuesSupported.Count == 0)
        {
            return ValidateOptionsResult.Fail(
                "AuthorizationServerOptions.IdTokenSigningAlgValuesSupported must contain at least one value.");
        }

        if (options.DiscoveryDocumentCacheMaxAgeSeconds < 0)
        {
            return ValidateOptionsResult.Fail(
                "AuthorizationServerOptions.DiscoveryDocumentCacheMaxAgeSeconds must not be negative.");
        }

        // Validate endpoint URI overrides — RFC 8414 §2 requires all metadata URLs to use HTTPS.
        static ValidateOptionsResult? ValidateEndpointUri(string propertyName, string? value, bool allowInsecure, bool rejectQuery = false, bool rejectFragment = false)
        {
            if (value is null) return null;

            if (!Uri.TryCreate(value, UriKind.Absolute, out var uri))
                return ValidateOptionsResult.Fail(
                    $"AuthorizationServerOptions.{propertyName} '{value}' is not a valid absolute URI.");

            var isHttps = string.Equals(uri.Scheme, Uri.UriSchemeHttps, StringComparison.OrdinalIgnoreCase);
            var isHttp = string.Equals(uri.Scheme, Uri.UriSchemeHttp, StringComparison.OrdinalIgnoreCase);

            if (!isHttps && !(isHttp && allowInsecure))
                return ValidateOptionsResult.Fail(
                    $"AuthorizationServerOptions.{propertyName} '{value}' must use HTTPS. " +
                    "Set AllowInsecureIssuer = true to permit HTTP for local development only.");

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
        if (ValidateEndpointUri(nameof(options.AuthorizationEndpoint), options.AuthorizationEndpoint, options.AllowInsecureIssuer, rejectFragment: true) is { } aeError)
            return aeError;

        if (ValidateEndpointUri(nameof(options.TokenEndpoint), options.TokenEndpoint, options.AllowInsecureIssuer, rejectFragment: true) is { } teError)
            return teError;

        if (ValidateEndpointUri(nameof(options.JwksUri), options.JwksUri, options.AllowInsecureIssuer, rejectQuery: true, rejectFragment: true) is { } jwksError)
            return jwksError;

        return ValidateOptionsResult.Success;
    }
}
