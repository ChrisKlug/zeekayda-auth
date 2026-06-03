using Microsoft.Extensions.Options;
using ZeeKayDa.Auth;
using ZeeKayDa.Auth.Scopes;

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
    private const string TokenEndpointAuthMethodsRequiredMessage =
        "AuthorizationServerOptions.TokenEndpoint.AuthMethodsSupported must not be null or empty. " +
        "Specify at least one client authentication method (e.g., TokenEndpointAuthMethod.ClientSecretBasic). " +
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

    private readonly IScopeRepository _scopeRepository;

    public AuthorizationServerOptionsValidator(IScopeRepository scopeRepository)
    {
        _scopeRepository = scopeRepository;
    }

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

        if (uri.UserInfo.Length > 0)
        {
            return ValidateOptionsResult.Fail(
                $"AuthorizationServerOptions.Issuer '{options.Issuer}' must not contain user information.");
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
        // AllowInsecureIssuer permits only HTTP loopback issuers for local development.
        var isHttps = string.Equals(uri.Scheme, Uri.UriSchemeHttps, StringComparison.OrdinalIgnoreCase);
        var isHttp = string.Equals(uri.Scheme, Uri.UriSchemeHttp, StringComparison.OrdinalIgnoreCase);

        if (!isHttps && !(isHttp && options.AllowInsecureIssuer))
        {
            return ValidateOptionsResult.Fail(
                $"AuthorizationServerOptions.Issuer '{options.Issuer}' uses an unsupported scheme '{uri.Scheme}'. " +
                "Only 'https' is permitted in production. " +
                "Set AllowInsecureIssuer = true to permit 'http' loopback issuers for local development and testing only.");
        }

        if (isHttp && options.AllowInsecureIssuer && !uri.IsLoopback)
        {
            return ValidateOptionsResult.Fail(
                $"AuthorizationServerOptions.Issuer '{options.Issuer}' uses HTTP for a non-loopback host. " +
                "AllowInsecureIssuer only permits HTTP loopback issuers for local development and testing.");
        }

        // Validate Response group
        if (options.Response.TypesSupported is null)
        {
            return ValidateOptionsResult.Fail(
                "AuthorizationServerOptions.Response.TypesSupported must not be null.");
        }

        if (options.Response.TypesSupported.Count == 0)
        {
            return ValidateOptionsResult.Fail(
                "AuthorizationServerOptions.Response.TypesSupported must contain at least one value.");
        }

        if (options.Response.ModesSupported is null)
        {
            return ValidateOptionsResult.Fail(
                "AuthorizationServerOptions.Response.ModesSupported must not be null.");
        }

        // Validate root-level GrantTypesSupported
        if (options.GrantTypesSupported is null)
        {
            return ValidateOptionsResult.Fail(
                "AuthorizationServerOptions.GrantTypesSupported must not be null.");
        }

        // Validate Token group
        if (options.TokenEndpoint.AuthMethodsSupported is null)
        {
            return ValidateOptionsResult.Fail(TokenEndpointAuthMethodsRequiredMessage);
        }

        // ADR 0002 §4: TokenEndpoint.AuthMethodsSupported must not be null or empty
        if (options.TokenEndpoint.AuthMethodsSupported.Count == 0)
        {
            return ValidateOptionsResult.Fail(TokenEndpointAuthMethodsRequiredMessage);
        }

        // TODO(ADR-0002): Keep this rule bound to the grouped TokenEndpoint.AuthMethodsSupported
        // shape and do not regress to legacy flat TokenEndpointAuthMethodsSupported references.
        // ADR 0002 §4: If client_credentials grant is supported, must have at least one non-None auth method
        if (options.GrantTypesSupported.Contains(GrantType.ClientCredentials) &&
            options.TokenEndpoint.AuthMethodsSupported.All(m => m == TokenEndpointAuthMethod.None))
        {
            return ValidateOptionsResult.Fail(ClientCredentialsRequiresNonNoneTokenAuthMethodMessage);
        }

        // Validate IdToken group
        if (options.IdToken.SigningAlgValuesSupported is null)
        {
            return ValidateOptionsResult.Fail(
                "AuthorizationServerOptions.IdToken.SigningAlgValuesSupported must not be null.");
        }

        if (options.IdToken.SigningAlgValuesSupported.Count == 0)
        {
            return ValidateOptionsResult.Fail(
                "AuthorizationServerOptions.IdToken.SigningAlgValuesSupported must contain at least one value.");
        }

        // Validate Discovery group
        if (options.DiscoveryDocument.CacheMaxAgeSeconds < 0)
        {
            return ValidateOptionsResult.Fail(
                "AuthorizationServerOptions.DiscoveryDocument.CacheMaxAgeSeconds must not be negative.");
        }

        // Validate endpoint URI overrides — RFC 8414 §2 requires all metadata URLs to use HTTPS.
        static ValidateOptionsResult? ValidateEndpointUri(string propertyName, string? value, bool allowInsecure, bool rejectQuery = false, bool rejectFragment = false)
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

            if (isHttp && allowInsecure && !uri.IsLoopback)
                return ValidateOptionsResult.Fail(
                    $"AuthorizationServerOptions.{propertyName} '{value}' uses HTTP for a non-loopback host. " +
                    "AllowInsecureIssuer only permits HTTP loopback endpoints for local development and testing.");

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
        if (ValidateEndpointUri(nameof(options.AuthorizationEndpoint.Uri), options.AuthorizationEndpoint.Uri, options.AllowInsecureIssuer, rejectFragment: true) is { } aeError)
            return aeError;

        if (ValidateEndpointUri(nameof(options.TokenEndpoint.Uri), options.TokenEndpoint.Uri, options.AllowInsecureIssuer, rejectFragment: true) is { } teError)
            return teError;

        if (ValidateEndpointUri(nameof(options.JwksEndpoint.Uri), options.JwksEndpoint.Uri, options.AllowInsecureIssuer, rejectQuery: true, rejectFragment: true) is { } jwksError)
            return jwksError;

        // IValidateOptions<T> is synchronous; block here so ValidateOnStart can fail fast.
        var scopes = _scopeRepository.GetScopesAsync().GetAwaiter().GetResult();
        if (!scopes.Any(scope => string.Equals(scope.Name, StandardScopes.OpenId.Name, StringComparison.Ordinal)))
        {
            return ValidateOptionsResult.Fail(
                $"IScopeRepository must include the '{StandardScopes.OpenId.Name}' scope. " +
                $"Every OpenID Connect authorization request is required to include '{StandardScopes.OpenId.Name}'.");
        }

        return ValidateOptionsResult.Success;
    }
}
