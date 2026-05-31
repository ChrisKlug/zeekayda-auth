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

        // The OIDC specification requires the issuer to be an HTTPS URI in production.
        // An explicit opt-in flag permits HTTP issuers for local development and testing only.
        if (!string.Equals(uri.Scheme, Uri.UriSchemeHttps, StringComparison.OrdinalIgnoreCase)
            && !options.AllowInsecureIssuer)
        {
            return ValidateOptionsResult.Fail(
                $"AuthorizationServerOptions.Issuer '{options.Issuer}' must use HTTPS. " +
                "Set AllowInsecureIssuer = true only for local development and testing — " +
                "never in production.");
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

        return ValidateOptionsResult.Success;
    }
}
