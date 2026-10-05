using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;
using ZeeKayDa.Auth;
using ZeeKayDa.Auth.StartupVerification;
using ZeeKayDa.Auth.Tokens;

namespace ZeeKayDa.Auth.AspNetCore.ClientAuthentication;

/// <summary>
/// Startup check that no registered <see cref="IClientAuthenticator"/> misconfigures the reserved
/// <c>none</c> method or overlaps with another, and that the token endpoint auth methods derived
/// from them (<see cref="AdvertisedAuthMethods"/>) can serve the configured grants.
/// </summary>
/// <remarks>
/// An activator rather than a verifier, by the mechanical rule: it constructs every registered
/// authenticator, and those are the host's own. It is deliberately not an
/// <c>IValidateOptions&lt;AuthorizationServerOptions&gt;</c>, which would make the first read of
/// the server options construct part of the service graph. The authenticators are resolved in
/// <see cref="VerifyAsync"/>, not injected, so one that fails to construct — the client-secret
/// authenticator builds every registered hasher — is reported against this check while the rest of
/// the phase still runs.
/// </remarks>
internal sealed class ClientAuthenticatorActivator(
    IOptions<AuthorizationServerOptions> options,
    IServiceProvider services) : IStartupActivator
{
    /// <inheritdoc/>
    public string Name => "ClientAuthenticator";

    /// <inheritdoc/>
    public Task VerifyAsync(StartupVerificationContext context, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(context);

        var authenticators = services.GetServices<IClientAuthenticator>();

        var declaringTypeByMethod = new Dictionary<string, string>(StringComparer.Ordinal);

        foreach (var authenticator in authenticators)
        {
            var typeName = authenticator.GetType().Name;
            foreach (var method in authenticator.AuthenticationMethods)
                CheckDeclaredMethod(context, declaringTypeByMethod, typeName, method);
        }

        VerifyAdvertisedMethods(context, services.GetRequiredService<AdvertisedAuthMethods>());

        return Task.CompletedTask;
    }

    private void VerifyAdvertisedMethods(StartupVerificationContext context, AdvertisedAuthMethods advertised)
    {
        if (advertised.Unperformable.Count > 0)
        {
            // A no-op rather than a misstatement: the advertised set is an intersection, so a method
            // no authenticator performs is never advertised whatever the filter says.
            context.AddWarning(
                "token_endpoint.advertised_auth_methods.unperformable",
                "TokenEndpoint.AdvertisedAuthMethods names {UnperformableMethods}, which no registered " +
                "IClientAuthenticator performs. Those entries have no effect — the server advertises " +
                "only methods it can perform: {AdvertisedMethods}.",
                string.Join(", ", advertised.Unperformable),
                string.Join(", ", advertised.Methods));
        }

        if (advertised.Methods.Count == 0)
        {
            context.AddFailure(
                "token_endpoint.advertised_auth_methods.none_performable",
                "TokenEndpoint.AdvertisedAuthMethods names no method the server performs, so the token " +
                "endpoint would accept no client. Name a method a registered IClientAuthenticator " +
                $"performs, or '{TokenEndpointAuthMethods.None}', or set the filter to null.");
        }
        else if (options.Value.GrantTypesSupported.Contains(GrantType.ClientCredentials)
            && TokenEndpointAuthMethodRules.AllowsOnlyNone(advertised.Methods))
        {
            // The client credentials grant requires client authentication (RFC 6749 §4.4, RFC 9700 §2.6).
            context.AddFailure(
                "token_endpoint.advertised_auth_methods.only_none_with_client_credentials",
                "GrantTypesSupported includes 'client_credentials', which requires confidential clients, " +
                "but the only advertised token endpoint auth method is 'none'. Register an " +
                "IClientAuthenticator, or stop TokenEndpoint.AdvertisedAuthMethods withholding its methods. " +
                "See RFC 6749 §4.4 and OAuth 2.0 Security BCP §2.6 (RFC 9700).");
        }
    }

    private static void CheckDeclaredMethod(
        StartupVerificationContext context,
        Dictionary<string, string> declaringTypeByMethod,
        string typeName,
        string method)
    {
        // Reject leading/trailing whitespace before any other check: " none" or
        // "client_secret_basic " would pass the ordinal equality checks below but fail
        // silently at runtime because the runtime comparisons are also ordinal.
        if (method != method.Trim())
        {
            context.AddFailure(
                "authenticators.method_whitespace",
                $"{typeName} declares auth method '{method}' which has leading or trailing " +
                "whitespace. Method strings must match exactly — use the constants in " +
                $"{nameof(TokenEndpointAuthMethods)}.");
            return;
        }

        // Non-canonical casing (e.g. "Client_Secret_Basic") passes the ordinal overlap
        // check below but still collides at runtime with the built-in authenticator's
        // CanHandle, producing a silent invalid_client.
        if (_canonicalMethodNames.TryGetValue(method, out var canonical) &&
            !string.Equals(method, canonical, StringComparison.Ordinal))
        {
            context.AddFailure(
                "authenticators.method_casing",
                $"{typeName} declares auth method '{method}' which differs from the canonical " +
                $"form '{canonical}' in casing. Use the exact constant from " +
                $"{nameof(TokenEndpointAuthMethods)} to avoid silent runtime mismatches.");
            return;
        }

        if (string.Equals(method, TokenEndpointAuthMethods.None, StringComparison.Ordinal))
        {
            context.AddFailure(
                "authenticators.none_declared",
                $"{typeName} declares '{TokenEndpointAuthMethods.None}' in AuthenticationMethods. " +
                $"'{TokenEndpointAuthMethods.None}' is reserved for the CompositeClientAuthenticator " +
                "fallback and must not be declared by any IClientAuthenticator.");
            return;
        }

        if (declaringTypeByMethod.TryGetValue(method, out var existingType))
        {
            context.AddFailure(
                "authenticators.method_overlap",
                $"Both {existingType} and {typeName} declare auth method '{method}'. " +
                "Each method must be handled by exactly one IClientAuthenticator.");
        }
        else
        {
            declaringTypeByMethod[method] = typeName;
        }
    }

    // Case-insensitive map of framework-handled method strings to their canonical form.
    private static readonly IReadOnlyDictionary<string, string> _canonicalMethodNames =
        new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
        {
            [TokenEndpointAuthMethods.ClientSecretBasic] = TokenEndpointAuthMethods.ClientSecretBasic,
            [TokenEndpointAuthMethods.ClientSecretPost] = TokenEndpointAuthMethods.ClientSecretPost,
            [TokenEndpointAuthMethods.None] = TokenEndpointAuthMethods.None,
        };
}
