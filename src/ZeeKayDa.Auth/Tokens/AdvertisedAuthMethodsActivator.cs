using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;
using ZeeKayDa.Auth.StartupVerification;

namespace ZeeKayDa.Auth.Tokens;

/// <summary>
/// Startup check that the token endpoint auth methods the server advertises (<see cref="AdvertisedAuthMethods"/>)
/// are what the operator's filter meant and can serve the configured grants.
/// </summary>
/// <remarks>
/// An activator rather than a verifier, by the mechanical rule: resolving the advertised methods builds
/// every registered client authenticator, and those are the host's own. Resolved in
/// <see cref="VerifyAsync"/>, not injected, so a construction failure is reported against a check.
/// Registered by the core, so a host without the HTTP layer is held to the same rules.
/// </remarks>
internal sealed class AdvertisedAuthMethodsActivator(
    IOptions<AuthorizationServerOptions> options,
    IServiceProvider services) : IStartupActivator
{
    /// <inheritdoc/>
    public string Name => "AdvertisedAuthMethods";

    /// <inheritdoc/>
    public Task VerifyAsync(StartupVerificationContext context, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(context);

        var advertised = services.GetRequiredService<AdvertisedAuthMethods>();

        VerifyFilterEntries(context, advertised);
        VerifyAdvertisedSet(context, advertised);

        return Task.CompletedTask;
    }

    /// <summary>
    /// A filter entry the server does not perform is a no-op, unless it is a performed method in other
    /// casing: then it is a typo withholding the method it meant to keep.
    /// </summary>
    private static void VerifyFilterEntries(StartupVerificationContext context, AdvertisedAuthMethods advertised)
    {
        var unperformable = new List<string>();

        foreach (var entry in advertised.Unperformable)
        {
            var meant = advertised.Performable.FirstOrDefault(
                method => string.Equals(method, entry, StringComparison.OrdinalIgnoreCase));

            if (meant is null)
            {
                unperformable.Add(entry);
                continue;
            }

            context.AddFailure(
                "token_endpoint.advertised_auth_methods.casing",
                $"TokenEndpoint.AdvertisedAuthMethods names '{entry}', which differs only in casing from " +
                $"'{meant}'. Method names compare exactly — use the constants in {nameof(TokenEndpointAuthMethods)}.");
        }

        if (unperformable.Count > 0)
        {
            context.AddWarning(
                "token_endpoint.advertised_auth_methods.unperformable",
                "TokenEndpoint.AdvertisedAuthMethods names {UnperformableMethods}, which no registered " +
                "client authenticator performs. Those entries have no effect — the server advertises " +
                "only methods it can perform: {AdvertisedMethods}.",
                string.Join(", ", unperformable),
                string.Join(", ", advertised.Methods));
        }
    }

    private void VerifyAdvertisedSet(StartupVerificationContext context, AdvertisedAuthMethods advertised)
    {
        if (advertised.Methods.Count == 0)
        {
            context.AddFailure(
                "token_endpoint.advertised_auth_methods.none_performable",
                "TokenEndpoint.AdvertisedAuthMethods names no method the server performs, so the token " +
                "endpoint would accept no client. Name a method a registered client authenticator " +
                $"performs, or '{TokenEndpointAuthMethods.None}', or set the filter to null.");
        }
        else if (options.Value.GrantTypesSupported.Contains(GrantType.ClientCredentials)
            && TokenEndpointAuthMethodRules.AllowsOnlyNone(advertised.Methods))
        {
            // The client credentials grant requires client authentication (RFC 6749 §4.4, RFC 9700 §2.6).
            context.AddFailure(
                "token_endpoint.advertised_auth_methods.only_none_with_client_credentials",
                "GrantTypesSupported includes 'client_credentials', which requires confidential clients, " +
                "but the only advertised token endpoint auth method is 'none'. Register a client " +
                "authenticator (AddZeeKayDaAuth registers the client-secret one), or stop " +
                "TokenEndpoint.AdvertisedAuthMethods withholding its methods. " +
                "See RFC 6749 §4.4 and OAuth 2.0 Security BCP §2.6 (RFC 9700).");
        }
    }
}
