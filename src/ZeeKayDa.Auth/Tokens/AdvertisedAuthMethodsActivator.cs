using Microsoft.Extensions.DependencyInjection;
using ZeeKayDa.Auth.StartupVerification;

namespace ZeeKayDa.Auth.Tokens;

/// <summary>
/// Checks at startup that the advertised token endpoint auth methods are what the filter meant and
/// accept some client. An activator because resolving them builds the host's authenticators.
/// </summary>
internal sealed class AdvertisedAuthMethodsActivator(IServiceProvider services) : IStartupActivator
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

    private static void VerifyAdvertisedSet(StartupVerificationContext context, AdvertisedAuthMethods advertised)
    {
        if (advertised.Methods.Count == 0)
        {
            context.AddFailure(
                "token_endpoint.advertised_auth_methods.none_performable",
                "TokenEndpoint.AdvertisedAuthMethods names no method the server performs, so the token " +
                "endpoint would accept no client. Name a method a registered client authenticator " +
                $"performs, or '{TokenEndpointAuthMethods.None}', or set the filter to null.");
        }
    }
}
