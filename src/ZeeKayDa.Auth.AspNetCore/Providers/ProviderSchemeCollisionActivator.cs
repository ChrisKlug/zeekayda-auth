using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;
using ZeeKayDa.Auth.AspNetCore.Endpoints;
using ZeeKayDa.Auth.AspNetCore.Interaction;
using ZeeKayDa.Auth.StartupVerification;

namespace ZeeKayDa.Auth.AspNetCore.Providers;

/// <summary>
/// Fails startup when a provider's name is also in the host's final scheme map, or a host remote
/// scheme's callback path is a provider's route: the middleware would serve that callback itself.
/// </summary>
/// <remarks>
/// An activator: building the resolved map and the host schemes' options runs host code.
/// </remarks>
internal sealed class ProviderSchemeCollisionActivator(
    ProviderRegistry registry,
    IOptions<AuthorizationServerOptions> options,
    IServiceProvider services,
    IAuthenticationSchemeProvider? schemeProvider = null) : IStartupActivator
{
    /// <inheritdoc/>
    public string Name => "ProviderSchemeCollisions";

    /// <inheritdoc/>
    public async Task VerifyAsync(StartupVerificationContext context, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(context);

        if (registry.Count == 0)
            return;

        if (schemeProvider is null)
            return;

        var hostSchemes = (await schemeProvider.GetAllSchemesAsync().ConfigureAwait(false))
            .Where(scheme => !ZeeKayDaCookies.SchemeNames.Contains(scheme.Name, StringComparer.Ordinal))
            .ToArray();

        var byName = hostSchemes
            .Select(scheme => scheme.Name)
            .ToHashSet(StringComparer.OrdinalIgnoreCase);
        foreach (var registration in registry.Registrations.Where(registration => byName.Contains(registration.Name)))
        {
            cancellationToken.ThrowIfCancellationRequested();

            context.AddFailure(
                "provider.scheme_visible_to_host",
                $"The provider '{registration.Name}' is also registered as an authentication scheme of " +
                "the host, outside WithProviders. A provider scheme must exist only in the framework's " +
                "scheme map, or the host could challenge it and the authentication middleware would " +
                "serve its callback. Remove the host's registration, or rename one of the two.");
        }

        // A name collision is already reported; its callback path would say nothing new.
        var providerNames = registry.Registrations
            .Select(registration => registration.Name)
            .ToHashSet(StringComparer.OrdinalIgnoreCase);
        foreach (var scheme in hostSchemes.Where(scheme => !providerNames.Contains(scheme.Name)))
        {
            cancellationToken.ThrowIfCancellationRequested();
            ReportCallbackPathCollision(context, scheme);
        }
    }

    private void ReportCallbackPathCollision(StartupVerificationContext context, AuthenticationScheme scheme)
    {
        if (HandlerOptions.TypeOf(scheme.HandlerType) is not { } optionsType
            || !typeof(RemoteAuthenticationOptions).IsAssignableFrom(optionsType))
        {
            return;
        }

        PathString callbackPath;
        try
        {
            callbackPath = ((RemoteAuthenticationOptions)HandlerOptions.Resolve(services, optionsType, scheme.Name))
                .CallbackPath;
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            // The host's scheme failing its own configuration surfaces on the host's own path.
            return;
        }

        var issuerUri = EndpointRouteHelper.GetIssuerUri(options);

        foreach (var registration in registry.Registrations
            .Where(registration => ProviderCallbackRoute.For(issuerUri, registration.Name) == callbackPath))
        {
            context.AddFailure(
                "provider.callback_path_taken",
                $"The host's authentication scheme '{scheme.Name}' has the callback path " +
                $"'{callbackPath}', which is the callback route of provider '{registration.Name}'. " +
                "The authentication middleware would claim the provider's callback before the " +
                "framework's endpoint saw it. Change the host scheme's CallbackPath.");
        }
    }
}
