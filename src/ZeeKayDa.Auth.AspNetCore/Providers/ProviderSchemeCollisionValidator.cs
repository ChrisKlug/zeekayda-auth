using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;
using ZeeKayDa.Auth.AspNetCore.Endpoints;
using ZeeKayDa.Auth.AspNetCore.Interaction;

namespace ZeeKayDa.Auth.AspNetCore.Providers;

/// <summary>
/// Fails startup when a registered provider's name also exists in the host's final scheme map —
/// registered before or after <c>WithProviders</c>, by the host or a library — or when a host
/// remote scheme's callback path is a provider's callback route.
/// </summary>
/// <remarks>
/// <para>
/// Provider schemes are invisible to the host by construction: not enumerable, not challengeable
/// by name, never dispatched by the authentication middleware. A host scheme with the same name
/// would reintroduce exactly that — the middleware would serve its callback and the host could
/// challenge it — and a host remote scheme with the same callback path would have the middleware
/// claim the provider's callback before the framework's endpoint saw it. Both are refused rather
/// than tolerated.
/// </para>
/// <para>
/// This reads the resolved <see cref="IAuthenticationSchemeProvider"/> and the host schemes'
/// options, not the registration window, so it sees the map as the application will run it. An
/// activator rather than a verifier, by the mechanical rule: building that map and resolving
/// those options runs the host's own configuration code.
/// </para>
/// </remarks>
internal sealed class ProviderSchemeCollisionValidator : IStartupActivator
{
    private readonly ProviderRegistry _registry;
    private readonly IOptions<AuthorizationServerOptions> _options;

    public ProviderSchemeCollisionValidator(ProviderRegistry registry, IOptions<AuthorizationServerOptions> options)
    {
        ArgumentNullException.ThrowIfNull(registry);
        ArgumentNullException.ThrowIfNull(options);

        _registry = registry;
        _options = options;
    }

    /// <inheritdoc/>
    public string Name => "ProviderSchemeCollisions";

    /// <inheritdoc/>
    public async ValueTask VerifyAsync(
        StartupVerificationContext context,
        IServiceProvider scopedServices,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(context);
        ArgumentNullException.ThrowIfNull(scopedServices);

        if (_registry.Count == 0)
            return;

        var schemeProvider = scopedServices.GetService<IAuthenticationSchemeProvider>();
        if (schemeProvider is null)
            return;

        var hostSchemes = (await schemeProvider.GetAllSchemesAsync().ConfigureAwait(false))
            .Where(scheme => !ZeeKayDaCookies.SchemeNames.Contains(scheme.Name, StringComparer.Ordinal))
            .ToArray();

        var byName = hostSchemes
            .Select(scheme => scheme.Name)
            .ToHashSet(StringComparer.OrdinalIgnoreCase);
        foreach (var registration in _registry.Registrations.Where(registration => byName.Contains(registration.Name)))
        {
            cancellationToken.ThrowIfCancellationRequested();

            context.AddFailure(
                "provider.scheme_visible_to_host",
                $"The provider '{registration.Name}' is also registered as an authentication scheme of " +
                "the host, outside WithProviders. A provider scheme must exist only in the framework's " +
                "scheme map, or the host could challenge it and the authentication middleware would " +
                "serve its callback. Remove the host's registration, or rename one of the two.");
        }

        // A scheme that collides by name is pinned to the provider's route as well; reporting it
        // twice would say nothing new.
        var providerNames = _registry.Registrations
            .Select(registration => registration.Name)
            .ToHashSet(StringComparer.OrdinalIgnoreCase);
        foreach (var scheme in hostSchemes.Where(scheme => !providerNames.Contains(scheme.Name)))
        {
            cancellationToken.ThrowIfCancellationRequested();
            ReportCallbackPathCollision(context, scopedServices, scheme);
        }
    }

    private void ReportCallbackPathCollision(
        StartupVerificationContext context,
        IServiceProvider scopedServices,
        AuthenticationScheme scheme)
    {
        if (HandlerOptions.TypeOf(scheme.HandlerType) is not { } optionsType
            || !typeof(RemoteAuthenticationOptions).IsAssignableFrom(optionsType))
        {
            return;
        }

        PathString callbackPath;
        try
        {
            callbackPath = ((RemoteAuthenticationOptions)HandlerOptions.Resolve(scopedServices, optionsType, scheme.Name))
                .CallbackPath;
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            // The host's own scheme failing its own configuration — an options validation
            // failure, or the argument exception a remote handler's Validate throws — is the
            // host's failure to hear about, on the host's own path. There is no callback path to
            // compare, and nothing to report here.
            return;
        }

        var issuerUri = EndpointRouteHelper.GetIssuerUri(_options);

        foreach (var registration in _registry.Registrations
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
