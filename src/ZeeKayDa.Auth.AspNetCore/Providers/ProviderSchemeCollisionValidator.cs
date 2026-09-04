using Microsoft.AspNetCore.Authentication;
using Microsoft.Extensions.DependencyInjection;

namespace ZeeKayDa.Auth.AspNetCore.Providers;

/// <summary>
/// Fails startup when a registered provider's name also exists in the host's final scheme map —
/// registered before or after <c>WithProviders</c>, by the host or a library.
/// </summary>
/// <remarks>
/// <para>
/// Provider schemes are invisible to the host by construction: not enumerable, not challengeable
/// by name, never dispatched by the authentication middleware. A host scheme with the same name
/// would reintroduce exactly that — the middleware would serve its callback and the host could
/// challenge it — so the collision is refused rather than tolerated.
/// </para>
/// <para>
/// This reads the resolved <see cref="IAuthenticationSchemeProvider"/>, not the registration
/// window, so it sees the map as the application will run it. An activator rather than a
/// verifier, by the mechanical rule: building that map runs the host's own configuration code.
/// </para>
/// </remarks>
internal sealed class ProviderSchemeCollisionValidator : IStartupActivator
{
    private readonly ProviderRegistry _registry;

    public ProviderSchemeCollisionValidator(ProviderRegistry registry)
    {
        ArgumentNullException.ThrowIfNull(registry);

        _registry = registry;
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
            .Select(scheme => scheme.Name)
            .ToHashSet(StringComparer.OrdinalIgnoreCase);
        foreach (var registration in _registry.Registrations.Where(registration => hostSchemes.Contains(registration.Name)))
        {
            cancellationToken.ThrowIfCancellationRequested();

            context.AddFailure(
                "provider.scheme_visible_to_host",
                $"The provider '{registration.Name}' is also registered as an authentication scheme of " +
                "the host, outside WithProviders. A provider scheme must exist only in the framework's " +
                "scheme map, or the host could challenge it and the authentication middleware would " +
                "serve its callback. Remove the host's registration, or rename one of the two.");
        }
    }
}
