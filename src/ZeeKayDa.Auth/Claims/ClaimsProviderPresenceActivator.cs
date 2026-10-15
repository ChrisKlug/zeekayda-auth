using Microsoft.Extensions.DependencyInjection;
using ZeeKayDa.Auth.Claims;
using ZeeKayDa.Auth.StartupVerification;

namespace ZeeKayDa.Auth.Claims;

/// <summary>
/// Fails startup when no <see cref="IClaimsProvider"/> is registered; an empty default would silently issue
/// tokens carrying only <c>sub</c>.
/// </summary>
/// <remarks>
/// Asks <see cref="IServiceProviderIsService"/> so the scoped provider is not built; a container without it
/// resolves the provider instead, which is why this is an activator.
/// </remarks>
internal sealed class ClaimsProviderPresenceActivator(IServiceProvider services) : IStartupActivator
{
    /// <inheritdoc/>
    public string Name => "ClaimsProviderPresence";

    /// <inheritdoc/>
    public Task VerifyAsync(StartupVerificationContext context, CancellationToken cancellationToken)
    {
        if (!IsProviderRegistered())
        {
            context.AddFailure(
                "claims.provider.missing",
                "No IClaimsProvider has been registered. Call builder.AddClaimsProvider<TProvider>() with the " +
                "host's implementation. The framework never reads an identity store itself, so without a " +
                "provider no token could carry a subject claim.");
        }

        return Task.CompletedTask;
    }

    private bool IsProviderRegistered() =>
        services.GetService<IServiceProviderIsService>() is { } isService
            ? isService.IsService(typeof(IClaimsProvider))
            : services.GetService<IClaimsProvider>() is not null;
}
