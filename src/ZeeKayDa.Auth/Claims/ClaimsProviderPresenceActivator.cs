using Microsoft.Extensions.DependencyInjection;
using ZeeKayDa.Auth.Claims;
using ZeeKayDa.Auth.StartupVerification;

namespace ZeeKayDa.Auth.Claims;

/// <summary>
/// Verifies at application startup that an <see cref="IClaimsProvider"/> is registered. There is
/// no default: an optional provider with an empty fallback would let a deployment silently issue
/// tokens carrying <c>sub</c> and nothing else.
/// </summary>
/// <remarks>
/// Asks <see cref="IServiceProviderIsService"/> where the container offers it, so the provider,
/// which is scoped and may need a request to construct, is not resolved. A container that does
/// not offer it is asked to resolve the provider from the startup scope instead: the check is
/// what makes the seam mandatory, so it cannot be the one thing a third-party container is
/// allowed to skip. An activator rather than a verifier because that fallback constructs a
/// caller-supplied service.
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
