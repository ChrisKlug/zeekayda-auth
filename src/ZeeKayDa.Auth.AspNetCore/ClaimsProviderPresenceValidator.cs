using Microsoft.Extensions.DependencyInjection;
using ZeeKayDa.Auth.Claims;

namespace ZeeKayDa.Auth.AspNetCore;

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
/// allowed to skip.
/// </remarks>
internal sealed class ClaimsProviderPresenceValidator : IStartupVerifier
{
    /// <inheritdoc/>
    public string Name => "ClaimsProviderPresence";

    /// <inheritdoc/>
    public ValueTask VerifyAsync(
        StartupVerificationContext context,
        IServiceProvider scopedServices,
        CancellationToken cancellationToken)
    {
        if (!IsProviderRegistered(scopedServices))
        {
            context.AddFailure(
                "claims.provider.missing",
                "No IClaimsProvider has been registered. Call builder.AddClaimsProvider<TProvider>() with the " +
                "host's implementation. The framework never reads an identity store itself, so without a " +
                "provider no token could carry a subject claim.");
        }

        return ValueTask.CompletedTask;
    }

    private static bool IsProviderRegistered(IServiceProvider scopedServices) =>
        scopedServices.GetService<IServiceProviderIsService>() is { } isService
            ? isService.IsService(typeof(IClaimsProvider))
            : scopedServices.GetService<IClaimsProvider>() is not null;
}
