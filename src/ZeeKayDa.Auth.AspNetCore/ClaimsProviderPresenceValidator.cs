using Microsoft.Extensions.DependencyInjection;
using ZeeKayDa.Auth.Claims;

namespace ZeeKayDa.Auth.AspNetCore;

/// <summary>
/// Verifies at application startup that an <see cref="IClaimsProvider"/> is registered. There is
/// no default: an optional provider with an empty fallback would let a deployment silently issue
/// tokens carrying <c>sub</c> and nothing else.
/// </summary>
/// <remarks>
/// Uses <see cref="IServiceProviderIsService"/> to inspect the container without resolving the
/// provider, which is scoped and may need a request to construct. If
/// <see cref="IServiceProviderIsService"/> is absent (a third-party container), the check is
/// skipped rather than failing with a confusing resolution error.
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
        var isService = scopedServices.GetService<IServiceProviderIsService>();
        if (isService is null)
            return ValueTask.CompletedTask;

        if (!isService.IsService(typeof(IClaimsProvider)))
        {
            context.AddFailure(
                "claims.provider.missing",
                "No IClaimsProvider has been registered. Call builder.AddClaimsProvider<TProvider>() with the " +
                "host's implementation. The framework never reads an identity store itself, so without a " +
                "provider no token could carry a subject claim.");
        }

        return ValueTask.CompletedTask;
    }
}
