using Microsoft.Extensions.DependencyInjection;
using ZeeKayDa.Auth.StartupVerification;
using ZeeKayDa.Auth.Stores;

namespace ZeeKayDa.Auth.Stores;

/// <summary>
/// Verifies at application startup that every store the framework needs has been registered in
/// the dependency injection container: <see cref="IAuthorizationCodeBackingStore"/>,
/// <see cref="IRefreshTokenBackingStore"/>, and the interaction store behind the authorize flow.
/// </summary>
/// <remarks>
/// Uses <see cref="IServiceProviderIsService"/> to inspect the DI container without resolving the
/// services themselves. If <see cref="IServiceProviderIsService"/> is absent (e.g. a third-party
/// DI container replacing the default provider), the check is skipped rather than failing with a
/// confusing resolution error.
/// </remarks>
internal sealed class TokenStorePresenceVerifier : IStartupVerifier
{
    /// <inheritdoc/>
    public string Name => "TokenStorePresence";

    /// <inheritdoc/>
    public Task VerifyAsync(
        StartupVerificationContext context,
        IServiceProvider scopedServices,
        CancellationToken cancellationToken)
    {
        var isService = scopedServices.GetService<IServiceProviderIsService>();
        if (isService is null)
            return Task.CompletedTask;

        if (!isService.IsService(typeof(IAuthorizationCodeBackingStore)))
            context.AddFailure(
                "stores.authorization_code_store.missing",
                "No authorization code store has been registered. " +
                "Call builder.AddInMemoryAuthorizationCodeStore() or builder.AddAuthorizationCodeStore<T>().");

        if (!isService.IsService(typeof(IRefreshTokenBackingStore)))
            context.AddFailure(
                "stores.refresh_token_store.missing",
                "No refresh token store has been registered. " +
                "Call builder.AddInMemoryRefreshTokenStore() or builder.AddRefreshTokenStore<T>().");

        if (!isService.IsService(typeof(IInteractionBackingStore)))
            context.AddFailure(
                "stores.interaction_store.missing",
                "No interaction store has been registered. " +
                "Call builder.AddInMemoryInteractionStore() or builder.AddDistributedCacheInteractionStore().");

        return Task.CompletedTask;
    }
}
