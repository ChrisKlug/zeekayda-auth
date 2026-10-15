using Microsoft.Extensions.DependencyInjection;
using ZeeKayDa.Auth.StartupVerification;
using ZeeKayDa.Auth.Stores;

namespace ZeeKayDa.Auth.Stores;

/// <summary>
/// Fails startup when the code, refresh token or interaction store is missing; skipped for a container
/// without <see cref="IServiceProviderIsService"/>.
/// </summary>
internal sealed class TokenStorePresenceVerifier(IServiceProviderIsService? isService = null) : IStartupVerifier
{
    /// <inheritdoc/>
    public string Name => "TokenStorePresence";

    /// <inheritdoc/>
    public Task VerifyAsync(StartupVerificationContext context, CancellationToken cancellationToken)
    {
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
