using Microsoft.Extensions.DependencyInjection;
using ZeeKayDa.Auth.Stores;

namespace ZeeKayDa.Auth.AspNetCore;

/// <summary>
/// Verifies at application startup that both <see cref="IAuthorizationCodeStore"/> and
/// <see cref="IRefreshTokenStore"/> have been registered in the dependency injection container.
/// </summary>
/// <remarks>
/// Uses <see cref="IServiceProviderIsService"/> to inspect the DI container without resolving the
/// services themselves. If <see cref="IServiceProviderIsService"/> is absent (e.g. a third-party
/// DI container replacing the default provider), the check is skipped rather than failing with a
/// confusing resolution error.
/// </remarks>
internal sealed class TokenStorePresenceValidator : IStartupVerifier
{
    /// <inheritdoc/>
    public string Name => "TokenStorePresence";

    /// <inheritdoc/>
    public ValueTask VerifyAsync(
        StartupVerificationContext context,
        IServiceProvider scopedServices,
        CancellationToken cancellationToken)
    {
        var isService = scopedServices.GetService<IServiceProviderIsService>();
        if (isService is null)
            return ValueTask.CompletedTask;

        if (!isService.IsService(typeof(IAuthorizationCodeStore)))
            context.AddFailure(
                "stores.authorization_code_store.missing",
                "No IAuthorizationCodeStore has been registered. " +
                "Call builder.AddInMemoryAuthorizationCodeStore(), builder.AddAuthorizationCodeStore<T>(), " +
                "or builder.AddDistributedCacheAuthorizationCodeStore().");

        if (!isService.IsService(typeof(IRefreshTokenStore)))
            context.AddFailure(
                "stores.refresh_token_store.missing",
                "No IRefreshTokenStore has been registered. " +
                "Call builder.AddInMemoryRefreshTokenStore(), builder.AddRefreshTokenGrantStore<T>(), " +
                "or builder.AddDistributedCacheRefreshTokenStore().");

        return ValueTask.CompletedTask;
    }
}
