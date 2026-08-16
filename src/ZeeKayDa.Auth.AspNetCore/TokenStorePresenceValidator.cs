using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
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
internal sealed class TokenStorePresenceValidator : IHostedService
{
    private readonly IServiceProviderIsService? _isService;

    public TokenStorePresenceValidator(IServiceProviderIsService? isService)
        => _isService = isService;

    /// <inheritdoc/>
    public Task StartAsync(CancellationToken cancellationToken)
    {
        if (_isService is null)
            return Task.CompletedTask;

        var failures = new List<ZeeKayDaConfigurationFailure>();

        if (!_isService.IsService(typeof(IAuthorizationCodeStore)))
            failures.Add(new ZeeKayDaConfigurationFailure(
                "stores.authorization_code_store.missing",
                "No IAuthorizationCodeStore has been registered. " +
                "Call builder.AddInMemoryAuthorizationCodeStore(), builder.AddAuthorizationCodeStore<T>(), " +
                "or builder.AddDistributedCacheAuthorizationCodeStore()."));

        if (!_isService.IsService(typeof(IRefreshTokenStore)))
            failures.Add(new ZeeKayDaConfigurationFailure(
                "stores.refresh_token_store.missing",
                "No IRefreshTokenStore has been registered. " +
                "Call builder.AddInMemoryRefreshTokenStore(), builder.AddRefreshTokenGrantStore<T>(), " +
                "or builder.AddDistributedCacheRefreshTokenStore()."));

        if (failures.Count > 0)
            throw new ZeeKayDaConfigurationException([.. failures]);

        return Task.CompletedTask;
    }

    /// <inheritdoc/>
    public Task StopAsync(CancellationToken cancellationToken) => Task.CompletedTask;
}
