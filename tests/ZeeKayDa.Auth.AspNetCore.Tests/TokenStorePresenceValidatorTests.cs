using Microsoft.Extensions.DependencyInjection;
using ZeeKayDa.Auth.Stores;

namespace ZeeKayDa.Auth.AspNetCore.Tests;

public sealed class TokenStorePresenceValidatorTests
{
    private static TokenStorePresenceValidator BuildSut(bool? hasAuthCodeStore, bool? hasRefreshTokenStore)
    {
        if (hasAuthCodeStore is null && hasRefreshTokenStore is null)
            return new TokenStorePresenceValidator(null);

        var isService = new FakeServiceProviderIsService(
            hasAuthCodeStore ?? true,
            hasRefreshTokenStore ?? true);

        return new TokenStorePresenceValidator(isService);
    }

    [Fact]
    public async Task StartAsync_completes_without_throwing_when_both_stores_are_registered()
    {
        var sut = BuildSut(hasAuthCodeStore: true, hasRefreshTokenStore: true);

        await sut.Awaiting(s => s.StartAsync(CancellationToken.None)).Should().NotThrowAsync();
    }

    [Fact]
    public async Task StartAsync_throws_ZeeKayDaConfigurationException_when_IAuthorizationCodeStore_is_missing()
    {
        var sut = BuildSut(hasAuthCodeStore: false, hasRefreshTokenStore: true);

        var ex = await sut.Awaiting(s => s.StartAsync(CancellationToken.None))
            .Should().ThrowAsync<ZeeKayDaConfigurationException>();

        ex.Which.AggregatedFailures.Should().ContainSingle()
            .Which.Code.Should().Be("stores.authorization_code_store.missing");

        ex.Which.AggregatedFailures.Single().Message.Should().Contain("IAuthorizationCodeStore");
    }

    [Fact]
    public async Task StartAsync_throws_ZeeKayDaConfigurationException_when_IRefreshTokenStore_is_missing()
    {
        var sut = BuildSut(hasAuthCodeStore: true, hasRefreshTokenStore: false);

        var ex = await sut.Awaiting(s => s.StartAsync(CancellationToken.None))
            .Should().ThrowAsync<ZeeKayDaConfigurationException>();

        ex.Which.AggregatedFailures.Should().ContainSingle()
            .Which.Code.Should().Be("stores.refresh_token_store.missing");

        ex.Which.AggregatedFailures.Single().Message.Should().Contain("IRefreshTokenStore");
    }

    [Fact]
    public async Task StartAsync_throws_with_two_failures_when_both_stores_are_missing()
    {
        var sut = BuildSut(hasAuthCodeStore: false, hasRefreshTokenStore: false);

        var ex = await sut.Awaiting(s => s.StartAsync(CancellationToken.None))
            .Should().ThrowAsync<ZeeKayDaConfigurationException>();

        ex.Which.AggregatedFailures.Should().HaveCount(2);
        ex.Which.AggregatedFailures.Should().Contain(f => f.Code == "stores.authorization_code_store.missing");
        ex.Which.AggregatedFailures.Should().Contain(f => f.Code == "stores.refresh_token_store.missing");
    }

    [Fact]
    public async Task StartAsync_does_not_throw_when_IServiceProviderIsService_is_null()
    {
        var sut = BuildSut(hasAuthCodeStore: null, hasRefreshTokenStore: null);

        await sut.Awaiting(s => s.StartAsync(CancellationToken.None)).Should().NotThrowAsync();
    }

    [Fact]
    public async Task StopAsync_does_not_throw()
    {
        var sut = BuildSut(hasAuthCodeStore: true, hasRefreshTokenStore: true);

        await sut.Awaiting(s => s.StopAsync(CancellationToken.None)).Should().NotThrowAsync();
    }

    private sealed class FakeServiceProviderIsService : IServiceProviderIsService
    {
        private readonly bool _hasAuthCodeStore;
        private readonly bool _hasRefreshTokenStore;

        public FakeServiceProviderIsService(bool hasAuthCodeStore, bool hasRefreshTokenStore)
        {
            _hasAuthCodeStore = hasAuthCodeStore;
            _hasRefreshTokenStore = hasRefreshTokenStore;
        }

        public bool IsService(Type serviceType)
        {
            if (serviceType == typeof(IAuthorizationCodeStore)) return _hasAuthCodeStore;
            if (serviceType == typeof(IRefreshTokenStore)) return _hasRefreshTokenStore;
            return false;
        }
    }
}
