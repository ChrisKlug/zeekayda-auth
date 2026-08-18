using Microsoft.Extensions.DependencyInjection;
using ZeeKayDa.Auth;
using ZeeKayDa.Auth.AspNetCore;

namespace ZeeKayDa.Auth.AspNetCore.Tests;

public sealed class TokenStorePresenceValidatorTests
{
    // Real ServiceProvider instances automatically implement IServiceProviderIsService via their
    // own engine, and that built-in implementation cannot be shadowed by a user AddSingleton
    // registration of the same interface — so these tests register (or omit) the real store
    // interfaces via the public builder methods and let the provider's own
    // IServiceProviderIsService report on them truthfully.

    private static ZeeKayDaAuthBuilder CreateBuilder(ServiceCollection services)
        => new(services);

    [Fact]
    public async Task VerifyAsync_completes_without_failures_when_both_stores_are_registered()
    {
        var services = new ServiceCollection();
        CreateBuilder(services).AddInMemoryStores(allowOutsideDevelopment: true);
        using var provider = services.BuildServiceProvider();
        var sut = new TokenStorePresenceValidator();
        var context = new StartupVerificationContext();

        await sut.VerifyAsync(context, provider, TestContext.Current.CancellationToken);

        context.Failures.Should().BeEmpty();
    }

    [Fact]
    public async Task VerifyAsync_adds_a_failure_when_IAuthorizationCodeStore_is_missing()
    {
        var services = new ServiceCollection();
        CreateBuilder(services).AddInMemoryRefreshTokenStore(allowOutsideDevelopment: true);
        using var provider = services.BuildServiceProvider();
        var sut = new TokenStorePresenceValidator();
        var context = new StartupVerificationContext();

        await sut.VerifyAsync(context, provider, TestContext.Current.CancellationToken);

        context.Failures.Should().ContainSingle()
            .Which.Code.Should().Be("stores.authorization_code_store.missing");

        context.Failures.Single().Message.Should().Contain("IAuthorizationCodeStore");
    }

    [Fact]
    public async Task VerifyAsync_adds_a_failure_when_IRefreshTokenStore_is_missing()
    {
        var services = new ServiceCollection();
        CreateBuilder(services).AddInMemoryAuthorizationCodeStore(allowOutsideDevelopment: true);
        using var provider = services.BuildServiceProvider();
        var sut = new TokenStorePresenceValidator();
        var context = new StartupVerificationContext();

        await sut.VerifyAsync(context, provider, TestContext.Current.CancellationToken);

        context.Failures.Should().ContainSingle()
            .Which.Code.Should().Be("stores.refresh_token_store.missing");

        context.Failures.Single().Message.Should().Contain("IRefreshTokenStore");
    }

    [Fact]
    public async Task VerifyAsync_adds_two_failures_when_both_stores_are_missing()
    {
        var services = new ServiceCollection();
        using var provider = services.BuildServiceProvider();
        var sut = new TokenStorePresenceValidator();
        var context = new StartupVerificationContext();

        await sut.VerifyAsync(context, provider, TestContext.Current.CancellationToken);

        context.Failures.Should().HaveCount(2);
        context.Failures.Should().Contain(f => f.Code == "stores.authorization_code_store.missing");
        context.Failures.Should().Contain(f => f.Code == "stores.refresh_token_store.missing");
    }

    [Fact]
    public async Task VerifyAsync_does_not_add_failures_when_IServiceProviderIsService_is_absent()
    {
        // Neither store is registered, but the provider has no IServiceProviderIsService at all
        // (e.g. a third-party DI container replacing the default one) — the check is skipped
        // rather than failing with a confusing resolution error.
        var sut = new TokenStorePresenceValidator();
        var context = new StartupVerificationContext();

        await sut.VerifyAsync(context, new NoServiceProviderIsServiceProvider(), TestContext.Current.CancellationToken);

        context.Failures.Should().BeEmpty();
    }

    [Fact]
    public void Name_is_TokenStorePresence()
    {
        var sut = new TokenStorePresenceValidator();

        sut.Name.Should().Be("TokenStorePresence");
    }

    private sealed class NoServiceProviderIsServiceProvider : IServiceProvider
    {
        public object? GetService(Type serviceType) => null;
    }
}
