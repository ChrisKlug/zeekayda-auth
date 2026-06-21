using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using ZeeKayDa.Auth.AspNetCore;
using ZeeKayDa.Auth.Stores;

namespace ZeeKayDa.Auth.AspNetCore.Tests.Extensions;

public sealed class ZeeKayDaAuthBuilderStoreExtensionsTests
{
    // ── AddAuthorizationCodeStore: argument validation ────────────────────────────────────────────

    [Fact]
    public void AddAuthorizationCodeStore_throws_ArgumentNullException_when_builder_is_null()
    {
        var act = () => ((ZeeKayDaAuthBuilder)null!).AddAuthorizationCodeStore<StubAuthorizationCodeStore>();

        act.Should().Throw<ArgumentNullException>().WithParameterName("builder");
    }

    // ── AddAuthorizationCodeStore: happy path ─────────────────────────────────────────────────────

    [Fact]
    public void AddAuthorizationCodeStore_registers_IAuthorizationCodeStore_as_singleton()
    {
        var services = new ServiceCollection();
        var builder = new ZeeKayDaAuthBuilder(services);

        builder.AddAuthorizationCodeStore<StubAuthorizationCodeStore>();

        using var provider = services.BuildServiceProvider();
        var first = provider.GetRequiredService<IAuthorizationCodeStore>();
        var second = provider.GetRequiredService<IAuthorizationCodeStore>();
        first.Should().BeOfType<StubAuthorizationCodeStore>();
        first.Should().BeSameAs(second, "singleton lifetime means a single shared instance");
    }

    [Fact]
    public void AddAuthorizationCodeStore_returns_builder_for_chaining()
    {
        var services = new ServiceCollection();
        var builder = new ZeeKayDaAuthBuilder(services);

        var returned = builder.AddAuthorizationCodeStore<StubAuthorizationCodeStore>();

        returned.Should().BeSameAs(builder);
    }

    // ── AddAuthorizationCodeStore: double-registration guard ─────────────────────────────────────

    [Fact]
    public void AddAuthorizationCodeStore_throws_InvalidOperationException_on_second_call_with_same_type()
    {
        var services = new ServiceCollection();
        var builder = new ZeeKayDaAuthBuilder(services);
        builder.AddAuthorizationCodeStore<StubAuthorizationCodeStore>();

        var act = () => builder.AddAuthorizationCodeStore<StubAuthorizationCodeStore>();

        act.Should().Throw<InvalidOperationException>()
            .WithMessage("*IAuthorizationCodeStore is already registered*");
    }

    [Fact]
    public void AddAuthorizationCodeStore_throws_InvalidOperationException_on_second_call_with_different_type()
    {
        var services = new ServiceCollection();
        var builder = new ZeeKayDaAuthBuilder(services);
        builder.AddAuthorizationCodeStore<StubAuthorizationCodeStore>();

        var act = () => builder.AddAuthorizationCodeStore<AnotherStubAuthorizationCodeStore>();

        act.Should().Throw<InvalidOperationException>()
            .WithMessage("*IAuthorizationCodeStore is already registered*");
    }

    // ── AddRefreshTokenStore: argument validation ─────────────────────────────────────────────────

    [Fact]
    public void AddRefreshTokenStore_throws_ArgumentNullException_when_builder_is_null()
    {
        var act = () => ((ZeeKayDaAuthBuilder)null!).AddRefreshTokenStore<StubRefreshTokenStore>();

        act.Should().Throw<ArgumentNullException>().WithParameterName("builder");
    }

    // ── AddRefreshTokenStore: happy path ──────────────────────────────────────────────────────────

    [Fact]
    public void AddRefreshTokenStore_registers_IRefreshTokenStore_as_singleton()
    {
        var services = new ServiceCollection();
        var builder = new ZeeKayDaAuthBuilder(services);

        builder.AddRefreshTokenStore<StubRefreshTokenStore>();

        using var provider = services.BuildServiceProvider();
        var first = provider.GetRequiredService<IRefreshTokenStore>();
        var second = provider.GetRequiredService<IRefreshTokenStore>();
        first.Should().BeOfType<StubRefreshTokenStore>();
        first.Should().BeSameAs(second, "singleton lifetime means a single shared instance");
    }

    [Fact]
    public void AddRefreshTokenStore_returns_builder_for_chaining()
    {
        var services = new ServiceCollection();
        var builder = new ZeeKayDaAuthBuilder(services);

        var returned = builder.AddRefreshTokenStore<StubRefreshTokenStore>();

        returned.Should().BeSameAs(builder);
    }

    // ── AddRefreshTokenStore: double-registration guard ───────────────────────────────────────────

    [Fact]
    public void AddRefreshTokenStore_throws_InvalidOperationException_on_second_call_with_same_type()
    {
        var services = new ServiceCollection();
        var builder = new ZeeKayDaAuthBuilder(services);
        builder.AddRefreshTokenStore<StubRefreshTokenStore>();

        var act = () => builder.AddRefreshTokenStore<StubRefreshTokenStore>();

        act.Should().Throw<InvalidOperationException>()
            .WithMessage("*IRefreshTokenStore is already registered*");
    }

    [Fact]
    public void AddRefreshTokenStore_throws_InvalidOperationException_on_second_call_with_different_type()
    {
        var services = new ServiceCollection();
        var builder = new ZeeKayDaAuthBuilder(services);
        builder.AddRefreshTokenStore<StubRefreshTokenStore>();

        var act = () => builder.AddRefreshTokenStore<AnotherStubRefreshTokenStore>();

        act.Should().Throw<InvalidOperationException>()
            .WithMessage("*IRefreshTokenStore is already registered*");
    }

    // ── Independent store guards ──────────────────────────────────────────────────────────────────

    [Fact]
    public void Registering_IAuthorizationCodeStore_does_not_block_IRefreshTokenStore_registration()
    {
        var services = new ServiceCollection();
        var builder = new ZeeKayDaAuthBuilder(services);
        builder.AddAuthorizationCodeStore<StubAuthorizationCodeStore>();

        var act = () => builder.AddRefreshTokenStore<StubRefreshTokenStore>();

        act.Should().NotThrow("the guard is per-interface, not global");
        services.Should().Contain(sd =>
            sd.ServiceType == typeof(IRefreshTokenStore) &&
            sd.ImplementationType == typeof(StubRefreshTokenStore));
    }

    [Fact]
    public void Registering_IRefreshTokenStore_does_not_block_IAuthorizationCodeStore_registration()
    {
        var services = new ServiceCollection();
        var builder = new ZeeKayDaAuthBuilder(services);
        builder.AddRefreshTokenStore<StubRefreshTokenStore>();

        var act = () => builder.AddAuthorizationCodeStore<StubAuthorizationCodeStore>();

        act.Should().NotThrow("the guard is per-interface, not global");
        services.Should().Contain(sd =>
            sd.ServiceType == typeof(IAuthorizationCodeStore) &&
            sd.ImplementationType == typeof(StubAuthorizationCodeStore));
    }

    // ── ThrowIfAlreadyRegistered on a fresh builder ───────────────────────────────────────────────

    [Fact]
    public void ThrowIfAlreadyRegistered_does_not_throw_on_fresh_builder_for_unregistered_type()
    {
        var services = new ServiceCollection();
        var builder = new ZeeKayDaAuthBuilder(services);

        var act = () => builder.ThrowIfAlreadyRegistered(typeof(IAuthorizationCodeStore));

        act.Should().NotThrow("the type has not yet been registered in the empty service collection");
    }

    // ── AddInMemoryAuthorizationCodeStore: argument validation ────────────────────────────────────

    [Fact]
    public void AddInMemoryAuthorizationCodeStore_throws_ArgumentNullException_when_builder_is_null()
    {
        var act = () => null!.AddInMemoryAuthorizationCodeStore();

        act.Should().Throw<ArgumentNullException>().WithParameterName("builder");
    }

    // ── AddInMemoryAuthorizationCodeStore: happy path ─────────────────────────────────────────────

    [Fact]
    public void AddInMemoryAuthorizationCodeStore_returns_builder_for_chaining()
    {
        var services = new ServiceCollection();
        var builder = new ZeeKayDaAuthBuilder(services);

        var returned = builder.AddInMemoryAuthorizationCodeStore();

        returned.Should().BeSameAs(builder);
    }

    [Fact]
    public void AddInMemoryAuthorizationCodeStore_registers_IAuthorizationCodeStore_as_singleton_with_InMemoryAuthorizationCodeStore_implementation()
    {
        var services = new ServiceCollection();
        var builder = new ZeeKayDaAuthBuilder(services);

        builder.AddInMemoryAuthorizationCodeStore();

        services.Should().Contain(sd =>
            sd.ServiceType == typeof(IAuthorizationCodeStore) &&
            sd.ImplementationType == typeof(InMemoryAuthorizationCodeStore) &&
            sd.Lifetime == ServiceLifetime.Singleton);
    }

    [Fact]
    public void AddInMemoryAuthorizationCodeStore_registers_InMemoryStoreWarningService_as_IHostedService()
    {
        var services = new ServiceCollection();
        var builder = new ZeeKayDaAuthBuilder(services);

        builder.AddInMemoryAuthorizationCodeStore();

        services.Should().Contain(sd =>
            sd.ServiceType == typeof(IHostedService) &&
            sd.ImplementationType == typeof(InMemoryStoreWarningService));
    }

    // ── AddInMemoryAuthorizationCodeStore: double-registration guard ──────────────────────────────

    [Fact]
    public void AddInMemoryAuthorizationCodeStore_throws_InvalidOperationException_when_IAuthorizationCodeStore_is_already_registered()
    {
        var services = new ServiceCollection();
        var builder = new ZeeKayDaAuthBuilder(services);
        builder.AddInMemoryAuthorizationCodeStore();

        var act = () => builder.AddInMemoryAuthorizationCodeStore();

        act.Should().Throw<InvalidOperationException>()
            .WithMessage("*IAuthorizationCodeStore is already registered*");
    }

    [Fact]
    public void AddInMemoryAuthorizationCodeStore_throws_InvalidOperationException_when_generic_AddAuthorizationCodeStore_was_called_first()
    {
        var services = new ServiceCollection();
        var builder = new ZeeKayDaAuthBuilder(services);
        builder.AddAuthorizationCodeStore<StubAuthorizationCodeStore>();

        var act = () => builder.AddInMemoryAuthorizationCodeStore();

        act.Should().Throw<InvalidOperationException>()
            .WithMessage("*IAuthorizationCodeStore is already registered*");
    }

    // ── AddInMemoryRefreshTokenStore: argument validation ─────────────────────────────────────────

    [Fact]
    public void AddInMemoryRefreshTokenStore_throws_ArgumentNullException_when_builder_is_null()
    {
        var act = () => (null!).AddInMemoryRefreshTokenStore();

        act.Should().Throw<ArgumentNullException>().WithParameterName("builder");
    }

    // ── AddInMemoryRefreshTokenStore: happy path ──────────────────────────────────────────────────

    [Fact]
    public void AddInMemoryRefreshTokenStore_returns_builder_for_chaining()
    {
        var services = new ServiceCollection();
        var builder = new ZeeKayDaAuthBuilder(services);

        var returned = builder.AddInMemoryRefreshTokenStore();

        returned.Should().BeSameAs(builder);
    }

    [Fact]
    public void AddInMemoryRefreshTokenStore_registers_IRefreshTokenStore_as_singleton_with_InMemoryRefreshTokenStore_implementation()
    {
        var services = new ServiceCollection();
        var builder = new ZeeKayDaAuthBuilder(services);

        builder.AddInMemoryRefreshTokenStore();

        services.Should().Contain(sd =>
            sd.ServiceType == typeof(IRefreshTokenStore) &&
            sd.ImplementationType == typeof(InMemoryRefreshTokenStore) &&
            sd.Lifetime == ServiceLifetime.Singleton);
    }

    [Fact]
    public void AddInMemoryRefreshTokenStore_registers_InMemoryStoreWarningService_as_IHostedService()
    {
        var services = new ServiceCollection();
        var builder = new ZeeKayDaAuthBuilder(services);

        builder.AddInMemoryRefreshTokenStore();

        services.Should().Contain(sd =>
            sd.ServiceType == typeof(IHostedService) &&
            sd.ImplementationType == typeof(InMemoryStoreWarningService));
    }

    // ── AddInMemoryRefreshTokenStore: double-registration guard ───────────────────────────────────

    [Fact]
    public void AddInMemoryRefreshTokenStore_throws_InvalidOperationException_when_IRefreshTokenStore_is_already_registered()
    {
        var services = new ServiceCollection();
        var builder = new ZeeKayDaAuthBuilder(services);
        builder.AddInMemoryRefreshTokenStore();

        var act = () => builder.AddInMemoryRefreshTokenStore();

        act.Should().Throw<InvalidOperationException>()
            .WithMessage("*IRefreshTokenStore is already registered*");
    }

    [Fact]
    public void AddInMemoryRefreshTokenStore_throws_InvalidOperationException_when_generic_AddRefreshTokenStore_was_called_first()
    {
        var services = new ServiceCollection();
        var builder = new ZeeKayDaAuthBuilder(services);
        builder.AddRefreshTokenStore<StubRefreshTokenStore>();

        var act = () => builder.AddInMemoryRefreshTokenStore();

        act.Should().Throw<InvalidOperationException>()
            .WithMessage("*IRefreshTokenStore is already registered*");
    }

    // ── AddInMemoryStores: argument validation ────────────────────────────────────────────────────

    [Fact]
    public void AddInMemoryStores_throws_ArgumentNullException_when_builder_is_null()
    {
        ZeeKayDaAuthBuilder builder = null!;
        var act = () => builder.AddInMemoryStores();

        act.Should().Throw<ArgumentNullException>().WithParameterName("builder");
    }

    // ── AddInMemoryStores: happy path ─────────────────────────────────────────────────────────────

    [Fact]
    public void AddInMemoryStores_returns_builder_for_chaining()
    {
        var services = new ServiceCollection();
        var builder = new ZeeKayDaAuthBuilder(services);

        var returned = builder.AddInMemoryStores();

        returned.Should().BeSameAs(builder);
    }

    [Fact]
    public void AddInMemoryStores_registers_both_IAuthorizationCodeStore_and_IRefreshTokenStore()
    {
        var services = new ServiceCollection();
        var builder = new ZeeKayDaAuthBuilder(services);

        builder.AddInMemoryStores();

        services.Should().Contain(sd =>
            sd.ServiceType == typeof(IAuthorizationCodeStore) &&
            sd.ImplementationType == typeof(InMemoryAuthorizationCodeStore));
        services.Should().Contain(sd =>
            sd.ServiceType == typeof(IRefreshTokenStore) &&
            sd.ImplementationType == typeof(InMemoryRefreshTokenStore));
    }

    [Fact]
    public void AddInMemoryStores_registers_InMemoryStoreWarningService_exactly_once()
    {
        var services = new ServiceCollection();
        var builder = new ZeeKayDaAuthBuilder(services);

        builder.AddInMemoryStores();

        services.Count(sd =>
            sd.ServiceType == typeof(IHostedService) &&
            sd.ImplementationType == typeof(InMemoryStoreWarningService))
            .Should().Be(1, "TryAddEnumerable ensures idempotent registration across both calls");
    }

    [Fact]
    public void Calling_AddInMemoryAuthorizationCodeStore_and_AddInMemoryRefreshTokenStore_separately_registers_InMemoryStoreWarningService_exactly_once()
    {
        var services = new ServiceCollection();
        var builder = new ZeeKayDaAuthBuilder(services);

        builder.AddInMemoryAuthorizationCodeStore();
        builder.AddInMemoryRefreshTokenStore();

        services.Count(sd =>
            sd.ServiceType == typeof(IHostedService) &&
            sd.ImplementationType == typeof(InMemoryStoreWarningService))
            .Should().Be(1, "TryAddEnumerable ensures idempotent registration when called independently");
    }

    // ── AddInMemoryStores: per-interface guard independence ───────────────────────────────────────

    [Fact]
    public void AddInMemoryStores_throws_InvalidOperationException_when_IAuthorizationCodeStore_is_already_registered_even_if_IRefreshTokenStore_is_not()
    {
        var services = new ServiceCollection();
        var builder = new ZeeKayDaAuthBuilder(services);
        builder.AddInMemoryAuthorizationCodeStore();

        var act = () => builder.AddInMemoryStores();

        act.Should().Throw<InvalidOperationException>()
            .WithMessage("*IAuthorizationCodeStore is already registered*");
    }

    [Fact]
    public void AddInMemoryStores_throws_InvalidOperationException_when_IRefreshTokenStore_is_already_registered_even_if_IAuthorizationCodeStore_is_not()
    {
        var services = new ServiceCollection();
        var builder = new ZeeKayDaAuthBuilder(services);
        builder.AddInMemoryRefreshTokenStore();

        // AddInMemoryStores calls AddInMemoryAuthorizationCodeStore first, which succeeds,
        // then AddInMemoryRefreshTokenStore, which must throw because it is already registered.
        var act = () => builder.AddInMemoryStores();

        act.Should().Throw<InvalidOperationException>()
            .WithMessage("*IRefreshTokenStore is already registered*");
    }

    // ── No-op stub implementations ────────────────────────────────────────────────────────────────

    private sealed class StubAuthorizationCodeStore : IAuthorizationCodeStore
    {
        public Task StoreAsync(string code, AuthorizationCodeEntry entry, CancellationToken cancellationToken)
            => Task.CompletedTask;

        public ValueTask<AuthorizationCodeRedemptionOutcome> TryRedeemAsync(
            string code, string clientId, string familyId, CancellationToken cancellationToken)
            => ValueTask.FromResult<AuthorizationCodeRedemptionOutcome>(new AuthorizationCodeRedemptionOutcome.NotFound());
    }

    private sealed class AnotherStubAuthorizationCodeStore : IAuthorizationCodeStore
    {
        public Task StoreAsync(string code, AuthorizationCodeEntry entry, CancellationToken cancellationToken)
            => Task.CompletedTask;

        public ValueTask<AuthorizationCodeRedemptionOutcome> TryRedeemAsync(
            string code, string clientId, string familyId, CancellationToken cancellationToken)
            => ValueTask.FromResult<AuthorizationCodeRedemptionOutcome>(new AuthorizationCodeRedemptionOutcome.NotFound());
    }

    private sealed class StubRefreshTokenStore : IRefreshTokenStore
    {
        public Task StoreAsync(string tokenHandle, RefreshTokenEntry entry, CancellationToken cancellationToken)
            => Task.CompletedTask;

        public ValueTask<RefreshTokenEntry?> FindAsync(string tokenHandle, CancellationToken cancellationToken)
            => ValueTask.FromResult<RefreshTokenEntry?>(null);

        public ValueTask<RefreshTokenConsumptionOutcome> TryConsumeAsync(
            string tokenHandle, string clientId, CancellationToken cancellationToken)
            => ValueTask.FromResult<RefreshTokenConsumptionOutcome>(new RefreshTokenConsumptionOutcome.NotFound());

        public Task RevokeFamilyAsync(string familyId, CancellationToken cancellationToken)
            => Task.CompletedTask;
    }

    private sealed class AnotherStubRefreshTokenStore : IRefreshTokenStore
    {
        public Task StoreAsync(string tokenHandle, RefreshTokenEntry entry, CancellationToken cancellationToken)
            => Task.CompletedTask;

        public ValueTask<RefreshTokenEntry?> FindAsync(string tokenHandle, CancellationToken cancellationToken)
            => ValueTask.FromResult<RefreshTokenEntry?>(null);

        public ValueTask<RefreshTokenConsumptionOutcome> TryConsumeAsync(
            string tokenHandle, string clientId, CancellationToken cancellationToken)
            => ValueTask.FromResult<RefreshTokenConsumptionOutcome>(new RefreshTokenConsumptionOutcome.NotFound());

        public Task RevokeFamilyAsync(string familyId, CancellationToken cancellationToken)
            => Task.CompletedTask;
    }
}
