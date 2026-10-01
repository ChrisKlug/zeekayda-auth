using Microsoft.Extensions.Caching.Distributed;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.FileProviders;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;
using ZeeKayDa.Auth;
using ZeeKayDa.Auth.StartupVerification;
using ZeeKayDa.Auth.Stores;

namespace ZeeKayDa.Auth.Tests.Extensions;

public sealed class ZeeKayDaAuthCoreBuilderStoreExtensionsTests
{
    // ── Fake infrastructure for InMemoryStoreVerifier resolution ─────────────────────────────────

    private sealed class FakeHostEnvironment(string environmentName) : IHostEnvironment
    {
        public string EnvironmentName { get; set; } = environmentName;
        public string ApplicationName { get; set; } = "TestApp";
        public string ContentRootPath { get; set; } = "/";
        public IFileProvider ContentRootFileProvider { get; set; } = new NullFileProvider();
    }

    private static ServiceCollection CreateServicesWithStoreVerifierDependencies(
        string environmentName = "Development")
    {
        var services = new ServiceCollection();
        services.AddSingleton<IHostEnvironment>(new FakeHostEnvironment(environmentName));
        return services;
    }

    // ── AddAuthorizationCodeStore: happy path ─────────────────────────────────────────────────────

    [Fact]
    public void AddAuthorizationCodeStore_registers_T_as_IAuthorizationCodeBackingStore()
    {
        var services = new ServiceCollection();
        var builder = new ZeeKayDaAuthCoreBuilder(services);

        builder.AddAuthorizationCodeStore<StubAuthorizationCodeBackingStore>();

        using var provider = services.BuildServiceProvider();
        var first = provider.GetRequiredService<IAuthorizationCodeBackingStore>();
        var second = provider.GetRequiredService<IAuthorizationCodeBackingStore>();
        first.Should().BeOfType<StubAuthorizationCodeBackingStore>();
        first.Should().BeSameAs(second, "singleton lifetime means a single shared instance");
    }

    [Fact]
    public void AddAuthorizationCodeStore_registers_the_framework_AuthorizationCodeStore()
    {
        var services = new ServiceCollection();
        var builder = new ZeeKayDaAuthCoreBuilder(services);

        builder.AddAuthorizationCodeStore<StubAuthorizationCodeBackingStore>();

        services.Should().Contain(sd =>
            sd.ServiceType == typeof(AuthorizationCodeStore) &&
            sd.Lifetime == ServiceLifetime.Singleton,
            because: "third parties implement only IAuthorizationCodeBackingStore; the framework's own store runs over it");
    }

    // ── AddAuthorizationCodeStore: double-registration guard ─────────────────────────────────────

    [Fact]
    public void AddAuthorizationCodeStore_throws_InvalidOperationException_on_second_call_with_same_type()
    {
        var services = new ServiceCollection();
        var builder = new ZeeKayDaAuthCoreBuilder(services);
        builder.AddAuthorizationCodeStore<StubAuthorizationCodeBackingStore>();

        var act = () => builder.AddAuthorizationCodeStore<StubAuthorizationCodeBackingStore>();

        act.Should().Throw<InvalidOperationException>()
            .WithMessage("*IAuthorizationCodeBackingStore is already registered*");
    }

    [Fact]
    public void AddAuthorizationCodeStore_throws_InvalidOperationException_on_second_call_with_different_type()
    {
        var services = new ServiceCollection();
        var builder = new ZeeKayDaAuthCoreBuilder(services);
        builder.AddAuthorizationCodeStore<StubAuthorizationCodeBackingStore>();

        var act = () => builder.AddAuthorizationCodeStore<AnotherStubAuthorizationCodeBackingStore>();

        act.Should().Throw<InvalidOperationException>()
            .WithMessage("*IAuthorizationCodeBackingStore is already registered*");
    }

    // ── AddRefreshTokenStore: happy path ─────────────────────────────────────────────────────

    [Fact]
    public void AddRefreshTokenStore_registers_T_as_IRefreshTokenBackingStore()
    {
        var services = new ServiceCollection();
        var builder = new ZeeKayDaAuthCoreBuilder(services);

        builder.AddRefreshTokenStore<StubRefreshTokenBackingStore>();

        using var provider = services.BuildServiceProvider();
        var first = provider.GetRequiredService<IRefreshTokenBackingStore>();
        var second = provider.GetRequiredService<IRefreshTokenBackingStore>();
        first.Should().BeOfType<StubRefreshTokenBackingStore>();
        first.Should().BeSameAs(second, "singleton lifetime means a single shared instance");
    }

    [Fact]
    public void AddRefreshTokenStore_registers_the_framework_RefreshTokenStore()
    {
        var services = new ServiceCollection();
        var builder = new ZeeKayDaAuthCoreBuilder(services);

        builder.AddRefreshTokenStore<StubRefreshTokenBackingStore>();

        services.Should().Contain(sd =>
            sd.ServiceType == typeof(RefreshTokenStore) &&
            sd.Lifetime == ServiceLifetime.Singleton,
            because: "third parties implement only IRefreshTokenBackingStore; the framework's own store runs over it");
    }

    // ── AddRefreshTokenStore: double-registration guard ──────────────────────────────────────

    [Fact]
    public void AddRefreshTokenStore_throws_InvalidOperationException_on_second_call_with_same_type()
    {
        var services = new ServiceCollection();
        var builder = new ZeeKayDaAuthCoreBuilder(services);
        builder.AddRefreshTokenStore<StubRefreshTokenBackingStore>();

        var act = () => builder.AddRefreshTokenStore<StubRefreshTokenBackingStore>();

        act.Should().Throw<InvalidOperationException>()
            .WithMessage("*IRefreshTokenBackingStore is already registered*");
    }

    [Fact]
    public void AddRefreshTokenStore_throws_InvalidOperationException_on_second_call_with_different_type()
    {
        var services = new ServiceCollection();
        var builder = new ZeeKayDaAuthCoreBuilder(services);
        builder.AddRefreshTokenStore<StubRefreshTokenBackingStore>();

        var act = () => builder.AddRefreshTokenStore<AnotherStubRefreshTokenBackingStore>();

        act.Should().Throw<InvalidOperationException>()
            .WithMessage("*IRefreshTokenBackingStore is already registered*");
    }

    // ── Independent store guards ──────────────────────────────────────────────────────────────────

    [Fact]
    public void Registering_the_code_store_does_not_block_the_refresh_token_store_registration()
    {
        var services = new ServiceCollection();
        var builder = new ZeeKayDaAuthCoreBuilder(services);
        builder.AddAuthorizationCodeStore<StubAuthorizationCodeBackingStore>();

        var act = () => builder.AddRefreshTokenStore<StubRefreshTokenBackingStore>();

        act.Should().NotThrow("the guard is per-interface, not global");
        services.Should().Contain(sd =>
            sd.ServiceType == typeof(IRefreshTokenBackingStore) &&
            sd.ImplementationType == typeof(StubRefreshTokenBackingStore));
    }

    [Fact]
    public void Registering_the_refresh_token_store_does_not_block_the_code_store_registration()
    {
        var services = new ServiceCollection();
        var builder = new ZeeKayDaAuthCoreBuilder(services);
        builder.AddRefreshTokenStore<StubRefreshTokenBackingStore>();

        var act = () => builder.AddAuthorizationCodeStore<StubAuthorizationCodeBackingStore>();

        act.Should().NotThrow("the guard is per-interface, not global");
        services.Should().Contain(sd =>
            sd.ServiceType == typeof(IAuthorizationCodeBackingStore) &&
            sd.ImplementationType == typeof(StubAuthorizationCodeBackingStore));
    }

    // ── AddInMemoryAuthorizationCodeStore: happy path ─────────────────────────────────────────────

    [Fact]
    public void AddInMemoryAuthorizationCodeStore_registers_IAuthorizationCodeBackingStore_as_singleton_with_InMemoryAuthorizationCodeBackingStore_implementation()
    {
        var services = new ServiceCollection();
        var builder = new ZeeKayDaAuthCoreBuilder(services);

        builder.AddInMemoryAuthorizationCodeStore();

        services.Should().Contain(sd =>
            sd.ServiceType == typeof(IAuthorizationCodeBackingStore) &&
            sd.ImplementationType == typeof(InMemoryAuthorizationCodeBackingStore) &&
            sd.Lifetime == ServiceLifetime.Singleton);
    }

    [Fact]
    public void AddInMemoryAuthorizationCodeStore_registers_the_framework_AuthorizationCodeStore()
    {
        var services = new ServiceCollection();
        var builder = new ZeeKayDaAuthCoreBuilder(services);

        builder.AddInMemoryAuthorizationCodeStore();

        services.Should().Contain(sd =>
            sd.ServiceType == typeof(AuthorizationCodeStore) &&
            sd.Lifetime == ServiceLifetime.Singleton);
    }

    [Fact]
    public void AddInMemoryAuthorizationCodeStore_registers_InMemoryStoreVerifier_as_IStartupVerifier()
    {
        var services = CreateServicesWithStoreVerifierDependencies();
        var builder = new ZeeKayDaAuthCoreBuilder(services);

        builder.AddInMemoryAuthorizationCodeStore();

        using var provider = services.BuildServiceProvider();
        provider.GetServices<IStartupVerifier>().Should().ContainSingle()
            .Which.Should().BeOfType<InMemoryStoreVerifier>();
    }

    // ── AddInMemoryAuthorizationCodeStore: double-registration guard ──────────────────────────────

    [Fact]
    public void AddInMemoryAuthorizationCodeStore_throws_InvalidOperationException_when_the_code_store_is_already_registered()
    {
        var services = new ServiceCollection();
        var builder = new ZeeKayDaAuthCoreBuilder(services);
        builder.AddInMemoryAuthorizationCodeStore();

        var act = () => builder.AddInMemoryAuthorizationCodeStore();

        act.Should().Throw<InvalidOperationException>()
            .WithMessage("*IAuthorizationCodeBackingStore is already registered*");
    }

    [Fact]
    public void AddInMemoryAuthorizationCodeStore_throws_InvalidOperationException_when_generic_AddAuthorizationCodeStore_was_called_first()
    {
        var services = new ServiceCollection();
        var builder = new ZeeKayDaAuthCoreBuilder(services);
        builder.AddAuthorizationCodeStore<StubAuthorizationCodeBackingStore>();

        var act = () => builder.AddInMemoryAuthorizationCodeStore();

        act.Should().Throw<InvalidOperationException>()
            .WithMessage("*IAuthorizationCodeBackingStore is already registered*");
    }

    // ── AddInMemoryRefreshTokenStore: happy path ──────────────────────────────────────────────────

    [Fact]
    public void AddInMemoryRefreshTokenStore_registers_the_framework_RefreshTokenStore()
    {
        var services = new ServiceCollection();
        var builder = new ZeeKayDaAuthCoreBuilder(services);

        builder.AddInMemoryRefreshTokenStore();

        services.Should().Contain(sd =>
            sd.ServiceType == typeof(RefreshTokenStore) &&
            sd.Lifetime == ServiceLifetime.Singleton);
        services.Should().Contain(sd =>
            sd.ServiceType == typeof(IRefreshTokenBackingStore) &&
            sd.ImplementationType == typeof(InMemoryRefreshTokenBackingStore) &&
            sd.Lifetime == ServiceLifetime.Singleton);
    }

    [Fact]
    public void AddInMemoryRefreshTokenStore_registers_InMemoryStoreVerifier_as_IStartupVerifier()
    {
        var services = CreateServicesWithStoreVerifierDependencies();
        var builder = new ZeeKayDaAuthCoreBuilder(services);

        builder.AddInMemoryRefreshTokenStore();

        using var provider = services.BuildServiceProvider();
        provider.GetServices<IStartupVerifier>().Should().ContainSingle()
            .Which.Should().BeOfType<InMemoryStoreVerifier>();
    }

    // ── AddInMemoryRefreshTokenStore: double-registration guard ───────────────────────────────────

    [Fact]
    public void AddInMemoryRefreshTokenStore_throws_InvalidOperationException_when_the_refresh_token_store_is_already_registered()
    {
        var services = new ServiceCollection();
        var builder = new ZeeKayDaAuthCoreBuilder(services);
        builder.AddInMemoryRefreshTokenStore();

        var act = () => builder.AddInMemoryRefreshTokenStore();

        act.Should().Throw<InvalidOperationException>()
            .WithMessage("*IRefreshTokenBackingStore is already registered*");
    }

    [Fact]
    public void AddInMemoryRefreshTokenStore_throws_InvalidOperationException_when_generic_AddRefreshTokenStore_was_called_first()
    {
        var services = new ServiceCollection();
        var builder = new ZeeKayDaAuthCoreBuilder(services);
        builder.AddRefreshTokenStore<StubRefreshTokenBackingStore>();

        var act = () => builder.AddInMemoryRefreshTokenStore();

        act.Should().Throw<InvalidOperationException>()
            .WithMessage("*IRefreshTokenBackingStore is already registered*");
    }

    // ── AddInMemoryStores: happy path ─────────────────────────────────────────────────────────────

    [Fact]
    public void AddInMemoryStores_registers_the_code_refresh_token_and_interaction_stores()
    {
        var services = new ServiceCollection();
        var builder = new ZeeKayDaAuthCoreBuilder(services);

        builder.AddInMemoryStores();

        services.Should().Contain(sd =>
            sd.ServiceType == typeof(IAuthorizationCodeBackingStore) &&
            sd.ImplementationType == typeof(InMemoryAuthorizationCodeBackingStore));
        services.Should().Contain(sd =>
            sd.ServiceType == typeof(RefreshTokenStore));
        services.Should().Contain(sd =>
            sd.ServiceType == typeof(IRefreshTokenBackingStore) &&
            sd.ImplementationType == typeof(InMemoryRefreshTokenBackingStore));
        services.Should().Contain(sd =>
            sd.ServiceType == typeof(IInteractionBackingStore) &&
            sd.ImplementationType == typeof(InMemoryInteractionBackingStore));
    }

    [Fact]
    public void AddInMemoryStores_registers_InMemoryStoreVerifier_once_per_store()
    {
        var services = CreateServicesWithStoreVerifierDependencies();
        var builder = new ZeeKayDaAuthCoreBuilder(services);

        builder.AddInMemoryStores();

        using var provider = services.BuildServiceProvider();
        provider.GetServices<IStartupVerifier>().OfType<InMemoryStoreVerifier>()
            .Should().HaveCount(3, "each of the three stores registers its own independently-gated verifier");
    }

    [Fact]
    public void Calling_AddInMemoryAuthorizationCodeStore_and_AddInMemoryRefreshTokenStore_separately_registers_InMemoryStoreVerifier_once_per_store()
    {
        var services = CreateServicesWithStoreVerifierDependencies();
        var builder = new ZeeKayDaAuthCoreBuilder(services);

        builder.AddInMemoryAuthorizationCodeStore();
        builder.AddInMemoryRefreshTokenStore();

        using var provider = services.BuildServiceProvider();
        provider.GetServices<IStartupVerifier>().OfType<InMemoryStoreVerifier>()
            .Should().HaveCount(2, "each store registration captures and enforces its own allowOutsideDevelopment value");
    }

    [Fact]
    public async Task AddInMemoryStores_produces_a_distinctly_worded_warning_per_store_not_the_same_warning_repeated()
    {
        var services = CreateServicesWithStoreVerifierDependencies();
        var builder = new ZeeKayDaAuthCoreBuilder(services);

        builder.AddInMemoryStores();

        using var provider = services.BuildServiceProvider();
        var contexts = new List<StartupVerificationContext>();
        foreach (var verifier in provider.GetServices<IStartupVerifier>().OfType<InMemoryStoreVerifier>())
        {
            var context = new StartupVerificationContext();
            await verifier.VerifyAsync(context, CancellationToken.None);
            contexts.Add(context);
        }

        var allArgs = contexts.SelectMany(c => c.Warnings).SelectMany(w => w.Args).ToList();
        allArgs.Distinct().Should().HaveCount(3,
            "each store's warning must name its own store, not repeat an identical value");
        allArgs.Should().Contain(InMemoryStoreVerifier.AuthorizationCodeStoreName);
        allArgs.Should().Contain(InMemoryStoreVerifier.RefreshTokenStoreName);
        allArgs.Should().Contain(InMemoryStoreVerifier.InteractionStoreName);
    }

    // ── AddInMemoryStores: allowOutsideDevelopment parameter ──────────────────────────────────────

    [Fact]
    public async Task AddInMemoryStores_passes_allowOutsideDevelopment_through_to_both_underlying_registrations()
    {
        var services = CreateServicesWithStoreVerifierDependencies(Environments.Production);
        var builder = new ZeeKayDaAuthCoreBuilder(services);

        builder.AddInMemoryStores(allowOutsideDevelopment: true);

        using var provider = services.BuildServiceProvider();
        var verifiers = provider.GetServices<IStartupVerifier>().OfType<InMemoryStoreVerifier>();

        foreach (var verifier in verifiers)
        {
            var context = new StartupVerificationContext();
            await verifier.VerifyAsync(context, CancellationToken.None);
            context.Failures.Should().BeEmpty();
        }
    }

    [Fact]
    public async Task Mixed_allowOutsideDevelopment_values_across_granular_calls_are_enforced_independently()
    {
        // Each of the three in-memory registration methods carries its own
        // allowOutsideDevelopment parameter and gates independently on it. Mixing granular calls
        // with different values must not let one call's override leak into the other's gate.
        var services = CreateServicesWithStoreVerifierDependencies(Environments.Production);
        var builder = new ZeeKayDaAuthCoreBuilder(services);

        builder.AddInMemoryAuthorizationCodeStore(allowOutsideDevelopment: true);
        builder.AddInMemoryRefreshTokenStore(allowOutsideDevelopment: false);

        using var provider = services.BuildServiceProvider();
        var verifiers = provider.GetServices<IStartupVerifier>()
            .OfType<InMemoryStoreVerifier>()
            .ToList();

        verifiers.Should().HaveCount(2);

        var outcomes = new List<bool>();
        foreach (var verifier in verifiers)
        {
            var context = new StartupVerificationContext();
            await verifier.VerifyAsync(context, CancellationToken.None);
            outcomes.Add(context.Failures.Count > 0);
        }

        outcomes.Should().ContainSingle(failed => failed,
            "the refresh-token-store registration (allowOutsideDevelopment: false) must still fail " +
            "closed outside Development even though the auth-code-store registration allowed it");
        outcomes.Should().ContainSingle(failed => !failed,
            "the auth-code-store registration (allowOutsideDevelopment: true) must not fail");
    }

    // ── AddInMemoryStores: per-interface guard independence ───────────────────────────────────────

    [Fact]
    public void AddInMemoryStores_throws_InvalidOperationException_when_the_code_store_is_already_registered_even_if_the_refresh_token_store_is_not()
    {
        var services = new ServiceCollection();
        var builder = new ZeeKayDaAuthCoreBuilder(services);
        builder.AddInMemoryAuthorizationCodeStore();

        var act = () => builder.AddInMemoryStores();

        act.Should().Throw<InvalidOperationException>()
            .WithMessage("*IAuthorizationCodeBackingStore is already registered*");
    }

    [Fact]
    public void AddInMemoryStores_throws_InvalidOperationException_when_the_refresh_token_store_is_already_registered_even_if_the_code_store_is_not()
    {
        var services = new ServiceCollection();
        var builder = new ZeeKayDaAuthCoreBuilder(services);
        builder.AddInMemoryRefreshTokenStore();

        // AddInMemoryStores calls AddInMemoryAuthorizationCodeStore first, which succeeds,
        // then AddInMemoryRefreshTokenStore, which must throw because it is already registered.
        var act = () => builder.AddInMemoryStores();

        act.Should().Throw<InvalidOperationException>()
            .WithMessage("*IRefreshTokenBackingStore is already registered*");
    }

    [Fact]
    public void AddInMemoryStores_throws_InvalidOperationException_when_an_interaction_store_is_already_registered()
    {
        var services = new ServiceCollection();
        var builder = new ZeeKayDaAuthCoreBuilder(services);
        builder.AddDistributedCacheInteractionStore();

        var act = () => builder.AddInMemoryStores();

        act.Should().Throw<InvalidOperationException>()
            .WithMessage("*interaction store is already registered*");
    }

    // ── AddInMemoryInteractionStore ───────────────────────────────────────────────────────────────

    [Fact]
    public void AddInMemoryInteractionStore_registers_the_per_process_store_and_its_gate()
    {
        // Control-presence: the gate on a per-process store outside Development is only a control
        // if the registration that creates the store also registers it.
        var services = CreateServicesWithStoreVerifierDependencies();
        var builder = new ZeeKayDaAuthCoreBuilder(services);

        builder.AddInMemoryInteractionStore();

        services.Should().Contain(sd =>
            sd.ServiceType == typeof(IInteractionBackingStore) &&
            sd.ImplementationType == typeof(InMemoryInteractionBackingStore) &&
            sd.Lifetime == ServiceLifetime.Singleton);
        using var provider = services.BuildServiceProvider();
        provider.GetServices<IStartupVerifier>().OfType<InMemoryStoreVerifier>()
            .Should().ContainSingle().Which.Name.Should().Be($"InMemoryStore({InMemoryStoreVerifier.InteractionStoreName})");
    }

    [Fact]
    public void AddInMemoryInteractionStore_throws_InvalidOperationException_when_an_interaction_store_is_already_registered()
    {
        var services = new ServiceCollection();
        var builder = new ZeeKayDaAuthCoreBuilder(services);
        builder.AddInMemoryInteractionStore();

        var act = () => builder.AddInMemoryInteractionStore();

        act.Should().Throw<InvalidOperationException>()
            .WithMessage("*interaction store is already registered*");
    }

    // ── AddDistributedCacheInteractionStore ───────────────────────────────────────────────────────

    [Fact]
    public void AddDistributedCacheInteractionStore_registers_the_cache_backed_store_and_its_gate()
    {
        var services = CreateServicesWithStoreVerifierDependencies();
        var builder = new ZeeKayDaAuthCoreBuilder(services);

        builder.AddDistributedCacheInteractionStore();

        services.Should().Contain(sd =>
            sd.ServiceType == typeof(IInteractionBackingStore) &&
            sd.ImplementationType == typeof(DistributedCacheInteractionBackingStore) &&
            sd.Lifetime == ServiceLifetime.Singleton);
        using var provider = services.BuildServiceProvider();
        provider.GetServices<IStartupActivator>()
            .Should().ContainSingle(activator => activator is DistributedCacheInteractionStoreActivator);
    }

    [Fact]
    public async Task AddDistributedCacheInteractionStore_passes_the_memory_cache_override_through_to_its_gate()
    {
        var services = CreateServicesWithStoreVerifierDependencies(Environments.Production);
        services.AddDistributedMemoryCache();
        var builder = new ZeeKayDaAuthCoreBuilder(services);

        builder.AddDistributedCacheInteractionStore(allowMemoryCacheOutsideDevelopment: true);

        using var provider = services.BuildServiceProvider();
        var gate = provider.GetServices<IStartupActivator>().OfType<DistributedCacheInteractionStoreActivator>().Single();
        var context = new StartupVerificationContext();
        await gate.VerifyAsync(context, CancellationToken.None);
        context.Failures.Should().BeEmpty();
        context.Warnings.Should().ContainSingle().Which.Code.Should().Be("stores.interaction.per_process_cache_override");
    }

    [Fact]
    public void AddDistributedCacheInteractionStore_throws_InvalidOperationException_when_an_interaction_store_is_already_registered()
    {
        var services = new ServiceCollection();
        var builder = new ZeeKayDaAuthCoreBuilder(services);
        builder.AddInMemoryInteractionStore();

        var act = () => builder.AddDistributedCacheInteractionStore();

        act.Should().Throw<InvalidOperationException>()
            .WithMessage("*interaction store is already registered*");
    }

    [Fact]
    public void Registering_an_interaction_store_does_not_block_the_token_store_registrations()
    {
        var services = new ServiceCollection();
        var builder = new ZeeKayDaAuthCoreBuilder(services);
        builder.AddDistributedCacheInteractionStore();

        var act = () => builder
            .AddAuthorizationCodeStore<StubAuthorizationCodeBackingStore>()
            .AddRefreshTokenStore<StubRefreshTokenBackingStore>();

        act.Should().NotThrow();
    }

    // ── Backing stores registered directly ────────────────────────────────────────────────────────

    [Fact]
    public void Backing_stores_registered_straight_on_the_service_collection_get_the_framework_stores_over_them()
    {
        // The backing contracts are public, so a host can register them without the builder
        // methods; the framework's own stores must still be there to run over them.
        var services = new ServiceCollection();
        services.AddSingleton(typeof(ILogger<>), typeof(NullLogger<>));
        services.AddZeeKayDaAuthCore(options => options.Issuer = "https://test.example.com");
        services.AddSingleton<IAuthorizationCodeBackingStore, StubAuthorizationCodeBackingStore>();
        services.AddSingleton<IRefreshTokenBackingStore, StubRefreshTokenBackingStore>();

        using var provider = services.BuildServiceProvider();

        provider.GetRequiredService<AuthorizationCodeStore>().Should().NotBeNull();
        provider.GetRequiredService<RefreshTokenStore>().Should().NotBeNull();
    }

    // ── No-op stub implementations ────────────────────────────────────────────────────────────────

    private sealed class StubAuthorizationCodeBackingStore : IAuthorizationCodeBackingStore
    {
        public Task<bool> TryInsertAsync(StoreKey key, ReadOnlyMemory<byte> value, DateTimeOffset expiresAt, CancellationToken cancellationToken)
            => Task.FromResult(true);

        public Task<ReadOnlyMemory<byte>?> GetAsync(StoreKey key, CancellationToken cancellationToken)
            => Task.FromResult<ReadOnlyMemory<byte>?>(null);

        public Task RemoveAsync(StoreKey key, CancellationToken cancellationToken)
            => Task.CompletedTask;
    }

    private sealed class AnotherStubAuthorizationCodeBackingStore : IAuthorizationCodeBackingStore
    {
        public Task<bool> TryInsertAsync(StoreKey key, ReadOnlyMemory<byte> value, DateTimeOffset expiresAt, CancellationToken cancellationToken)
            => Task.FromResult(true);

        public Task<ReadOnlyMemory<byte>?> GetAsync(StoreKey key, CancellationToken cancellationToken)
            => Task.FromResult<ReadOnlyMemory<byte>?>(null);

        public Task RemoveAsync(StoreKey key, CancellationToken cancellationToken)
            => Task.CompletedTask;
    }

    private sealed class StubRefreshTokenBackingStore : IRefreshTokenBackingStore
    {
        public Task InsertAsync(RefreshTokenGrant grant, CancellationToken cancellationToken)
            => Task.CompletedTask;

        public Task<RefreshTokenGrant?> FindByHandleAsync(StoreKey handleHash, CancellationToken cancellationToken)
            => Task.FromResult<RefreshTokenGrant?>(null);

        public Task<bool> TryMarkConsumedAsync(StoreKey handleHash, CancellationToken cancellationToken)
            => Task.FromResult(false);

        public Task RevokeFamilyAsync(string familyId, DateTimeOffset rememberUntil, CancellationToken cancellationToken)
            => Task.CompletedTask;

        public Task RevokeBySubjectAsync(string subject, CancellationToken cancellationToken)
            => Task.CompletedTask;

        public Task<bool> IsFamilyRevokedAsync(string familyId, CancellationToken cancellationToken)
            => Task.FromResult(false);
    }

    private sealed class AnotherStubRefreshTokenBackingStore : IRefreshTokenBackingStore
    {
        public Task InsertAsync(RefreshTokenGrant grant, CancellationToken cancellationToken)
            => Task.CompletedTask;

        public Task<RefreshTokenGrant?> FindByHandleAsync(StoreKey handleHash, CancellationToken cancellationToken)
            => Task.FromResult<RefreshTokenGrant?>(null);

        public Task<bool> TryMarkConsumedAsync(StoreKey handleHash, CancellationToken cancellationToken)
            => Task.FromResult(false);

        public Task RevokeFamilyAsync(string familyId, DateTimeOffset rememberUntil, CancellationToken cancellationToken)
            => Task.CompletedTask;

        public Task RevokeBySubjectAsync(string subject, CancellationToken cancellationToken)
            => Task.CompletedTask;

        public Task<bool> IsFamilyRevokedAsync(string familyId, CancellationToken cancellationToken)
            => Task.FromResult(false);
    }
}
