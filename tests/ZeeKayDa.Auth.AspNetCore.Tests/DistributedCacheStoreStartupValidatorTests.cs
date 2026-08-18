using Microsoft.Extensions.Caching.Distributed;
using Microsoft.Extensions.DependencyInjection;
using ZeeKayDa.Auth;
using ZeeKayDa.Auth.AspNetCore;

namespace ZeeKayDa.Auth.AspNetCore.Tests;

public sealed class DistributedCacheStoreStartupValidatorTests
{
    // ── Fake infrastructure ───────────────────────────────────────────────────────────────────────

    private sealed class FakeDistributedCache : IDistributedCache
    {
        public byte[]? Get(string key) => null;
        public Task<byte[]?> GetAsync(string key, CancellationToken token = default) => Task.FromResult<byte[]?>(null);
        public void Refresh(string key) { }
        public Task RefreshAsync(string key, CancellationToken token = default) => Task.CompletedTask;
        public void Remove(string key) { }
        public Task RemoveAsync(string key, CancellationToken token = default) => Task.CompletedTask;
        public void Set(string key, byte[] value, DistributedCacheEntryOptions options) { }
        public Task SetAsync(string key, byte[] value, DistributedCacheEntryOptions options, CancellationToken token = default) => Task.CompletedTask;
    }

    private static (DistributedCacheStoreStartupValidator Sut, IServiceProvider Provider) BuildSut(
        Action<IServiceCollection> configure)
    {
        var services = new ServiceCollection();
        configure(services);
        return (new DistributedCacheStoreStartupValidator(), services.BuildServiceProvider());
    }

    // ── VerifyAsync: IDistributedCache absent ─────────────────────────────────────────────────────

    [Fact]
    public async Task VerifyAsync_adds_a_failure_when_IDistributedCache_is_not_registered()
    {
        var (sut, provider) = BuildSut(_ => { });
        var context = new StartupVerificationContext();

        await sut.VerifyAsync(context, provider, TestContext.Current.CancellationToken);

        context.Failures.Should().ContainSingle();
    }

    [Fact]
    public async Task VerifyAsync_adds_a_failure_with_code_stores_idistributedcache_missing()
    {
        var (sut, provider) = BuildSut(_ => { });
        var context = new StartupVerificationContext();

        await sut.VerifyAsync(context, provider, TestContext.Current.CancellationToken);

        context.Failures.Should().ContainSingle()
            .Which.Code.Should().Be("stores.idistributedcache.missing");
    }

    [Fact]
    public async Task VerifyAsync_adds_a_failure_mentioning_AddDistributedMemoryCache()
    {
        var (sut, provider) = BuildSut(_ => { });
        var context = new StartupVerificationContext();

        await sut.VerifyAsync(context, provider, TestContext.Current.CancellationToken);

        context.Failures.Single().Message.Should().Contain("AddDistributedMemoryCache");
    }

    // ── VerifyAsync: MemoryDistributedCache — no warning ──────────────────────────────────────────

    [Fact]
    public async Task VerifyAsync_adds_nothing_when_IDistributedCache_is_MemoryDistributedCache()
    {
        var (sut, provider) = BuildSut(services => services.AddDistributedMemoryCache());
        var context = new StartupVerificationContext();

        await sut.VerifyAsync(context, provider, TestContext.Current.CancellationToken);

        context.Warnings.Should().BeEmpty("MemoryDistributedCache is the expected dev/test implementation");
        context.Failures.Should().BeEmpty();
    }

    // ── VerifyAsync: non-memory implementation — warning emitted ──────────────────────────────────

    [Fact]
    public async Task VerifyAsync_adds_a_warning_when_IDistributedCache_is_not_MemoryDistributedCache()
    {
        var (sut, provider) = BuildSut(services => services.AddSingleton<IDistributedCache, FakeDistributedCache>());
        var context = new StartupVerificationContext();

        await sut.VerifyAsync(context, provider, TestContext.Current.CancellationToken);

        context.Warnings.Should().ContainSingle();
        context.Failures.Should().BeEmpty();
    }

    [Fact]
    public async Task VerifyAsync_adds_a_warning_with_code_stores_idistributedcache_non_atomic()
    {
        var (sut, provider) = BuildSut(services => services.AddSingleton<IDistributedCache, FakeDistributedCache>());
        var context = new StartupVerificationContext();

        await sut.VerifyAsync(context, provider, TestContext.Current.CancellationToken);

        context.Warnings.Should().ContainSingle()
            .Which.Code.Should().Be("stores.idistributedcache.non_atomic");
    }

    [Fact]
    public async Task VerifyAsync_adds_the_exact_WarningMessage_text()
    {
        var (sut, provider) = BuildSut(services => services.AddSingleton<IDistributedCache, FakeDistributedCache>());
        var context = new StartupVerificationContext();

        await sut.VerifyAsync(context, provider, TestContext.Current.CancellationToken);

        context.Warnings.Should().ContainSingle()
            .Which.MessageTemplate.Should().Be(DistributedCacheStoreStartupValidator.WarningMessage);
    }

    [Fact]
    public void Name_is_DistributedCacheStore()
    {
        var sut = new DistributedCacheStoreStartupValidator();

        sut.Name.Should().Be("DistributedCacheStore");
    }
}
