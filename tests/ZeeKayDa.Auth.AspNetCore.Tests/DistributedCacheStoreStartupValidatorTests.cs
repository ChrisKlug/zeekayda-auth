using Microsoft.Extensions.Caching.Distributed;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using ZeeKayDa.Auth;
using ZeeKayDa.Auth.AspNetCore;
using ZeeKayDa.Auth.Logging;

namespace ZeeKayDa.Auth.AspNetCore.Tests;

public sealed class DistributedCacheStoreStartupValidatorTests
{
    // ── Fake infrastructure ───────────────────────────────────────────────────────────────────────

    private sealed class CapturingLogger<T> : ISanitizingLogger<T>
    {
        public List<(LogLevel Level, string Message)> Entries { get; } = [];

        public IDisposable? BeginScope<TState>(TState state) where TState : notnull => null;

        public bool IsEnabled(LogLevel logLevel) => true;

        public void Log<TState>(
            LogLevel logLevel,
            EventId eventId,
            TState state,
            Exception? exception,
            Func<TState, Exception?, string> formatter)
        {
            Entries.Add((logLevel, formatter(state, exception)));
        }
    }

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

    private static DistributedCacheStoreStartupValidator BuildSut(
        Action<IServiceCollection> configure,
        CapturingLogger<DistributedCacheStoreStartupValidator>? logger = null)
    {
        var services = new ServiceCollection();
        configure(services);
        return new DistributedCacheStoreStartupValidator(
            services.BuildServiceProvider().GetRequiredService<IServiceScopeFactory>(),
            logger ?? new CapturingLogger<DistributedCacheStoreStartupValidator>());
    }

    // ── Constructor: argument validation ─────────────────────────────────────────────────────────

    [Fact]
    public void Constructor_throws_ArgumentNullException_when_scopeFactory_is_null()
    {
        var act = () => new DistributedCacheStoreStartupValidator(
            null!,
            NullSanitizingLogger<DistributedCacheStoreStartupValidator>.Instance);

        act.Should().Throw<ArgumentNullException>().WithParameterName("scopeFactory");
    }

    [Fact]
    public void Constructor_throws_ArgumentNullException_when_logger_is_null()
    {
        var services = new ServiceCollection();
        var scopeFactory = services.BuildServiceProvider().GetRequiredService<IServiceScopeFactory>();

        var act = () => new DistributedCacheStoreStartupValidator(scopeFactory, null!);

        act.Should().Throw<ArgumentNullException>().WithParameterName("logger");
    }

    // ── StartAsync: IDistributedCache absent ──────────────────────────────────────────────────────

    [Fact]
    public async Task StartAsync_throws_ZeeKayDaConfigurationException_when_IDistributedCache_is_not_registered()
    {
        var sut = BuildSut(_ => { });

        await sut.Awaiting(s => s.StartAsync(CancellationToken.None))
            .Should().ThrowAsync<ZeeKayDaConfigurationException>();
    }

    [Fact]
    public async Task StartAsync_throws_with_code_stores_idistributedcache_missing()
    {
        var sut = BuildSut(_ => { });

        var ex = await sut.Awaiting(s => s.StartAsync(CancellationToken.None))
            .Should().ThrowAsync<ZeeKayDaConfigurationException>();

        ex.Which.AggregatedFailures.Should().ContainSingle()
            .Which.Code.Should().Be("stores.idistributedcache.missing");
    }

    [Fact]
    public async Task StartAsync_throws_with_message_mentioning_AddDistributedMemoryCache()
    {
        var sut = BuildSut(_ => { });

        var ex = await sut.Awaiting(s => s.StartAsync(CancellationToken.None))
            .Should().ThrowAsync<ZeeKayDaConfigurationException>();

        ex.Which.Message.Should().Contain("AddDistributedMemoryCache");
    }

    // ── StartAsync: MemoryDistributedCache — no warning ───────────────────────────────────────────

    [Fact]
    public async Task StartAsync_completes_without_logging_when_IDistributedCache_is_MemoryDistributedCache()
    {
        var logger = new CapturingLogger<DistributedCacheStoreStartupValidator>();
        var sut = BuildSut(services => services.AddDistributedMemoryCache(), logger);

        await sut.StartAsync(CancellationToken.None);

        logger.Entries.Should().BeEmpty("MemoryDistributedCache is the expected dev/test implementation");
    }

    // ── StartAsync: non-memory implementation — warning emitted ──────────────────────────────────

    [Fact]
    public async Task StartAsync_logs_Warning_when_IDistributedCache_is_not_MemoryDistributedCache()
    {
        var logger = new CapturingLogger<DistributedCacheStoreStartupValidator>();
        var sut = BuildSut(
            services => services.AddSingleton<IDistributedCache, FakeDistributedCache>(),
            logger);

        await sut.StartAsync(CancellationToken.None);

        logger.Entries.Should().ContainSingle()
            .Which.Level.Should().Be(LogLevel.Warning);
    }

    [Fact]
    public async Task StartAsync_logs_exactly_once_when_IDistributedCache_is_non_memory_implementation()
    {
        var logger = new CapturingLogger<DistributedCacheStoreStartupValidator>();
        var sut = BuildSut(
            services => services.AddSingleton<IDistributedCache, FakeDistributedCache>(),
            logger);

        await sut.StartAsync(CancellationToken.None);

        logger.Entries.Should().HaveCount(1);
    }

    [Fact]
    public async Task StartAsync_logs_the_exact_WarningMessage_text()
    {
        var logger = new CapturingLogger<DistributedCacheStoreStartupValidator>();
        var sut = BuildSut(
            services => services.AddSingleton<IDistributedCache, FakeDistributedCache>(),
            logger);

        await sut.StartAsync(CancellationToken.None);

        logger.Entries.Should().ContainSingle()
            .Which.Message.Should().Be(DistributedCacheStoreStartupValidator.WarningMessage);
    }

    // ── StopAsync: no side effects ────────────────────────────────────────────────────────────────

    [Fact]
    public async Task StopAsync_does_not_throw()
    {
        var sut = BuildSut(services => services.AddDistributedMemoryCache());

        await sut.Awaiting(s => s.StopAsync(CancellationToken.None)).Should().NotThrowAsync();
    }
}
