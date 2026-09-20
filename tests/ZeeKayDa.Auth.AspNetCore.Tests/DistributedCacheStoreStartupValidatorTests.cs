using Microsoft.Extensions.Caching.Distributed;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.FileProviders;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;

namespace ZeeKayDa.Auth.AspNetCore.Tests;

/// <summary>
/// The startup gate on a distributed-cache-backed token store: a cache must be registered, and
/// outside Development it must not be the per-process one.
/// </summary>
public sealed class DistributedCacheStoreStartupValidatorTests
{
    private const string StoreName = DistributedCacheStoreStartupValidator.AuthorizationCodeStoreName;

    // ── Fake infrastructure ───────────────────────────────────────────────────────────────────────

    private sealed class FakeHostEnvironment(string environmentName) : IHostEnvironment
    {
        public string EnvironmentName { get; set; } = environmentName;
        public string ApplicationName { get; set; } = "TestApp";
        public string ContentRootPath { get; set; } = "/";
        public IFileProvider ContentRootFileProvider { get; set; } = new NullFileProvider();
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

    private static async Task<StartupVerificationContext> VerifyAsync(
        string environment,
        Action<IServiceCollection> configure,
        bool allowMemoryCacheOutsideDevelopment = false,
        string storeName = StoreName)
    {
        var services = new ServiceCollection();
        configure(services);
        using var provider = services.BuildServiceProvider();
        var sut = new DistributedCacheStoreStartupValidator(
            new FakeHostEnvironment(environment),
            storeName,
            allowMemoryCacheOutsideDevelopment);
        var context = new StartupVerificationContext();

        await sut.VerifyAsync(context, provider, TestContext.Current.CancellationToken);

        return context;
    }

    // ── IDistributedCache absent ──────────────────────────────────────────────────────────────────

    [Fact]
    public async Task No_cache_registered_fails_startup()
    {
        var context = await VerifyAsync(Environments.Development, _ => { });

        context.Failures.Should().ContainSingle()
            .Which.Code.Should().Be("stores.idistributedcache.missing");
    }

    [Fact]
    public async Task No_cache_registered_names_AddDistributedMemoryCache_in_the_failure()
    {
        var context = await VerifyAsync(Environments.Development, _ => { });

        context.Failures.Single().Message.Should().Contain("AddDistributedMemoryCache");
    }

    // ── The per-process cache, by environment ─────────────────────────────────────────────────────

    [Fact]
    public async Task The_per_process_cache_in_Development_logs_at_Information_on_every_start()
    {
        var context = await VerifyAsync(Environments.Development, services => services.AddDistributedMemoryCache());

        context.Failures.Should().BeEmpty();
        var warning = context.Warnings.Should().ContainSingle().Which;
        warning.Code.Should().Be("stores.token.per_process_cache_active");
        warning.Level.Should().Be(LogLevel.Information);
        warning.MessageTemplate.Should().Be(DistributedCacheStoreStartupValidator.PerProcessCacheActiveMessageFormat);
    }

    [Theory]
    [InlineData("Production")]
    [InlineData("Staging")]
    public async Task The_per_process_cache_outside_Development_fails_startup_for_a_token_store(string environment)
    {
        // The gap this issue closes: the validator did not look at the environment at all, so a
        // MemoryDistributedCache-backed token store started silently in Production. Despite its
        // name that cache is shared with nothing, so an authorization code issued by one instance
        // cannot be redeemed at another and single-use enforcement holds only per process.
        var context = await VerifyAsync(environment, services => services.AddDistributedMemoryCache());

        context.Failures.Should().ContainSingle()
            .Which.Code.Should().Be("stores.token.per_process_cache");
        context.Failures.Single().Message.Should().Contain("allowMemoryCacheOutsideDevelopment");
    }

    [Fact]
    public async Task The_per_process_cache_outside_Development_with_the_override_warns_at_Critical_on_every_start()
    {
        var context = await VerifyAsync(
            Environments.Production,
            services => services.AddDistributedMemoryCache(),
            allowMemoryCacheOutsideDevelopment: true);

        context.Failures.Should().BeEmpty();
        var warning = context.Warnings.Should().ContainSingle().Which;
        warning.Code.Should().Be("stores.token.per_process_cache_override");
        warning.Level.Should().Be(LogLevel.Critical);
        warning.MessageTemplate.Should().Be(DistributedCacheStoreStartupValidator.PerProcessCacheOverrideWarningMessageFormat);
    }

    [Fact]
    public async Task The_failure_names_the_store_it_is_about()
    {
        // One validator is registered per store, both report in the same phase, and the runner
        // collapses failures identical in code and message. A message naming no store would report
        // one of two broken registrations and hide the other until the next restart.
        var context = await VerifyAsync(
            Environments.Production,
            services => services.AddDistributedMemoryCache(),
            storeName: DistributedCacheStoreStartupValidator.RefreshTokenStoreName);

        context.Failures.Single().Message.Should().Contain(DistributedCacheStoreStartupValidator.RefreshTokenStoreName);
    }

    // ── A real shared cache ───────────────────────────────────────────────────────────────────────

    [Theory]
    [InlineData("Development")]
    [InlineData("Production")]
    public async Task A_shared_cache_warns_that_the_stores_are_non_atomic_in_every_environment(string environment)
    {
        // A different concern from the environment gate, and not fixed by a shared cache: these
        // stores cannot make check-and-set atomic, so a multi-instance deployment is exposed to
        // double redemption whatever is behind IDistributedCache.
        var context = await VerifyAsync(environment, services => services.AddSingleton<IDistributedCache, FakeDistributedCache>());

        context.Failures.Should().BeEmpty();
        var warning = context.Warnings.Should().ContainSingle().Which;
        warning.Code.Should().Be("stores.idistributedcache.non_atomic");
        warning.MessageTemplate.Should().Be(DistributedCacheStoreStartupValidator.WarningMessage);
    }
}
