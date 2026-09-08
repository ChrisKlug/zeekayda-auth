using Microsoft.Extensions.Caching.Distributed;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.FileProviders;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using ZeeKayDa.Auth;
using ZeeKayDa.Auth.AspNetCore;

namespace ZeeKayDa.Auth.AspNetCore.Tests;

/// <summary>
/// The startup gate on the distributed-cache interaction store: a cache must be registered, and
/// outside Development it must not be the per-process one.
/// </summary>
public sealed class DistributedCacheInteractionStoreStartupValidatorTests
{
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
        bool allowMemoryCacheOutsideDevelopment = false)
    {
        var services = new ServiceCollection();
        configure(services);
        using var provider = services.BuildServiceProvider();
        var sut = new DistributedCacheInteractionStoreStartupValidator(new FakeHostEnvironment(environment), allowMemoryCacheOutsideDevelopment);
        var context = new StartupVerificationContext();

        await sut.VerifyAsync(context, provider, TestContext.Current.CancellationToken);

        return context;
    }

    [Fact]
    public async Task No_cache_registered_fails_startup()
    {
        var context = await VerifyAsync(Environments.Development, _ => { });

        context.Failures.Should().ContainSingle()
            .Which.Code.Should().Be("stores.idistributedcache.missing");
    }

    [Fact]
    public async Task The_per_process_cache_in_Development_passes_quietly()
    {
        var context = await VerifyAsync(Environments.Development, services => services.AddDistributedMemoryCache());

        context.Failures.Should().BeEmpty();
        context.Warnings.Should().BeEmpty();
    }

    [Theory]
    [InlineData("Production")]
    [InlineData("Staging")]
    public async Task The_per_process_cache_outside_Development_fails_startup(string environment)
    {
        // Despite its name, MemoryDistributedCache is shared with nothing. Behind a load balancer
        // the login POST lands on an instance that never saw the authorize request.
        var context = await VerifyAsync(environment, services => services.AddDistributedMemoryCache());

        context.Failures.Should().ContainSingle()
            .Which.Code.Should().Be("stores.interaction.per_process_cache");
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
        warning.Code.Should().Be("stores.interaction.per_process_cache_override");
        warning.Level.Should().Be(LogLevel.Critical);
        warning.MessageTemplate.Should().Be(DistributedCacheInteractionStoreStartupValidator.PerProcessCacheOverrideWarningMessage);
    }

    [Theory]
    [InlineData("Development")]
    [InlineData("Production")]
    public async Task A_shared_cache_passes_in_every_environment(string environment)
    {
        // Set, get and remove are what a distributed cache is; a shared one is a complete answer
        // for the interaction store, so there is nothing to warn about.
        var context = await VerifyAsync(environment, services => services.AddSingleton<IDistributedCache, FakeDistributedCache>());

        context.Failures.Should().BeEmpty();
        context.Warnings.Should().BeEmpty();
    }
}
