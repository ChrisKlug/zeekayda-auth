using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Options;
using ZeeKayDa.Auth.Tokens;

namespace ZeeKayDa.Auth.AspNetCore.Tests.Extensions;

public sealed class ZeeKayDaAuthBuilderSigningExtensionsTests
{
    // ── Argument validation ───────────────────────────────────────────────────────────────────────

    [Fact]
    public void AddDevelopmentJwtSigningKeys_throws_ArgumentNullException_when_builder_is_null()
    {
        var act = () => ((ZeeKayDaAuthBuilder)null!).AddDevelopmentJwtSigningKeys();

        act.Should().Throw<ArgumentNullException>().WithParameterName("builder");
    }

    // ── Ephemeral mode (no argument) ─────────────────────────────────────────────────────────────

    [Fact]
    public async Task AddDevelopmentJwtSigningKeys_with_no_argument_registers_IJwtSigningService()
    {
        var services = new ServiceCollection();
        services.AddSingleton<IHostEnvironment>(new FakeHostEnvironment { ContentRootPath = "/app" });
        var builder = new ZeeKayDaAuthBuilder(services);

        builder.AddDevelopmentJwtSigningKeys();

        await using var provider = services.BuildServiceProvider();
        var service = provider.GetRequiredService<IJwtSigningService>();
        service.Should().BeOfType<DevelopmentJwtSigningService>();
    }

    [Fact]
    public async Task AddDevelopmentJwtSigningKeys_with_no_argument_leaves_PersistToDirectory_null()
    {
        var services = new ServiceCollection();
        services.AddSingleton<IHostEnvironment>(new FakeHostEnvironment { ContentRootPath = "/app" });
        var builder = new ZeeKayDaAuthBuilder(services);

        builder.AddDevelopmentJwtSigningKeys();

        await using var provider = services.BuildServiceProvider();
        var options = provider.GetRequiredService<IOptions<DevelopmentSigningKeyOptions>>().Value;
        options.PersistToDirectory.Should().BeNull("no argument means ephemeral mode");
    }

    [Fact]
    public async Task AddDevelopmentJwtSigningKeys_with_no_argument_registers_TimeProvider_System_singleton()
    {
        var services = new ServiceCollection();
        services.AddSingleton<IHostEnvironment>(new FakeHostEnvironment { ContentRootPath = "/app" });
        var builder = new ZeeKayDaAuthBuilder(services);

        builder.AddDevelopmentJwtSigningKeys();

        await using var provider = services.BuildServiceProvider();
        var tp = provider.GetRequiredService<TimeProvider>();
        tp.Should().BeSameAs(TimeProvider.System);
    }

    [Fact]
    public async Task AddDevelopmentJwtSigningKeys_does_not_overwrite_already_registered_TimeProvider()
    {
        var services = new ServiceCollection();
        services.AddSingleton<IHostEnvironment>(new FakeHostEnvironment { ContentRootPath = "/app" });

        // Pre-register a custom TimeProvider (e.g. a test double) before calling the extension.
        var customTimeProvider = new StubTimeProvider();
        services.AddSingleton<TimeProvider>(customTimeProvider);

        var builder = new ZeeKayDaAuthBuilder(services);
        builder.AddDevelopmentJwtSigningKeys();

        await using var provider = services.BuildServiceProvider();
        var tp = provider.GetRequiredService<TimeProvider>();
        tp.Should().BeSameAs(customTimeProvider, "TryAddSingleton must not overwrite a pre-registered TimeProvider");
    }

    private sealed class StubTimeProvider : TimeProvider;

    [Fact]
    public void AddDevelopmentJwtSigningKeys_registers_DevelopmentSigningKeyWarningService_as_IHostedService()
    {
        var services = new ServiceCollection();
        services.AddSingleton<IHostEnvironment>(new FakeHostEnvironment { ContentRootPath = "/app" });
        var builder = new ZeeKayDaAuthBuilder(services);

        builder.AddDevelopmentJwtSigningKeys();

        var registrations = services
            .Where(d => d.ServiceType == typeof(IHostedService))
            .ToList();
        registrations.Should().ContainSingle(d =>
            d.ImplementationType == typeof(DevelopmentSigningKeyWarningService));
    }

    [Fact]
    public void AddDevelopmentJwtSigningKeys_returns_builder_for_chaining()
    {
        var services = new ServiceCollection();
        services.AddSingleton<IHostEnvironment>(new FakeHostEnvironment { ContentRootPath = "/app" });
        var builder = new ZeeKayDaAuthBuilder(services);

        var returned = builder.AddDevelopmentJwtSigningKeys();

        returned.Should().BeSameAs(builder);
    }

    // ── Persist to default path (null argument) ──────────────────────────────────────────────────

    [Fact]
    public async Task AddDevelopmentJwtSigningKeys_with_null_sets_PersistToDirectory_to_default_path()
    {
        var services = new ServiceCollection();
        services.AddSingleton<IHostEnvironment>(new FakeHostEnvironment { ContentRootPath = "/app" });
        var builder = new ZeeKayDaAuthBuilder(services);

        builder.AddDevelopmentJwtSigningKeys(persistTo: null);

        await using var provider = services.BuildServiceProvider();
        var options = provider.GetRequiredService<IOptions<DevelopmentSigningKeyOptions>>().Value;
        options.PersistToDirectory.Should().Be(
            Path.Join("/app", ".zeekayda", "signing-keys"),
            "null means default path under ContentRootPath");
    }

    // ── Persist to explicit path ──────────────────────────────────────────────────────────────────

    [Fact]
    public async Task AddDevelopmentJwtSigningKeys_with_explicit_path_sets_PersistToDirectory()
    {
        var services = new ServiceCollection();
        services.AddSingleton<IHostEnvironment>(new FakeHostEnvironment { ContentRootPath = "/app" });
        var builder = new ZeeKayDaAuthBuilder(services);

        builder.AddDevelopmentJwtSigningKeys(persistTo: "/custom/keys");

        await using var provider = services.BuildServiceProvider();
        var options = provider.GetRequiredService<IOptions<DevelopmentSigningKeyOptions>>().Value;
        options.PersistToDirectory.Should().Be("/custom/keys");
    }

    // ── Double-registration guard ─────────────────────────────────────────────────────────────────

    [Fact]
    public void AddDevelopmentJwtSigningKeys_throws_InvalidOperationException_when_called_twice()
    {
        var services = new ServiceCollection();
        services.AddSingleton<IHostEnvironment>(new FakeHostEnvironment { ContentRootPath = "/app" });
        var builder = new ZeeKayDaAuthBuilder(services);
        builder.AddDevelopmentJwtSigningKeys();

        var act = () => builder.AddDevelopmentJwtSigningKeys();

        act.Should().Throw<InvalidOperationException>()
            .WithMessage("*IJwtSigningService*already registered*");
    }

    // ── Helpers ───────────────────────────────────────────────────────────────────────────────────

    private sealed class FakeHostEnvironment : IHostEnvironment
    {
        public string EnvironmentName { get; set; } = "Development";
        public string ApplicationName { get; set; } = "TestApp";
        public string ContentRootPath { get; set; } = "/app";
        public Microsoft.Extensions.FileProviders.IFileProvider ContentRootFileProvider { get; set; } = null!;
    }
}
