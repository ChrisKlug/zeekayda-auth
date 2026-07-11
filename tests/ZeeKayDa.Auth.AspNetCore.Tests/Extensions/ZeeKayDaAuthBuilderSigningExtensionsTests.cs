using System.Reflection;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Options;
using ZeeKayDa.Auth.Tokens;

namespace ZeeKayDa.Auth.AspNetCore.Tests.Extensions;

public sealed class ZeeKayDaAuthBuilderSigningExtensionsTests
{
    // ── Configure surface type guarantee (issue #338 follow-up — PersistToDirectory must not be
    // reachable from AddInMemoryDevelopmentJwtSigningKeys' public configure callback) ───────────────

    [Fact]
    public void AddInMemoryDevelopmentJwtSigningKeys_configure_parameter_type_has_no_PersistToDirectory()
    {
        // Reflects on the actual public method signature — the type used here is precisely what a
        // caller's configure lambda is checked against by the compiler, so this pins the
        // compile-time guarantee: no source file could ever write
        // "AddInMemoryDevelopmentJwtSigningKeys(o => o.PersistToDirectory = ...)" because the
        // parameter type used for "o" has no such member.
        var method = typeof(ZeeKayDaAuthBuilderSigningExtensions).GetMethod(
            nameof(ZeeKayDaAuthBuilderSigningExtensions.AddInMemoryDevelopmentJwtSigningKeys));

        var configureParameterType = method!.GetParameters()
            .Single(p => p.Name == "configure").ParameterType;
        var callbackTargetType = configureParameterType.GetGenericArguments().Single();

        callbackTargetType.Should().Be(typeof(InMemoryDevelopmentSigningKeyOptions));
        callbackTargetType.GetProperty(
                "PersistToDirectory", BindingFlags.Public | BindingFlags.Instance)
            .Should().BeNull();
    }

    [Fact]
    public void AddPersistedDevelopmentJwtSigningKeys_configure_parameter_type_has_PersistToDirectory()
    {
        var method = typeof(ZeeKayDaAuthBuilderSigningExtensions).GetMethod(
            nameof(ZeeKayDaAuthBuilderSigningExtensions.AddPersistedDevelopmentJwtSigningKeys));

        var configureParameterType = method!.GetParameters()
            .Single(p => p.Name == "configure").ParameterType;
        var callbackTargetType = configureParameterType.GetGenericArguments().Single();

        callbackTargetType.Should().Be(typeof(DevelopmentSigningKeyOptions));
        callbackTargetType.GetProperty(
                "PersistToDirectory", BindingFlags.Public | BindingFlags.Instance)
            .Should().NotBeNull("the persisted variant's configure surface legitimately needs it");
    }

    // ── Argument validation ───────────────────────────────────────────────────────────────────────

    [Fact]
    public void AddInMemoryDevelopmentJwtSigningKeys_throws_ArgumentNullException_when_builder_is_null()
    {
        var act = () => ((ZeeKayDaAuthBuilder)null!).AddInMemoryDevelopmentJwtSigningKeys();

        act.Should().Throw<ArgumentNullException>().WithParameterName("builder");
    }

    [Fact]
    public void AddPersistedDevelopmentJwtSigningKeys_throws_ArgumentNullException_when_builder_is_null()
    {
        var act = () => ((ZeeKayDaAuthBuilder)null!).AddPersistedDevelopmentJwtSigningKeys();

        act.Should().Throw<ArgumentNullException>().WithParameterName("builder");
    }

    // ── Ephemeral mode (AddInMemoryDevelopmentJwtSigningKeys) ────────────────────────────────────

    [Fact]
    public async Task AddInMemoryDevelopmentJwtSigningKeys_registers_IJwtSigningService()
    {
        var services = new ServiceCollection();
        services.AddSingleton<IHostEnvironment>(new FakeHostEnvironment { ContentRootPath = "/app" });
        var builder = new ZeeKayDaAuthBuilder(services);

        builder.AddInMemoryDevelopmentJwtSigningKeys();

        await using var provider = services.BuildServiceProvider();
        var service = provider.GetRequiredService<IJwtSigningService>();
        service.Should().BeOfType<DevelopmentJwtSigningService>();
    }

    [Fact]
    public async Task AddInMemoryDevelopmentJwtSigningKeys_leaves_PersistToDirectory_null()
    {
        var services = new ServiceCollection();
        services.AddSingleton<IHostEnvironment>(new FakeHostEnvironment { ContentRootPath = "/app" });
        var builder = new ZeeKayDaAuthBuilder(services);

        builder.AddInMemoryDevelopmentJwtSigningKeys();

        await using var provider = services.BuildServiceProvider();
        var options = provider.GetRequiredService<IOptions<DevelopmentSigningKeyOptions>>().Value;
        options.PersistToDirectory.Should().BeNull("this method registers the ephemeral in-memory provider");
    }

    [Fact]
    public async Task AddInMemoryDevelopmentJwtSigningKeys_registers_TimeProvider_System_singleton()
    {
        var services = new ServiceCollection();
        services.AddSingleton<IHostEnvironment>(new FakeHostEnvironment { ContentRootPath = "/app" });
        var builder = new ZeeKayDaAuthBuilder(services);

        builder.AddInMemoryDevelopmentJwtSigningKeys();

        await using var provider = services.BuildServiceProvider();
        var tp = provider.GetRequiredService<TimeProvider>();
        tp.Should().BeSameAs(TimeProvider.System);
    }

    [Fact]
    public async Task AddInMemoryDevelopmentJwtSigningKeys_does_not_overwrite_already_registered_TimeProvider()
    {
        var services = new ServiceCollection();
        services.AddSingleton<IHostEnvironment>(new FakeHostEnvironment { ContentRootPath = "/app" });

        // Pre-register a custom TimeProvider (e.g. a test double) before calling the extension.
        var customTimeProvider = new StubTimeProvider();
        services.AddSingleton<TimeProvider>(customTimeProvider);

        var builder = new ZeeKayDaAuthBuilder(services);
        builder.AddInMemoryDevelopmentJwtSigningKeys();

        await using var provider = services.BuildServiceProvider();
        var tp = provider.GetRequiredService<TimeProvider>();
        tp.Should().BeSameAs(customTimeProvider, "TryAddSingleton must not overwrite a pre-registered TimeProvider");
    }

    private sealed class StubTimeProvider : TimeProvider;

    [Fact]
    public void AddInMemoryDevelopmentJwtSigningKeys_registers_DevelopmentSigningKeyWarningService_as_IHostedService()
    {
        var services = new ServiceCollection();
        services.AddSingleton<IHostEnvironment>(new FakeHostEnvironment { ContentRootPath = "/app" });
        var builder = new ZeeKayDaAuthBuilder(services);

        builder.AddInMemoryDevelopmentJwtSigningKeys();

        var registrations = services
            .Where(d => d.ServiceType == typeof(IHostedService))
            .ToList();
        registrations.Should().ContainSingle(d =>
            d.ImplementationType == typeof(DevelopmentSigningKeyWarningService));
    }

    [Fact]
    public void AddInMemoryDevelopmentJwtSigningKeys_returns_builder_for_chaining()
    {
        var services = new ServiceCollection();
        services.AddSingleton<IHostEnvironment>(new FakeHostEnvironment { ContentRootPath = "/app" });
        var builder = new ZeeKayDaAuthBuilder(services);

        var returned = builder.AddInMemoryDevelopmentJwtSigningKeys();

        returned.Should().BeSameAs(builder);
    }

    [Fact]
    public async Task AddInMemoryDevelopmentJwtSigningKeys_applies_configure_callback()
    {
        var services = new ServiceCollection();
        services.AddSingleton<IHostEnvironment>(new FakeHostEnvironment { ContentRootPath = "/app" });
        var builder = new ZeeKayDaAuthBuilder(services);

        builder.AddInMemoryDevelopmentJwtSigningKeys(o =>
            o.AllowedDevelopmentJwtSigningKeysEnvironments = ["Development", "IntegrationTesting"]);

        await using var provider = services.BuildServiceProvider();
        var options = provider.GetRequiredService<IOptions<DevelopmentSigningKeyOptions>>().Value;
        options.AllowedDevelopmentJwtSigningKeysEnvironments.Should().BeEquivalentTo(
            new[] { "Development", "IntegrationTesting" });
    }

    [Fact]
    public async Task AddInMemoryDevelopmentJwtSigningKeys_configure_callback_leaves_PersistToDirectory_null()
    {
        var services = new ServiceCollection();
        services.AddSingleton<IHostEnvironment>(new FakeHostEnvironment { ContentRootPath = "/app" });
        var builder = new ZeeKayDaAuthBuilder(services);

        builder.AddInMemoryDevelopmentJwtSigningKeys(o =>
            o.AllowedDevelopmentJwtSigningKeysEnvironments = ["Development", "IntegrationTesting"]);

        await using var provider = services.BuildServiceProvider();
        var options = provider.GetRequiredService<IOptions<DevelopmentSigningKeyOptions>>().Value;
        options.PersistToDirectory.Should().BeNull(
            "the in-memory configure callback's type has no PersistToDirectory member to set it through, " +
            "so an in-memory registration can never silently become a persisted one");
    }

    [Fact]
    public void AddInMemoryDevelopmentJwtSigningKeys_throws_InvalidOperationException_when_called_twice()
    {
        var services = new ServiceCollection();
        services.AddSingleton<IHostEnvironment>(new FakeHostEnvironment { ContentRootPath = "/app" });
        var builder = new ZeeKayDaAuthBuilder(services);
        builder.AddInMemoryDevelopmentJwtSigningKeys();

        var act = () => builder.AddInMemoryDevelopmentJwtSigningKeys();

        act.Should().Throw<InvalidOperationException>()
            .WithMessage("*IJwtSigningService*already registered*");
    }

    // ── Persist to default path (AddPersistedDevelopmentJwtSigningKeys with no argument) ────────

    [Fact]
    public async Task AddPersistedDevelopmentJwtSigningKeys_with_no_argument_sets_PersistToDirectory_to_default_path()
    {
        var services = new ServiceCollection();
        services.AddSingleton<IHostEnvironment>(new FakeHostEnvironment { ContentRootPath = "/app" });
        var builder = new ZeeKayDaAuthBuilder(services);

        builder.AddPersistedDevelopmentJwtSigningKeys();

        await using var provider = services.BuildServiceProvider();
        var options = provider.GetRequiredService<IOptions<DevelopmentSigningKeyOptions>>().Value;
        options.PersistToDirectory.Should().Be(
            Path.Join("/app", ".zeekayda", "signing-keys"),
            "no argument means the default path under ContentRootPath");
    }

    [Fact]
    public async Task AddPersistedDevelopmentJwtSigningKeys_with_null_sets_PersistToDirectory_to_default_path()
    {
        var services = new ServiceCollection();
        services.AddSingleton<IHostEnvironment>(new FakeHostEnvironment { ContentRootPath = "/app" });
        var builder = new ZeeKayDaAuthBuilder(services);

        builder.AddPersistedDevelopmentJwtSigningKeys(persistTo: null);

        await using var provider = services.BuildServiceProvider();
        var options = provider.GetRequiredService<IOptions<DevelopmentSigningKeyOptions>>().Value;
        options.PersistToDirectory.Should().Be(
            Path.Join("/app", ".zeekayda", "signing-keys"),
            "persistTo: null always means the default path — there is no ephemeral reading of this overload");
    }

    // ── Persist to explicit path ──────────────────────────────────────────────────────────────────

    [Fact]
    public async Task AddPersistedDevelopmentJwtSigningKeys_with_explicit_path_sets_PersistToDirectory()
    {
        var services = new ServiceCollection();
        services.AddSingleton<IHostEnvironment>(new FakeHostEnvironment { ContentRootPath = "/app" });
        var builder = new ZeeKayDaAuthBuilder(services);

        builder.AddPersistedDevelopmentJwtSigningKeys(persistTo: "/custom/keys");

        await using var provider = services.BuildServiceProvider();
        var options = provider.GetRequiredService<IOptions<DevelopmentSigningKeyOptions>>().Value;
        options.PersistToDirectory.Should().Be("/custom/keys");
    }

    [Fact]
    public async Task AddPersistedDevelopmentJwtSigningKeys_applies_configure_callback()
    {
        var services = new ServiceCollection();
        services.AddSingleton<IHostEnvironment>(new FakeHostEnvironment { ContentRootPath = "/app" });
        var builder = new ZeeKayDaAuthBuilder(services);

        builder.AddPersistedDevelopmentJwtSigningKeys(
            persistTo: "/custom/keys",
            configure: o => o.AllowedDevelopmentJwtSigningKeysEnvironments = ["Development", "Staging"]);

        await using var provider = services.BuildServiceProvider();
        var options = provider.GetRequiredService<IOptions<DevelopmentSigningKeyOptions>>().Value;
        options.AllowedDevelopmentJwtSigningKeysEnvironments.Should().BeEquivalentTo(
            new[] { "Development", "Staging" });
    }

    [Fact]
    public async Task AddPersistedDevelopmentJwtSigningKeys_configure_callback_can_override_PersistToDirectory()
    {
        var services = new ServiceCollection();
        services.AddSingleton<IHostEnvironment>(new FakeHostEnvironment { ContentRootPath = "/app" });
        var builder = new ZeeKayDaAuthBuilder(services);

        // No persistTo argument — the default path is applied first — then the configure
        // callback overrides it, proving PersistToDirectory is legitimately reachable and
        // settable through the persisted variant's configure surface.
        builder.AddPersistedDevelopmentJwtSigningKeys(
            configure: o => o.PersistToDirectory = "/overridden/keys");

        await using var provider = services.BuildServiceProvider();
        var options = provider.GetRequiredService<IOptions<DevelopmentSigningKeyOptions>>().Value;
        options.PersistToDirectory.Should().Be("/overridden/keys");
    }

    [Fact]
    public void AddPersistedDevelopmentJwtSigningKeys_returns_builder_for_chaining()
    {
        var services = new ServiceCollection();
        services.AddSingleton<IHostEnvironment>(new FakeHostEnvironment { ContentRootPath = "/app" });
        var builder = new ZeeKayDaAuthBuilder(services);

        var returned = builder.AddPersistedDevelopmentJwtSigningKeys();

        returned.Should().BeSameAs(builder);
    }

    // ── Double-registration guard ─────────────────────────────────────────────────────────────────

    [Fact]
    public void AddPersistedDevelopmentJwtSigningKeys_throws_InvalidOperationException_when_called_twice()
    {
        var services = new ServiceCollection();
        services.AddSingleton<IHostEnvironment>(new FakeHostEnvironment { ContentRootPath = "/app" });
        var builder = new ZeeKayDaAuthBuilder(services);
        builder.AddPersistedDevelopmentJwtSigningKeys();

        var act = () => builder.AddPersistedDevelopmentJwtSigningKeys();

        act.Should().Throw<InvalidOperationException>()
            .WithMessage("*IJwtSigningService*already registered*");
    }

    [Fact]
    public void AddInMemoryDevelopmentJwtSigningKeys_then_AddPersistedDevelopmentJwtSigningKeys_throws_InvalidOperationException()
    {
        var services = new ServiceCollection();
        services.AddSingleton<IHostEnvironment>(new FakeHostEnvironment { ContentRootPath = "/app" });
        var builder = new ZeeKayDaAuthBuilder(services);
        builder.AddInMemoryDevelopmentJwtSigningKeys();

        var act = () => builder.AddPersistedDevelopmentJwtSigningKeys();

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
