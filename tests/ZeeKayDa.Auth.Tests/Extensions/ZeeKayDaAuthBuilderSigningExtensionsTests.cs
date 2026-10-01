using System.Reflection;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using ZeeKayDa.Auth;
using ZeeKayDa.Auth.StartupVerification;
using ZeeKayDa.Auth.Tokens;

namespace ZeeKayDa.Auth.Tests.Extensions;

public sealed class ZeeKayDaAuthBuilderSigningExtensionsTests
{
    // ── Configure surface: only the environment list is reachable ─────────────────────────────────

    [Theory]
    [InlineData(nameof(ZeeKayDaAuthBuilderSigningExtensions.AddInMemoryDevelopmentSigning))]
    [InlineData(nameof(ZeeKayDaAuthBuilderSigningExtensions.AddPersistedDevelopmentSigning))]
    public void The_configure_callback_can_set_only_AllowedEnvironments(string methodName)
    {
        // Reflects on the public signature, which is what a caller's lambda compiles against: no
        // host can spoof the environment or give the in-memory registration a directory.
        var method = typeof(ZeeKayDaAuthBuilderSigningExtensions).GetMethod(methodName);
        var callbackTargetType = method!.GetParameters()
            .Single(p => p.Name == "configure").ParameterType
            .GetGenericArguments().Single();

        callbackTargetType.Should().Be(typeof(DevelopmentSigningOptions));
        callbackTargetType.GetProperties(BindingFlags.Public | BindingFlags.Instance)
            .Select(p => p.Name)
            .Should().Equal(nameof(DevelopmentSigningOptions.AllowedEnvironments));
    }

    // ── Argument validation ───────────────────────────────────────────────────────────────────────

    [Fact]
    public void AddInMemoryDevelopmentSigning_throws_ArgumentNullException_when_builder_is_null()
    {
        ZeeKayDaAuthCoreBuilder builder = null!;

        var act = () => builder.AddInMemoryDevelopmentSigning();

        act.Should().Throw<ArgumentNullException>().WithParameterName("builder");
    }

    [Fact]
    public void AddPersistedDevelopmentSigning_throws_ArgumentNullException_when_builder_is_null()
    {
        ZeeKayDaAuthCoreBuilder builder = null!;

        var act = () => builder.AddPersistedDevelopmentSigning();

        act.Should().Throw<ArgumentNullException>().WithParameterName("builder");
    }

    // ── Ephemeral mode (AddInMemoryDevelopmentSigning) ────────────────────────────────────

    [Fact]
    public async Task AddInMemoryDevelopmentSigning_registers_the_ring_over_the_development_source()
    {
        var services = new ServiceCollection();
        services.AddSingleton(typeof(ILogger<>), typeof(NullLogger<>));
        services.AddSingleton<IHostEnvironment>(new FakeHostEnvironment { ContentRootPath = "/app" });
        var builder = new ZeeKayDaAuthCoreBuilder(services);

        builder.AddInMemoryDevelopmentSigning();

        await using var provider = services.BuildServiceProvider();
        provider.GetRequiredService<ISigningKeyRing>().Should().BeOfType<StaticSigningKeyRing>();
        provider.GetRequiredService<SigningKeySourceRegistration>().SourceType
            .Should().Be<DevelopmentSigningKeySource>();
    }

    [Fact]
    public async Task AddInMemoryDevelopmentSigning_does_not_register_the_source_in_the_container()
    {
        var services = new ServiceCollection();
        services.AddSingleton(typeof(ILogger<>), typeof(NullLogger<>));
        services.AddSingleton<IHostEnvironment>(new FakeHostEnvironment { ContentRootPath = "/app" });
        var builder = new ZeeKayDaAuthCoreBuilder(services);

        builder.AddInMemoryDevelopmentSigning();

        await using var provider = services.BuildServiceProvider();
        provider.GetService<ISigningKeySource>().Should().BeNull(
            "the ring constructs and owns the source, so nothing else can reach it");
    }

    [Fact]
    public async Task AddInMemoryDevelopmentSigning_leaves_PersistToDirectory_null()
    {
        var services = new ServiceCollection();
        services.AddSingleton<IHostEnvironment>(new FakeHostEnvironment { ContentRootPath = "/app" });
        var builder = new ZeeKayDaAuthCoreBuilder(services);

        builder.AddInMemoryDevelopmentSigning();

        await using var provider = services.BuildServiceProvider();
        var options = provider.GetRequiredService<IOptions<DevelopmentSigningOptions>>().Value;
        options.PersistToDirectory.Should().BeNull("this method registers the ephemeral in-memory provider");
    }

    [Fact]
    public async Task AddInMemoryDevelopmentSigning_registers_TimeProvider_System_singleton()
    {
        var services = new ServiceCollection();
        services.AddSingleton<IHostEnvironment>(new FakeHostEnvironment { ContentRootPath = "/app" });
        var builder = new ZeeKayDaAuthCoreBuilder(services);

        builder.AddInMemoryDevelopmentSigning();

        await using var provider = services.BuildServiceProvider();
        var tp = provider.GetRequiredService<TimeProvider>();
        tp.Should().BeSameAs(TimeProvider.System);
    }

    [Fact]
    public async Task AddInMemoryDevelopmentSigning_does_not_overwrite_already_registered_TimeProvider()
    {
        var services = new ServiceCollection();
        services.AddSingleton<IHostEnvironment>(new FakeHostEnvironment { ContentRootPath = "/app" });

        // Pre-register a custom TimeProvider (e.g. a test double) before calling the extension.
        var customTimeProvider = new StubTimeProvider();
        services.AddSingleton<TimeProvider>(customTimeProvider);

        var builder = new ZeeKayDaAuthCoreBuilder(services);
        builder.AddInMemoryDevelopmentSigning();

        await using var provider = services.BuildServiceProvider();
        var tp = provider.GetRequiredService<TimeProvider>();
        tp.Should().BeSameAs(customTimeProvider, "TryAddSingleton must not overwrite a pre-registered TimeProvider");
    }

    private sealed class StubTimeProvider : TimeProvider;

    [Fact]
    public void AddInMemoryDevelopmentSigning_registers_DevelopmentSigningKeyVerifier_as_IStartupVerifier()
    {
        var services = new ServiceCollection();
        services.AddSingleton<IHostEnvironment>(new FakeHostEnvironment { ContentRootPath = "/app" });
        var builder = new ZeeKayDaAuthCoreBuilder(services);

        builder.AddInMemoryDevelopmentSigning();

        var registrations = services
            .Where(d => d.ServiceType == typeof(IStartupVerifier))
            .ToList();
        registrations.Should().ContainSingle(d =>
            d.ImplementationType == typeof(DevelopmentSigningKeyVerifier));
    }

    [Fact]
    public void AddInMemoryDevelopmentSigning_returns_builder_for_chaining()
    {
        var services = new ServiceCollection();
        services.AddSingleton<IHostEnvironment>(new FakeHostEnvironment { ContentRootPath = "/app" });
        var builder = new ZeeKayDaAuthCoreBuilder(services);

        var returned = builder.AddInMemoryDevelopmentSigning();

        returned.Should().BeSameAs(builder);
    }

    [Fact]
    public async Task AddInMemoryDevelopmentSigning_applies_configure_callback()
    {
        var services = new ServiceCollection();
        services.AddSingleton<IHostEnvironment>(new FakeHostEnvironment { ContentRootPath = "/app" });
        var builder = new ZeeKayDaAuthCoreBuilder(services);

        builder.AddInMemoryDevelopmentSigning(o =>
            o.AllowedEnvironments = ["Development", "IntegrationTesting"]);

        await using var provider = services.BuildServiceProvider();
        var options = provider.GetRequiredService<IOptions<DevelopmentSigningOptions>>().Value;
        options.AllowedEnvironments.Should().BeEquivalentTo(
            new[] { "Development", "IntegrationTesting" });
    }

    [Fact]
    public async Task AddInMemoryDevelopmentSigning_configure_callback_leaves_PersistToDirectory_null()
    {
        var services = new ServiceCollection();
        services.AddSingleton<IHostEnvironment>(new FakeHostEnvironment { ContentRootPath = "/app" });
        var builder = new ZeeKayDaAuthCoreBuilder(services);

        builder.AddInMemoryDevelopmentSigning(o =>
            o.AllowedEnvironments = ["Development", "IntegrationTesting"]);

        await using var provider = services.BuildServiceProvider();
        var options = provider.GetRequiredService<IOptions<DevelopmentSigningOptions>>().Value;
        options.PersistToDirectory.Should().BeNull(
            "the directory is set only through AddPersistedDevelopmentSigning's parameter, " +
            "so an in-memory registration can never silently become a persisted one");
    }

    [Fact]
    public void AddInMemoryDevelopmentSigning_throws_InvalidOperationException_when_called_twice()
    {
        var services = new ServiceCollection();
        services.AddSingleton<IHostEnvironment>(new FakeHostEnvironment { ContentRootPath = "/app" });
        var builder = new ZeeKayDaAuthCoreBuilder(services);
        builder.AddInMemoryDevelopmentSigning();

        var act = () => builder.AddInMemoryDevelopmentSigning();

        act.Should().Throw<InvalidOperationException>()
            .WithMessage("*already registered as the signing key source*");
    }

    // ── Persist to default path (AddPersistedDevelopmentSigning with no argument) ────────

    [Fact]
    public async Task AddPersistedDevelopmentSigning_with_no_argument_sets_PersistToDirectory_to_default_path()
    {
        var services = new ServiceCollection();
        services.AddSingleton<IHostEnvironment>(new FakeHostEnvironment { ContentRootPath = "/app" });
        var builder = new ZeeKayDaAuthCoreBuilder(services);

        builder.AddPersistedDevelopmentSigning();

        await using var provider = services.BuildServiceProvider();
        var options = provider.GetRequiredService<IOptions<DevelopmentSigningOptions>>().Value;
        options.PersistToDirectory.Should().Be(
            Path.Join("/app", ".zeekayda", "signing-keys"),
            "no argument means the default path under ContentRootPath");
    }

    [Fact]
    public async Task AddPersistedDevelopmentSigning_with_null_sets_PersistToDirectory_to_default_path()
    {
        var services = new ServiceCollection();
        services.AddSingleton<IHostEnvironment>(new FakeHostEnvironment { ContentRootPath = "/app" });
        var builder = new ZeeKayDaAuthCoreBuilder(services);

        builder.AddPersistedDevelopmentSigning(persistTo: null);

        await using var provider = services.BuildServiceProvider();
        var options = provider.GetRequiredService<IOptions<DevelopmentSigningOptions>>().Value;
        options.PersistToDirectory.Should().Be(
            Path.Join("/app", ".zeekayda", "signing-keys"),
            "persistTo: null always means the default path — there is no ephemeral reading of this overload");
    }

    // ── Persist to explicit path ──────────────────────────────────────────────────────────────────

    [Fact]
    public async Task AddPersistedDevelopmentSigning_with_explicit_path_sets_PersistToDirectory()
    {
        var services = new ServiceCollection();
        services.AddSingleton<IHostEnvironment>(new FakeHostEnvironment { ContentRootPath = "/app" });
        var builder = new ZeeKayDaAuthCoreBuilder(services);

        builder.AddPersistedDevelopmentSigning(persistTo: "/custom/keys");

        await using var provider = services.BuildServiceProvider();
        var options = provider.GetRequiredService<IOptions<DevelopmentSigningOptions>>().Value;
        options.PersistToDirectory.Should().Be("/custom/keys");
    }

    [Fact]
    public async Task AddPersistedDevelopmentSigning_applies_configure_callback()
    {
        var services = new ServiceCollection();
        services.AddSingleton<IHostEnvironment>(new FakeHostEnvironment { ContentRootPath = "/app" });
        var builder = new ZeeKayDaAuthCoreBuilder(services);

        builder.AddPersistedDevelopmentSigning(
            persistTo: "/custom/keys",
            configure: o => o.AllowedEnvironments = ["Development", "Staging"]);

        await using var provider = services.BuildServiceProvider();
        var options = provider.GetRequiredService<IOptions<DevelopmentSigningOptions>>().Value;
        options.AllowedEnvironments.Should().BeEquivalentTo(
            new[] { "Development", "Staging" });
    }

    [Fact]
    public void AddPersistedDevelopmentSigning_returns_builder_for_chaining()
    {
        var services = new ServiceCollection();
        services.AddSingleton<IHostEnvironment>(new FakeHostEnvironment { ContentRootPath = "/app" });
        var builder = new ZeeKayDaAuthCoreBuilder(services);

        var returned = builder.AddPersistedDevelopmentSigning();

        returned.Should().BeSameAs(builder);
    }

    // ── Double-registration guard ─────────────────────────────────────────────────────────────────

    [Fact]
    public void AddPersistedDevelopmentSigning_throws_InvalidOperationException_when_called_twice()
    {
        var services = new ServiceCollection();
        services.AddSingleton<IHostEnvironment>(new FakeHostEnvironment { ContentRootPath = "/app" });
        var builder = new ZeeKayDaAuthCoreBuilder(services);
        builder.AddPersistedDevelopmentSigning();

        var act = () => builder.AddPersistedDevelopmentSigning();

        act.Should().Throw<InvalidOperationException>()
            .WithMessage("*already registered as the signing key source*");
    }

    [Fact]
    public async Task A_rejected_second_registration_leaves_the_first_one_unconfigured_by_it()
    {
        var services = new ServiceCollection();
        services.AddSingleton<IHostEnvironment>(new FakeHostEnvironment { ContentRootPath = "/app" });
        var builder = new ZeeKayDaAuthCoreBuilder(services);
        builder.AddInMemoryDevelopmentSigning();

        try
        {
            builder.AddPersistedDevelopmentSigning("/tmp/keys");
        }
        catch (InvalidOperationException)
        {
            // The rejection is the point; what matters is what it left behind.
        }

        await using var provider = services.BuildServiceProvider();
        var options = provider.GetRequiredService<IOptions<DevelopmentSigningOptions>>().Value;
        options.PersistToDirectory.Should().BeNull(
            "a rejected registration must not leave its configuration applied to the surviving one");
    }

    [Fact]
    public void AddInMemoryDevelopmentSigning_then_AddPersistedDevelopmentSigning_throws_InvalidOperationException()
    {
        var services = new ServiceCollection();
        services.AddSingleton<IHostEnvironment>(new FakeHostEnvironment { ContentRootPath = "/app" });
        var builder = new ZeeKayDaAuthCoreBuilder(services);
        builder.AddInMemoryDevelopmentSigning();

        var act = () => builder.AddPersistedDevelopmentSigning();

        act.Should().Throw<InvalidOperationException>()
            .WithMessage("*already registered as the signing key source*");
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
