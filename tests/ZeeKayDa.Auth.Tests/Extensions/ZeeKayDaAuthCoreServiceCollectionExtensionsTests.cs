using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;
using ZeeKayDa.Auth;
using ZeeKayDa.Auth.Extensions;
using ZeeKayDa.Auth.Logging;
using ZeeKayDa.Auth.Tokens;

namespace ZeeKayDa.Auth.Tests.Extensions;

public sealed class ZeeKayDaAuthCoreServiceCollectionExtensionsTests
{
    [Fact]
    public void AddZeeKayDaAuthCore_registers_ISanitizingLogger_as_SecretSanitizingLogger()
    {
        var services = new ServiceCollection();
        services.AddSingleton(typeof(ILogger<>), typeof(NullLogger<>));

        services.AddZeeKayDaAuthCore();

        using var provider = services.BuildServiceProvider();
        var resolved = provider.GetRequiredService<ISanitizingLogger<object>>();

        resolved.Should().BeOfType<SecretSanitizingLogger<object>>();
    }

    [Fact]
    public void AddZeeKayDaAuthCore_is_idempotent()
    {
        var services = new ServiceCollection();

        services.AddZeeKayDaAuthCore();
        services.AddZeeKayDaAuthCore();

        services.Should().ContainSingle(sd => sd.ServiceType == typeof(ISanitizingLogger<>));
    }

    [Fact]
    public void AddZeeKayDaAuthCore_throws_ArgumentNullException_if_services_is_null()
    {
        IServiceCollection services = null!;
        var act = () => services.AddZeeKayDaAuthCore();

        act.Should().Throw<ArgumentNullException>();
    }

    // ── Issue #437: framework-owned startup self-test wiring ───────────────────────────────────────



    // ── Issue #444: unified startup verification wiring ─────────────────────────────────────────────

    [Fact]
    public void AddZeeKayDaAuthCore_registers_StartupVerificationHostedService_as_a_hosted_service()
    {
        var services = new ServiceCollection();
        services.AddSingleton(typeof(ILogger<>), typeof(NullLogger<>));

        services.AddZeeKayDaAuthCore();

        using var provider = services.BuildServiceProvider();
        provider.GetServices<IHostedService>().OfType<StartupVerificationHostedService>().Should().ContainSingle();
    }

    [Fact]
    public void AddZeeKayDaAuthCore_registers_a_non_empty_gate_collection_even_without_AddZeeKayDaAuth()
    {
        // A host wiring only AddZeeKayDaAuthCore() (e.g. a signing-provider package such as
        // .AzureKeyVault/.FileSystem/.Windows without AddZeeKayDaAuth()) must still get the
        // sanitizing-logger shadow gate — otherwise the runner's gate phase passes vacuously.
        var services = new ServiceCollection();
        services.AddSingleton(typeof(ILogger<>), typeof(NullLogger<>));

        services.AddZeeKayDaAuthCore();

        using var provider = services.BuildServiceProvider();
        provider.GetServices<IStartupVerificationGate>().Should().NotBeEmpty();
    }
}
