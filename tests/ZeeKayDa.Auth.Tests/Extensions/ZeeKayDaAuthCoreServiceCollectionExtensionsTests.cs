using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;
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

    [Fact]
    public void AddZeeKayDaAuthCore_registers_SigningStartupSelfTestHostedService_as_a_hosted_service()
    {
        var services = new ServiceCollection();
        services.AddSingleton(typeof(ILogger<>), typeof(NullLogger<>));

        services.AddZeeKayDaAuthCore();

        using var provider = services.BuildServiceProvider();
        provider.GetServices<IHostedService>().OfType<SigningStartupSelfTestHostedService>().Should().ContainSingle();
    }

    [Fact]
    public void AddZeeKayDaAuthCore_registers_the_signing_startup_self_test_hosted_service_exactly_once_across_repeated_calls()
    {
        var services = new ServiceCollection();
        services.AddSingleton(typeof(ILogger<>), typeof(NullLogger<>));

        services.AddZeeKayDaAuthCore();
        services.AddZeeKayDaAuthCore();

        using var provider = services.BuildServiceProvider();
        provider.GetServices<IHostedService>().OfType<SigningStartupSelfTestHostedService>().Should().ContainSingle();
    }

    [Fact]
    public async Task Registered_hosted_service_does_not_throw_when_no_IJwtSigningService_is_registered()
    {
        // A host that has not (yet) configured any signing key provider must still be able to start
        // — the self-test is a no-op, not a hard DI-resolution failure, when nothing is registered.
        var services = new ServiceCollection();
        services.AddSingleton(typeof(ILogger<>), typeof(NullLogger<>));
        services.AddZeeKayDaAuthCore();

        await using var provider = services.BuildServiceProvider();
        var hostedService = provider.GetServices<IHostedService>().OfType<SigningStartupSelfTestHostedService>().Single();

        var act = async () => await hostedService.StartAsync(TestContext.Current.CancellationToken);

        await act.Should().NotThrowAsync();
    }
}
