using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Diagnostics.HealthChecks;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;
using ZeeKayDa.Auth.Extensions;
using ZeeKayDa.Auth.Tokens;

namespace ZeeKayDa.Auth.Tests.Extensions;

/// <summary>
/// Exercises <see cref="ZeeKayDaSigningKeyHealthChecksBuilderExtensions.AddZeeKayDaSigningKeys"/>:
/// it registers the health check but never a ring or source, so an app that adds only this check
/// still starts and reports <see cref="HealthStatus.Unhealthy"/> rather than throwing.
/// </summary>
public sealed class ZeeKayDaSigningKeyHealthChecksBuilderExtensionsTests
{
    [Fact]
    public void AddZeeKayDaSigningKeys_does_not_register_an_ISigningKeyRing()
    {
        var services = new ServiceCollection();

        services.AddHealthChecks().AddZeeKayDaSigningKeys();

        services.Should().NotContain(d => d.ServiceType == typeof(ISigningKeyRing));
    }

    [Fact]
    public void AddZeeKayDaSigningKeys_does_not_register_an_ISigningKeySource()
    {
        var services = new ServiceCollection();

        services.AddHealthChecks().AddZeeKayDaSigningKeys();

        services.Should().NotContain(d => d.ServiceType == typeof(ISigningKeySource));
    }

    [Fact]
    public async Task An_app_with_only_the_health_check_still_starts_and_reports_Unhealthy()
    {
        var services = new ServiceCollection();
        services.AddSingleton(typeof(ILogger<>), typeof(NullLogger<>));
        services.AddHealthChecks().AddZeeKayDaSigningKeys();
        using var provider = services.BuildServiceProvider();

        var healthCheckService = provider.GetRequiredService<HealthCheckService>();
        var report = await healthCheckService.CheckHealthAsync(TestContext.Current.CancellationToken);

        report.Status.Should().Be(HealthStatus.Unhealthy);
    }

    [Fact]
    public void AddZeeKayDaSigningKeys_throws_ArgumentNullException_when_builder_is_null()
    {
        IHealthChecksBuilder builder = null!;

        var act = () => builder.AddZeeKayDaSigningKeys();

        act.Should().Throw<ArgumentNullException>();
    }
}
