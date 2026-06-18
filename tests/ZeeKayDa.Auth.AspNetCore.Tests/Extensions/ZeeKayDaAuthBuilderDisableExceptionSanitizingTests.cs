using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Options;
using ZeeKayDa.Auth.AspNetCore;
using ZeeKayDa.Auth.Logging;

namespace ZeeKayDa.Auth.AspNetCore.Tests.Extensions;

public sealed class ZeeKayDaAuthBuilderDisableExceptionSanitizingTests
{
    [Fact]
    public void DisableExceptionSanitizing_registers_ExceptionSanitizingDisabledWarningService_as_IHostedService()
    {
        var services = new ServiceCollection();
        var builder = new ZeeKayDaAuthBuilder(services);

        builder.DisableExceptionSanitizing();

        services.Should().Contain(sd =>
            sd.ServiceType == typeof(IHostedService) &&
            sd.ImplementationType == typeof(ExceptionSanitizingDisabledWarningService));
    }

    [Fact]
    public void DisableExceptionSanitizing_sets_ExceptionSanitizingDisabled_to_true_when_resolved()
    {
        var services = new ServiceCollection();
        services.AddLogging();
        services.AddOptions();
        var builder = new ZeeKayDaAuthBuilder(services);

        builder.DisableExceptionSanitizing();

        using var provider = services.BuildServiceProvider();
        var opts = provider.GetRequiredService<IOptions<SecretSanitizingLoggerOptions>>().Value;
        opts.ExceptionSanitizingDisabled.Should().BeTrue();
    }

    [Fact]
    public void DisableExceptionSanitizing_returns_same_builder_instance_for_chaining()
    {
        var services = new ServiceCollection();
        var builder = new ZeeKayDaAuthBuilder(services);

        var returned = builder.DisableExceptionSanitizing();

        returned.Should().BeSameAs(builder);
    }

    [Fact]
    public void Without_DisableExceptionSanitizing_ExceptionSanitizingDisabledWarningService_is_not_registered()
    {
        var services = new ServiceCollection();
        // Intentionally do NOT call DisableExceptionSanitizing()
        _ = new ZeeKayDaAuthBuilder(services);

        services.Should().NotContain(sd =>
            sd.ServiceType == typeof(IHostedService) &&
            sd.ImplementationType == typeof(ExceptionSanitizingDisabledWarningService));
    }
}
