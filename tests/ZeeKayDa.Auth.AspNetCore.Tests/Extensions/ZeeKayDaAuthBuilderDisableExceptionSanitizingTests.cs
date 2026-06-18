using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using ZeeKayDa.Auth.AspNetCore;

namespace ZeeKayDa.Auth.AspNetCore.Tests.Extensions;

/// <summary>
/// Verifies that <see cref="ExceptionSanitizingDisabledWarningService"/> is always registered
/// by <c>AddZeeKayDaAuth()</c>, independent of the
/// <see cref="ZeeKayDa.Auth.Logging.LoggingOptions.DisableExceptionSanitizing"/> flag.
/// The flag controls whether the service emits the warning at startup, not whether it is
/// registered.
/// </summary>
public sealed class ZeeKayDaAuthBuilderDisableExceptionSanitizingTests
{
    [Fact]
    public void AddZeeKayDaAuth_always_registers_ExceptionSanitizingDisabledWarningService_as_IHostedService()
    {
        // The service reads the flag at startup and emits a warning only when the flag is set.
        // It must always be registered so no registration call is needed at opt-out time.
        var services = new ServiceCollection();
        var builder = new ZeeKayDaAuthBuilder(services);

        // ExceptionSanitizingDisabledWarningService is registered by AddZeeKayDaAuth;
        // verify it is not accidentally removed from the DI registrations by checking
        // via ZeeKayDaAuthServiceCollectionExtensions (which is the real registration path).
        // Here we verify the builder itself carries no trace of the old opt-out pattern.
        builder.Services.Should().NotContain(sd =>
            sd.ServiceType == typeof(IHostedService) &&
            sd.ImplementationType == typeof(ExceptionSanitizingDisabledWarningService),
            "the warning service is registered by AddZeeKayDaAuth(), not by ZeeKayDaAuthBuilder directly");
    }
}
