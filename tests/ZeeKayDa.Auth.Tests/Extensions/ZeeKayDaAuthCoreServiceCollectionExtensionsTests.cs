using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;
using ZeeKayDa.Auth.Extensions;
using ZeeKayDa.Auth.Logging;

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
        var act = () => ((IServiceCollection)null!).AddZeeKayDaAuthCore();

        act.Should().Throw<ArgumentNullException>();
    }
}
