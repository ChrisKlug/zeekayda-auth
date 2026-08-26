using Microsoft.Extensions.DependencyInjection;
using ZeeKayDa.Auth;

namespace ZeeKayDa.Auth.Tests;

public sealed class ZeeKayDaAuthBuilderTests
{
    [Fact]
    public void ThrowIfAlreadyRegistered_does_not_throw_when_service_is_not_registered()
    {
        var builder = new ZeeKayDaAuthBuilder(new ServiceCollection());

        var act = () => builder.ThrowIfAlreadyRegistered(typeof(IFakeService));

        act.Should().NotThrow();
    }

    [Fact]
    public void ThrowIfAlreadyRegistered_throws_when_service_is_already_registered()
    {
        var services = new ServiceCollection();
        services.AddSingleton<IFakeService, FakeService>();
        var builder = new ZeeKayDaAuthBuilder(services);

        var act = () => builder.ThrowIfAlreadyRegistered(typeof(IFakeService));

        act.Should().Throw<InvalidOperationException>()
            .WithMessage("*IFakeService*already registered*");
    }

    private interface IFakeService;
    private sealed class FakeService : IFakeService;
}
