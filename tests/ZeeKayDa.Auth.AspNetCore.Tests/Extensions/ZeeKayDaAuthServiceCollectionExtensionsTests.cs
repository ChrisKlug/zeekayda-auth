using Microsoft.Extensions.DependencyInjection;
using ZeeKayDa.Auth;
using ZeeKayDa.Auth.AspNetCore.Extensions;

namespace ZeeKayDa.Auth.AspNetCore.Tests.Extensions;

public sealed class ZeeKayDaAuthServiceCollectionExtensionsTests
{
    [Fact]
    public void AddZeeKayDaAuth_NullServices_ThrowsArgumentNullException()
    {
        var act = () => ((IServiceCollection)null!).AddZeeKayDaAuth(_ => { });

        act.Should().Throw<ArgumentNullException>().WithParameterName("services");
    }

    [Fact]
    public void AddZeeKayDaAuth_NullConfigure_ThrowsArgumentNullException()
    {
        var act = () => new ServiceCollection().AddZeeKayDaAuth(null!);

        act.Should().Throw<ArgumentNullException>().WithParameterName("configure");
    }
}
