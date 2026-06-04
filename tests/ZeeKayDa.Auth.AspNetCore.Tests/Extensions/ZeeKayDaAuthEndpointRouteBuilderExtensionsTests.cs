using System.Reflection;
using ZeeKayDa.Auth.AspNetCore.Extensions;

namespace ZeeKayDa.Auth.AspNetCore.Tests.Extensions;

public sealed class ZeeKayDaAuthEndpointRouteBuilderExtensionsTests
{
    [Theory]
    [InlineData("", false)]
    [InlineData("   ", false)]
    [InlineData("localhost", true)]
    [InlineData("LOCALHOST", true)]
    [InlineData("127.0.0.1", true)]
    [InlineData("::1", true)]
    [InlineData("192.0.2.10", false)]
    [InlineData("auth.example.com", false)]
    public void IsLoopbackHost_ReturnsExpectedValue(string host, bool expected)
    {
        var method = typeof(ZeeKayDaAuthEndpointRouteBuilderExtensions).GetMethod(
            "IsLoopbackHost",
            BindingFlags.NonPublic | BindingFlags.Static);

        method.Should().NotBeNull();

        var result = method!.Invoke(null, [host]);
        result.Should().Be(expected);
    }
}
