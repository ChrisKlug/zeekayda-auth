using System.Net;
using Microsoft.AspNetCore.Mvc.Testing;

namespace ZeeKayDa.Auth.AspNetCore.Tests.Extensions;

public sealed class ZeeKayDaAuthEndpointRouteBuilderExtensionsTests
{
    private const string DiscoveryPath = "/.well-known/openid-configuration";

    private static HttpClient CreateLoopbackClient(
        WebApplicationFactory<TestWebAppFactory> factory,
        string baseAddress = "http://localhost:5000")
        => factory.CreateClient(new WebApplicationFactoryClientOptions
        {
            BaseAddress = new Uri(baseAddress),
            AllowAutoRedirect = false,
        });

    // AC1: non-loopback TCP connection with Host: localhost → 421
    [Fact]
    public async Task HttpsGuard_rejects_non_loopback_connection_even_when_Host_header_is_localhost()
    {
        using var factory = new TestWebAppFactoryWithRemoteIp(IPAddress.Parse("192.0.2.10"));
        using var client = CreateLoopbackClient(factory, "http://localhost:5000");

        var response = await client.GetAsync(DiscoveryPath, TestContext.Current.CancellationToken);

        response.StatusCode.Should().Be(HttpStatusCode.MisdirectedRequest);
    }

    // AC2 & AC3: loopback RemoteIpAddress → HTTP allowed regardless of Host
    [Theory]
    [InlineData("127.0.0.1")]
    [InlineData("::1")]
    public async Task HttpsGuard_allows_loopback_connection_regardless_of_Host_header(string remoteIp)
    {
        using var factory = new TestWebAppFactoryWithRemoteIp(IPAddress.Parse(remoteIp));
        // Use a non-loopback Host header to prove the guard uses IP, not Host
        using var client = CreateLoopbackClient(factory, "http://localhost:5000");

        var response = await client.GetAsync(DiscoveryPath, TestContext.Current.CancellationToken);

        response.StatusCode.Should().NotBe(HttpStatusCode.MisdirectedRequest);
    }

    // IPAddress.IsLoopback unwraps IPv4-mapped IPv6 (e.g. ::ffff:127.0.0.1), so dual-stack
    // sockets that present loopback as a mapped address are correctly treated as loopback.
    [Fact]
    public async Task HttpsGuard_allows_IPv4_mapped_IPv6_loopback_address()
    {
        using var factory = new TestWebAppFactoryWithRemoteIp(IPAddress.Parse("::ffff:127.0.0.1"));
        using var client = CreateLoopbackClient(factory);

        var response = await client.GetAsync(DiscoveryPath, TestContext.Current.CancellationToken);

        response.StatusCode.Should().NotBe(HttpStatusCode.MisdirectedRequest);
    }

    // AC4: null RemoteIpAddress → treated as non-loopback
    [Fact]
    public async Task HttpsGuard_rejects_request_when_RemoteIpAddress_is_null()
    {
        using var factory = new TestWebAppFactoryWithRemoteIp(remoteIpAddress: null);
        using var client = CreateLoopbackClient(factory);

        var response = await client.GetAsync(DiscoveryPath, TestContext.Current.CancellationToken);

        response.StatusCode.Should().Be(HttpStatusCode.MisdirectedRequest);
    }
}
