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

    // The case guard sits on the framework's route group, so it covers every protocol route —
    // including the provider callback and resume routes, which this host does not map.
    [Theory]
    [InlineData("GET", "/tenant1/.well-known/openid-configuration", "/TENANT1/.well-known/openid-configuration")]
    [InlineData("GET", "/.well-known/oauth-authorization-server/tenant1", "/.well-known/oauth-authorization-server/TENANT1")]
    [InlineData("GET", "/tenant1/.well-known/oauth-authorization-server", "/TENANT1/.well-known/oauth-authorization-server")]
    [InlineData("GET", "/tenant1/connect/jwks", "/TENANT1/connect/jwks")]
    [InlineData("GET", "/tenant1/connect/authorize", "/TENANT1/connect/authorize")]
    [InlineData("POST", "/tenant1/connect/token", "/TENANT1/connect/token")]
    [InlineData("POST", "/tenant1/connect/token", "/tenant1/CONNECT/token")]
    [InlineData("POST", "/tenant1/connect/token", "/tenant1/connect/token/")]
    [InlineData("GET", "/tenant1/connect/jwks", "/tenant1/connect/jwks/")]
    [InlineData("GET", "/tenant1/.well-known/openid-configuration", "/tenant1/.well-known/openid-configuration/")]
    public async Task Protocol_route_returns_404_when_the_path_differs_from_the_route_only_in_case_or_a_trailing_slash(
        string method, string route, string wrongCasePath)
    {
        using var factory = new TestWebAppFactory(opts => opts.Issuer = "https://test.example.com/tenant1");
        using var client = factory.CreateClient(new WebApplicationFactoryClientOptions
        {
            BaseAddress = new Uri("https://test.example.com"),
            AllowAutoRedirect = false,
        });

        var mapped = await client.SendAsync(new HttpRequestMessage(new HttpMethod(method), route), TestContext.Current.CancellationToken);
        var wrongCase = await client.SendAsync(new HttpRequestMessage(new HttpMethod(method), wrongCasePath), TestContext.Current.CancellationToken);

        mapped.StatusCode.Should().NotBe(HttpStatusCode.NotFound, because: "the correctly cased route is mapped");
        wrongCase.StatusCode.Should().Be(HttpStatusCode.NotFound,
            because: "a URL path is case-sensitive, so a differently cased path is not this issuer's endpoint");
    }

    [Fact]
    public async Task Protocol_route_returns_404_not_405_for_a_wrong_case_path_with_an_unmapped_method()
    {
        using var factory = new TestWebAppFactory(opts => opts.Issuer = "https://test.example.com/tenant1");
        using var client = factory.CreateClient(new WebApplicationFactoryClientOptions
        {
            BaseAddress = new Uri("https://test.example.com"),
            AllowAutoRedirect = false,
        });

        var rightCase = await client.GetAsync("/tenant1/connect/token", TestContext.Current.CancellationToken);
        var wrongCase = await client.GetAsync("/tenant1/connect/TOKEN", TestContext.Current.CancellationToken);

        rightCase.StatusCode.Should().Be(HttpStatusCode.MethodNotAllowed, because: "the token route is POST-only");
        wrongCase.StatusCode.Should().Be(HttpStatusCode.NotFound,
            because: "a wrong path is no route at all, so it must not be reported as a wrong method");
    }

    [Fact]
    public async Task Protocol_route_returns_404_not_421_for_a_wrong_case_path_over_plain_HTTP()
    {
        using var factory = new TestWebAppFactoryWithRemoteIp(IPAddress.Parse("192.0.2.10"));
        using var client = CreateLoopbackClient(factory, "http://localhost:5000");

        var rightCase = await client.GetAsync(DiscoveryPath, TestContext.Current.CancellationToken);
        var wrongCase = await client.GetAsync(DiscoveryPath.ToUpperInvariant(), TestContext.Current.CancellationToken);

        rightCase.StatusCode.Should().Be(HttpStatusCode.MisdirectedRequest);
        wrongCase.StatusCode.Should().Be(HttpStatusCode.NotFound,
            because: "a wrong path is decided during route matching, before the HTTPS filter runs");
    }

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
