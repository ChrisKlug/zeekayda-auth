using System.Net;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.AspNetCore.Routing;
using Microsoft.Extensions.DependencyInjection;
using ZeeKayDa.Auth.AspNetCore.Endpoints;

namespace ZeeKayDa.Auth.AspNetCore.Tests.Extensions;

public sealed class ZeeKayDaAuthEndpointRouteBuilderExtensionsTests(EveryRouteHostFixture everyRoute)
    : IClassFixture<EveryRouteHostFixture>
{
    private const string DiscoveryPath = "/.well-known/openid-configuration";

    /// <summary>
    /// Every route the framework maps on <see cref="EveryRouteHostFixture"/>, with one method each
    /// route accepts. The route group's filter runs per endpoint, not per method, so one request per
    /// endpoint proves it applies.
    /// </summary>
    private static readonly (string Method, string Path)[] FrameworkRoutes =
    [
        ("GET", "/.well-known/openid-configuration"),
        ("GET", "/.well-known/oauth-authorization-server"),
        ("GET", "/connect/jwks"),
        ("GET", "/connect/authorize"),
        ("POST", "/connect/token"),
        ("GET", "/connect/userinfo"),
        ("OPTIONS", "/connect/userinfo"),
        ("GET", "/connect/endsession"),
        ("GET", "/connect/endsession/confirm"),
        ("GET", "/connect/resume"),
        ("GET", "/connect/callback/acme"),
    ];

    public static TheoryData<string, string> FrameworkRouteRows => new(FrameworkRoutes);

    // ── Defensive security headers ────────────────────────────────────────────────────────────────
    //
    // The route group's filter adds these, not any handler, so a route has them only while it is
    // mapped inside the group — which no host-free handler test can see.

    [Theory]
    [MemberData(nameof(FrameworkRouteRows))]
    public async Task Every_framework_route_answers_with_the_route_groups_security_headers(string method, string path)
    {
        // Redirects are left unfollowed: an error page the host maps is outside the group.
        var client = everyRoute.NewClient(options => options.AllowAutoRedirect = false);
        using var request = new HttpRequestMessage(new HttpMethod(method), path);

        var response = await client.SendAsync(request, TestContext.Current.CancellationToken);

        HeaderOf(response, "X-Content-Type-Options").Should().Be("nosniff");
        HeaderOf(response, "Referrer-Policy").Should().Be("no-referrer");
        HeaderOf(response, "Cross-Origin-Resource-Policy").Should().Be("same-origin");
    }

    [Fact]
    public void The_security_header_rows_name_every_route_the_framework_maps()
    {
        var mapped = everyRoute.Services.GetRequiredService<EndpointDataSource>().Endpoints
            .OfType<RouteEndpoint>()
            .Where(endpoint => endpoint.Metadata.GetMetadata<ExactPathMetadata>() is not null)
            .Select(endpoint => (
                Path: endpoint.RoutePattern.RawText,
                Methods: endpoint.Metadata.GetMetadata<HttpMethodMetadata>()?.HttpMethods ?? []))
            .ToList();

        mapped.Select(endpoint => endpoint.Path).Should().BeEquivalentTo(FrameworkRoutes.Select(row => row.Path),
            because: "a framework route without a row has no test proving it carries the security headers");
        FrameworkRoutes.Should().OnlyContain(
            row => mapped.Any(endpoint => endpoint.Path == row.Path && endpoint.Methods.Contains(row.Method)),
            because: "each row must send a method its route accepts, or it would test a 405 instead");
    }

    private static string? HeaderOf(HttpResponseMessage response, string name) =>
        response.Headers.TryGetValues(name, out var values) ? string.Join(", ", values) : null;

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

        using var mappedRequest = new HttpRequestMessage(new HttpMethod(method), route);
        using var wrongCaseRequest = new HttpRequestMessage(new HttpMethod(method), wrongCasePath);

        var mapped = await client.SendAsync(mappedRequest, TestContext.Current.CancellationToken);
        var wrongCase = await client.SendAsync(wrongCaseRequest, TestContext.Current.CancellationToken);

        mapped.StatusCode.Should().NotBe(HttpStatusCode.NotFound, because: "the correctly cased route is mapped");
        wrongCase.StatusCode.Should().Be(HttpStatusCode.NotFound,
            because: "a URL path is case-sensitive, so a differently cased path is not this issuer's endpoint");
    }

    private static HttpClient CreateTenantClient(Action<IEndpointRouteBuilder> mapHostRoutes, out TestWebAppFactory factory)
    {
        factory = new TestWebAppFactory(
            opts => opts.Issuer = "https://test.example.com/tenant1",
            mapEndpoints: mapHostRoutes);
        return factory.CreateClient(new WebApplicationFactoryClientOptions
        {
            BaseAddress = new Uri("https://test.example.com"),
            AllowAutoRedirect = false,
        });
    }

    [Fact]
    public async Task Host_literal_route_differing_only_in_case_is_served_and_the_framework_route_still_answers()
    {
        using var client = CreateTenantClient(
            endpoints => endpoints.MapPost("/TENANT1/connect/token", () => Results.Text("host")), out var factory);
        using var _ = factory;

        var host = await client.PostAsync("/TENANT1/connect/token", content: null, TestContext.Current.CancellationToken);
        var framework = await client.PostAsync("/tenant1/connect/token", content: null, TestContext.Current.CancellationToken);

        (await host.Content.ReadAsStringAsync(TestContext.Current.CancellationToken)).Should().Be("host",
            because: "the exact-path policy only ever removes framework endpoints, never the host's");
        framework.StatusCode.Should().Be(HttpStatusCode.BadRequest,
            because: "the exactly written framework route still reaches the token endpoint, which rejects a bodiless request");
    }

    [Fact]
    public async Task Host_parameterised_route_answers_a_wrong_case_path_while_the_exact_path_reaches_the_framework()
    {
        using var client = CreateTenantClient(
            endpoints => endpoints.MapGet("/{tenant}/connect/jwks", () => Results.Text("host")), out var factory);
        using var _ = factory;

        var host = await client.GetAsync("/TENANT1/connect/jwks", TestContext.Current.CancellationToken);
        var framework = await client.GetAsync("/tenant1/connect/jwks", TestContext.Current.CancellationToken);

        (await host.Content.ReadAsStringAsync(TestContext.Current.CancellationToken)).Should().Be("host",
            because: "with the framework route excluded, the host's parameterised route is the match");
        (await framework.Content.ReadAsStringAsync(TestContext.Current.CancellationToken)).Should().Contain("\"keys\"",
            because: "the exactly written path still prefers the framework's literal JWKS route");
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
