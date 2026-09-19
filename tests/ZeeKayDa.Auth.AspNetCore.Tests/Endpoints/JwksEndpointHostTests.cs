using System.Net;
using System.Net.Http.Json;
using System.Text.Json;
using Microsoft.AspNetCore.Mvc.Testing;

namespace ZeeKayDa.Auth.AspNetCore.Tests.Endpoints;

/// <summary>
/// The parts of the JWKS endpoint that only a real host can answer: whether a host-wide
/// authorization fallback policy is bypassed, the routing that puts the key set at the address
/// discovery advertises, and case- and host-sensitive path matching. The handler's own behaviour —
/// the JWK Set body and the headers it writes itself — is covered host-free in
/// <see cref="JwksEndpointTests"/>.
/// </summary>
[Collection(DefaultHostCollection.Name)]
public sealed class JwksEndpointHostTests(
    DefaultHostFixture host,
    TenantIssuerHostFixture tenant,
    FallbackPolicyHostFixture fallback)
{
    private const string JwksPath = "/connect/jwks";

    private static CancellationToken Cancellation => TestContext.Current.CancellationToken;

    private static HttpClient CreateClient(
        WebApplicationFactory<TestWebAppFactory> factory,
        string baseAddress = "https://test.example.com")
        => factory.CreateClient(new WebApplicationFactoryClientOptions
        {
            BaseAddress = new Uri(baseAddress),
        });

    // ── Anonymous access ─────────────────────────────────────────────────────────────────────────

    [Fact]
    public async Task GetJwks_returns_200_under_a_host_wide_fallback_authorization_policy()
    {
        var client = fallback.Client;

        // The canary proves the fallback policy is actually enforced on this host...
        var hostRoute = await client.GetAsync("/host-route", Cancellation);
        hostRoute.StatusCode.Should().Be(HttpStatusCode.Unauthorized);

        // ...and the JWKS must remain anonymously readable regardless.
        var response = await client.GetAsync(JwksPath, Cancellation);
        response.StatusCode.Should().Be(HttpStatusCode.OK);
    }

    // ── Advertised jwks_uri agreement ────────────────────────────────────────────────────────────

    [Fact]
    public async Task GetJwks_serves_the_jwks_uri_the_discovery_document_advertises_for_a_path_bearing_Issuer()
    {
        var client = tenant.Client;

        var discovery = await client.GetFromJsonAsync<JsonDocument>(
            "/tenant1/.well-known/openid-configuration", Cancellation);
        var jwksUri = new Uri(discovery!.RootElement.GetProperty("jwks_uri").GetString()!);

        jwksUri.Host.Should().Be("test.example.com");
        var response = await client.GetAsync(jwksUri.AbsolutePath, Cancellation);

        response.StatusCode.Should().Be(HttpStatusCode.OK);
        var doc = await response.Content.ReadFromJsonAsync<JsonDocument>(Cancellation);
        doc!.RootElement.GetProperty("keys").GetArrayLength().Should().BeGreaterThan(0);
    }

    [Fact]
    public async Task GetJwks_serves_the_jwks_uri_the_discovery_document_advertises_when_an_override_is_configured()
    {
        using var factory = new TestWebAppFactory(opts =>
        {
            opts.Issuer = "https://login.example.com";
            opts.JwksEndpoint.Uri = "https://login.example.com/keys";
        });
        using var client = CreateClient(factory, "https://login.example.com");

        var discovery = await client.GetFromJsonAsync<JsonDocument>(
            "/.well-known/openid-configuration", Cancellation);
        var jwksUri = new Uri(discovery!.RootElement.GetProperty("jwks_uri").GetString()!);

        jwksUri.Should().Be(new Uri("https://login.example.com/keys"));
        var response = await client.GetAsync(jwksUri.AbsolutePath, Cancellation);

        response.StatusCode.Should().Be(HttpStatusCode.OK);
        var doc = await response.Content.ReadFromJsonAsync<JsonDocument>(Cancellation);
        doc!.RootElement.GetProperty("keys").GetArrayLength().Should().BeGreaterThan(0);
    }

    // ── Routing ──────────────────────────────────────────────────────────────────────────────────

    [Fact]
    public async Task GetJwks_serves_the_published_URI_when_an_explicit_override_is_configured()
    {
        using var factory = new TestWebAppFactory(opts =>
        {
            opts.Issuer = "https://login.example.com";
            opts.JwksEndpoint.Uri = "https://login.example.com/keys";
        });
        using var client = CreateClient(factory, "https://login.example.com");

        var response = await client.GetAsync("/keys", Cancellation);

        response.StatusCode.Should().Be(HttpStatusCode.OK);
        var doc = await response.Content.ReadFromJsonAsync<JsonDocument>(Cancellation);
        doc!.RootElement.GetProperty("keys").GetArrayLength().Should().Be(1);
    }

    [Fact]
    public async Task GetJwks_registers_at_Issuer_prefixed_path_for_path_bearing_Issuer()
    {
        var client = tenant.Client;

        var response = await client.GetAsync("/tenant1/connect/jwks", Cancellation);

        response.StatusCode.Should().Be(HttpStatusCode.OK);
    }

    [Fact]
    public async Task GetJwks_returns_404_for_wrong_host()
    {
        var client = host.ClientFor("https://other.example.com");

        var response = await client.GetAsync(JwksPath, Cancellation);

        response.StatusCode.Should().Be(HttpStatusCode.NotFound);
    }
}
