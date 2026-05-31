using System.Net;
using System.Net.Http.Json;
using System.Text.Json;
using Xunit.Sdk;
using ZeeKayDa.Auth.AspNetCore.Extensions;
using ZeeKayDa.Auth.Scopes;

namespace ZeeKayDa.Auth.AspNetCore.Tests.Endpoints;

public sealed class DiscoveryEndpointTests : IDisposable
{
    private const string DiscoveryPath = "/.well-known/openid-configuration";

    private readonly TestWebAppFactory _factory;
    private readonly HttpClient _client;

    public DiscoveryEndpointTests()
    {
        _factory = new TestWebAppFactory();
        _client = _factory.CreateClient();
    }

    public void Dispose()
    {
        _client.Dispose();
        _factory.Dispose();
    }

    // ── Status code ───────────────────────────────────────────────────────────────────────────────

    [Fact]
    public async Task GetDiscoveryDocument_Returns200()
    {
        var response = await _client.GetAsync(DiscoveryPath, TestContext.Current.CancellationToken);

        response.StatusCode.Should().Be(HttpStatusCode.OK);
    }

    // ── Content-Type ──────────────────────────────────────────────────────────────────────────────

    [Fact]
    public async Task GetDiscoveryDocument_ReturnsApplicationJsonContentType()
    {
        var response = await _client.GetAsync(DiscoveryPath, TestContext.Current.CancellationToken);

        response.Content.Headers.ContentType?.MediaType.Should().Be("application/json");
    }

    // ── Cache-Control ─────────────────────────────────────────────────────────────────────────────

    [Fact]
    public async Task GetDiscoveryDocument_ReturnsCacheControlPublicMaxAge86400()
    {
        var response = await _client.GetAsync(DiscoveryPath, TestContext.Current.CancellationToken);

        response.Headers.CacheControl.Should().NotBeNull();
        response.Headers.CacheControl!.Public.Should().BeTrue();
        response.Headers.CacheControl!.MaxAge.Should().Be(TimeSpan.FromSeconds(86400));
    }

    // ── CORS ──────────────────────────────────────────────────────────────────────────────────────

    [Fact]
    public async Task GetDiscoveryDocument_ReturnsAccessControlAllowOriginWildcard()
    {
        var response = await _client.GetAsync(DiscoveryPath, TestContext.Current.CancellationToken);

        response.Headers.TryGetValues("Access-Control-Allow-Origin", out var values).Should().BeTrue();
        values.Should().ContainSingle().Which.Should().Be("*");
    }

    // ── Response body ─────────────────────────────────────────────────────────────────────────────

    [Fact]
    public async Task GetDiscoveryDocument_ReturnsValidJson()
    {
        var response = await _client.GetAsync(DiscoveryPath, TestContext.Current.CancellationToken);
        var body = await response.Content.ReadAsStringAsync(TestContext.Current.CancellationToken);

        var act = () => JsonDocument.Parse(body);
        act.Should().NotThrow();
    }

    [Fact]
    public async Task GetDiscoveryDocument_IssuerMatchesConfiguredIssuer()
    {
        var doc = await _client.GetFromJsonAsync<JsonDocument>(
            DiscoveryPath,
            TestContext.Current.CancellationToken);

        doc!.RootElement.GetProperty("issuer").GetString()
            .Should().Be("https://test.example.com");
    }

    [Theory]
    [InlineData("issuer")]
    [InlineData("authorization_endpoint")]
    [InlineData("token_endpoint")]
    [InlineData("jwks_uri")]
    [InlineData("response_types_supported")]
    [InlineData("scopes_supported")]
    [InlineData("response_modes_supported")]
    [InlineData("grant_types_supported")]
    [InlineData("token_endpoint_auth_methods_supported")]
    [InlineData("subject_types_supported")]
    [InlineData("id_token_signing_alg_values_supported")]
    public async Task GetDiscoveryDocument_ContainsExpectedOidcDiscoveryField(string fieldName)
    {
        var doc = await _client.GetFromJsonAsync<JsonDocument>(
            DiscoveryPath,
            TestContext.Current.CancellationToken);

        doc!.RootElement.TryGetProperty(fieldName, out _)
            .Should().BeTrue(because: $"the discovery document should publish the '{fieldName}' field");
    }

    [Fact]
    public async Task GetDiscoveryDocument_DefaultMetadataCollections_AreSerializedAsExpectedStrings()
    {
        var doc = await _client.GetFromJsonAsync<JsonDocument>(
            DiscoveryPath,
            TestContext.Current.CancellationToken);

        doc!.RootElement.GetProperty("scopes_supported").EnumerateArray()
            .Select(element => element.GetString())
            .Should().Equal(ScopeNames.OpenId, ScopeNames.Profile);

        doc.RootElement.GetProperty("response_modes_supported").EnumerateArray()
            .Select(element => element.GetString())
            .Should().Equal("query");

        doc.RootElement.GetProperty("grant_types_supported").EnumerateArray()
            .Select(element => element.GetString())
            .Should().Equal("authorization_code");

        doc.RootElement.GetProperty("token_endpoint_auth_methods_supported").EnumerateArray()
            .Select(element => element.GetString())
            .Should().Equal("client_secret_basic");
    }

    [Fact]
    public async Task GetDiscoveryDocument_InMemoryScopeRepository_PublishesRepositoryScopes()
    {
        using var factory = new TestWebAppFactory(
            configureBuilder: builder => builder.AddInMemoryScopes(
            [
                new ScopeDefinition
                {
                    Name = ScopeNames.OpenId,
                    IdTokenClaims = ["sub"],
                    AccessTokenClaims = ["scope"],
                },
                new ScopeDefinition
                {
                    Name = ScopeNames.Profile,
                    IdTokenClaims = ["name"],
                    AccessTokenClaims = ["name"],
                },
            ]));
        using var client = factory.CreateClient();

        var doc = await client.GetFromJsonAsync<JsonDocument>(
            DiscoveryPath,
            TestContext.Current.CancellationToken);

        doc!.RootElement.GetProperty("scopes_supported").EnumerateArray()
            .Select(element => element.GetString())
            .Should().Equal(ScopeNames.OpenId, ScopeNames.Profile);
    }

    [Fact]
    public async Task GetDiscoveryDocument_InMemoryScopeRepository_ExcludesNonDiscoverableScopes()
    {
        using var factory = new TestWebAppFactory(
            configureBuilder: builder => builder.AddInMemoryScopes(
            [
                new ScopeDefinition { Name = ScopeNames.OpenId },
                new ScopeDefinition
                {
                    Name = "internal.admin",
                    IsDiscoverable = false,
                    AccessTokenClaims = ["scope"],
                },
            ]));
        using var client = factory.CreateClient();

        var doc = await client.GetFromJsonAsync<JsonDocument>(
            DiscoveryPath,
            TestContext.Current.CancellationToken);

        doc!.RootElement.GetProperty("scopes_supported").EnumerateArray()
            .Select(element => element.GetString())
            .Should().Equal(ScopeNames.OpenId);
    }

    // ── Unrelated paths ───────────────────────────────────────────────────────────────────────────

    [Fact]
    public async Task GetUnrelatedPath_IsNotIntercepted()
    {
        // The framework must not swallow requests to paths it does not own.
        // A 404 response confirms routing passed through without being intercepted.
        var response = await _client.GetAsync("/ping", TestContext.Current.CancellationToken);

        response.StatusCode.Should().Be(HttpStatusCode.NotFound);
    }

    // ── Method not allowed ────────────────────────────────────────────────────────────────────────

    [Fact]
    public async Task PostDiscoveryDocument_Returns405()
    {
        var response = await _client.PostAsync(
            DiscoveryPath,
            content: null,
            TestContext.Current.CancellationToken);

        response.StatusCode.Should().Be(HttpStatusCode.MethodNotAllowed);
    }

    // ── Path-bearing issuer ───────────────────────────────────────────────────────────────────────

    [Fact]
    public async Task GetDiscoveryDocument_PathBearingIssuer_RegistersAtIssuerPrefixedPath()
    {
        using var factory = new TestWebAppFactory(opts => opts.Issuer = "https://test.example.com/tenant1");
        using var client = factory.CreateClient();

        var response = await client.GetAsync(
            "/tenant1/.well-known/openid-configuration",
            TestContext.Current.CancellationToken);

        response.StatusCode.Should().Be(HttpStatusCode.OK);

        var doc = await response.Content.ReadFromJsonAsync<JsonDocument>(
            TestContext.Current.CancellationToken);
        doc!.RootElement.GetProperty("issuer").GetString()
            .Should().Be("https://test.example.com/tenant1");
    }

    [Fact]
    public async Task GetDiscoveryDocument_PathBearingIssuer_RootPathReturns404()
    {
        using var factory = new TestWebAppFactory(opts => opts.Issuer = "https://test.example.com/tenant1");
        using var client = factory.CreateClient();

        // When the issuer has a path, the root discovery path is not registered.
        var response = await client.GetAsync(
            "/.well-known/openid-configuration",
            TestContext.Current.CancellationToken);

        response.StatusCode.Should().Be(HttpStatusCode.NotFound);
    }

    // ── Startup validation ────────────────────────────────────────────────────────────────────────

    [Fact]
    public void Startup_WithoutIssuer_Throws()
    {
        using var factory = new TestWebAppFactory(opts => opts.Issuer = null);

        // Issuer = null fails in Map() (route registration) before ValidateOnStart can run.
        var act = () => factory.CreateClient();

        act.Should().Throw<Exception>();
    }
}
