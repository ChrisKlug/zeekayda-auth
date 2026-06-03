using System.Net;
using System.Net.Http.Json;
using System.Text.Json;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
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
        _client = CreateClient(_factory);
    }

    public void Dispose()
    {
        _client.Dispose();
        _factory.Dispose();
    }

    private static HttpClient CreateClient(
        TestWebAppFactory factory,
        string baseAddress = "https://test.example.com")
        => factory.CreateClient(new WebApplicationFactoryClientOptions
        {
            BaseAddress = new Uri(baseAddress),
        });

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
    public async Task GetDiscoveryDocument_ReturnsCacheControlPublicMaxAge3600()
    {
        var response = await _client.GetAsync(DiscoveryPath, TestContext.Current.CancellationToken);

        response.Headers.CacheControl.Should().NotBeNull();
        response.Headers.CacheControl!.Public.Should().BeTrue();
        response.Headers.CacheControl!.MaxAge.Should().Be(TimeSpan.FromSeconds(3600));
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
            .Should().Equal(StandardScopes.OpenId.Name, StandardScopes.Profile.Name);

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
                    Name = StandardScopes.OpenId.Name,
                    IdTokenClaims = ["sub"],
                    AccessTokenClaims = ["scope"],
                },
                new ScopeDefinition
                {
                    Name = StandardScopes.Profile.Name,
                    IdTokenClaims = ["name"],
                    AccessTokenClaims = ["name"],
                },
            ]));
        using var client = CreateClient(factory);

        var doc = await client.GetFromJsonAsync<JsonDocument>(
            DiscoveryPath,
            TestContext.Current.CancellationToken);

        doc!.RootElement.GetProperty("scopes_supported").EnumerateArray()
            .Select(element => element.GetString())
            .Should().Equal(StandardScopes.OpenId.Name, StandardScopes.Profile.Name);
    }

    [Fact]
    public async Task GetDiscoveryDocument_InMemoryScopeRepository_ExcludesNonDiscoverableScopes()
    {
        using var factory = new TestWebAppFactory(
            configureBuilder: builder => builder.AddInMemoryScopes(
            [
                new ScopeDefinition { Name = StandardScopes.OpenId.Name },
                new ScopeDefinition
                {
                    Name = "internal.admin",
                    IsDiscoverable = false,
                    AccessTokenClaims = ["scope"],
                },
            ]));
        using var client = CreateClient(factory);

        var doc = await client.GetFromJsonAsync<JsonDocument>(
            DiscoveryPath,
            TestContext.Current.CancellationToken);

        doc!.RootElement.GetProperty("scopes_supported").EnumerateArray()
            .Select(element => element.GetString())
            .Should().Equal(StandardScopes.OpenId.Name);
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
        using var client = CreateClient(factory);

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
        using var client = CreateClient(factory);

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

    [Fact]
    public void Startup_HttpIssuerWithoutFlag_ThrowsViaValidateOnStart()
    {
        // http://auth.example.com is non-null (passes the Map() guard) but invalid.
        // ValidateOnStart must surface the failure before the host accepts requests.
        var act = () => new TestWebAppFactory(opts =>
        {
            opts.Issuer = "http://auth.example.com";
            opts.AllowInsecureIssuer = false;
        }).CreateClient();

        act.Should().Throw<Exception>().WithMessage("*HTTPS*");
    }

    [Fact]
    public void Startup_CustomScopeRepositoryWithoutOpenId_ThrowsViaValidateOnStart()
    {
        var act = () => new TestWebAppFactory(
            configureBuilder: builder =>
            {
                builder.Services.Replace(
                    ServiceDescriptor.Singleton<IScopeRepository, CustomScopeRepositoryWithoutOpenId>());
            }).CreateClient();

        act.Should().Throw<Exception>().WithMessage($"*{StandardScopes.OpenId.Name}*");
    }

    // ── Configurable Cache-Control ────────────────────────────────────────────────────────────────

    [Fact]
    public async Task GetDiscoveryDocument_CustomCacheMaxAge_IsReflectedInHeader()
    {
        using var factory = new TestWebAppFactory(opts =>
        {
            opts.Issuer = "https://test.example.com";
            opts.DiscoveryDocument.CacheMaxAgeSeconds = 300;
        });
        using var client = CreateClient(factory);

        var response = await client.GetAsync(DiscoveryPath, TestContext.Current.CancellationToken);

        response.Headers.CacheControl!.ToString().Should().Contain("max-age=300");
    }

    [Fact]
    public async Task GetDiscoveryDocument_ZeroCacheMaxAge_ReturnsNoStore()
    {
        using var factory = new TestWebAppFactory(opts =>
        {
            opts.Issuer = "https://test.example.com";
            opts.DiscoveryDocument.CacheMaxAgeSeconds = 0;
        });
        using var client = CreateClient(factory);

        var response = await client.GetAsync(DiscoveryPath, TestContext.Current.CancellationToken);

        response.Headers.CacheControl!.ToString().Should().Be("no-store");
    }

    // ── Host binding ──────────────────────────────────────────────────────────────────────────────

    [Fact]
    public async Task GetDiscoveryDocument_WrongHostReturns404()
    {
        using var client = CreateClient(_factory, "https://other.example.com");

        var response = await client.GetAsync(DiscoveryPath, TestContext.Current.CancellationToken);

        response.StatusCode.Should().Be(HttpStatusCode.NotFound);
    }

    // ── Pre-alpha protocol endpoints ──────────────────────────────────────────────────────────────

    [Theory]
    [InlineData("GET", "/connect/authorize")]
    [InlineData("POST", "/connect/authorize")]
    [InlineData("POST", "/connect/token")]
    [InlineData("GET", "/connect/jwks")]
    public async Task AdvertisedPreAlphaProtocolEndpoints_Return501(string method, string path)
    {
        using var request = new HttpRequestMessage(new HttpMethod(method), path);

        var response = await _client.SendAsync(request, TestContext.Current.CancellationToken);

        response.StatusCode.Should().Be(HttpStatusCode.NotImplemented);
    }

    [Theory]
    [InlineData("GET", "/custom/authorize?prompt=login")]
    [InlineData("POST", "/custom/token?tenant=1")]
    [InlineData("GET", "/keys")]
    public async Task AdvertisedPreAlphaProtocolEndpoints_ExplicitOverrides_Return501AtPublishedUris(string method, string path)
    {
        using var factory = new TestWebAppFactory(opts =>
        {
            opts.AuthorizationEndpoint.Uri = "https://login.example.com/custom/authorize?prompt=login";
            opts.TokenEndpoint.Uri = "https://login.example.com/custom/token?tenant=1";
            opts.JwksEndpoint.Uri = "https://login.example.com/keys";
        });
        using var client = CreateClient(factory, "https://login.example.com");
        using var request = new HttpRequestMessage(new HttpMethod(method), path);

        var response = await client.SendAsync(request, TestContext.Current.CancellationToken);

        response.StatusCode.Should().Be(HttpStatusCode.NotImplemented);
    }

    // ── Enum field serialization ──────────────────────────────────────────────────────────────────

    [Fact]
    public async Task GetDiscoveryDocument_RequiredEnumFields_AreSerializedAsExpectedStrings()
    {
        var response = await _client.GetAsync(DiscoveryPath, TestContext.Current.CancellationToken);
        var doc = await response.Content.ReadFromJsonAsync<JsonDocument>(TestContext.Current.CancellationToken);

        doc!.RootElement.GetProperty("response_types_supported").EnumerateArray()
            .Select(e => e.GetString()).Should().Equal("code");

        doc.RootElement.GetProperty("id_token_signing_alg_values_supported").EnumerateArray()
            .Select(e => e.GetString()).Should().Equal("RS256");

        doc.RootElement.GetProperty("subject_types_supported").EnumerateArray()
            .Select(e => e.GetString()).Should().Equal("public");
    }

    // ── Derived endpoint URIs ─────────────────────────────────────────────────────────────────────

    [Fact]
    public async Task GetDiscoveryDocument_DerivedEndpoints_MatchExpectedUris()
    {
        var response = await _client.GetAsync(DiscoveryPath, TestContext.Current.CancellationToken);
        var doc = await response.Content.ReadFromJsonAsync<JsonDocument>(TestContext.Current.CancellationToken);

        // The test host issuer is "https://test.example.com"
        doc!.RootElement.GetProperty("authorization_endpoint").GetString()
            .Should().Be("https://test.example.com/connect/authorize");

        doc.RootElement.GetProperty("token_endpoint").GetString()
            .Should().Be("https://test.example.com/connect/token");

        doc.RootElement.GetProperty("jwks_uri").GetString()
            .Should().Be("https://test.example.com/connect/jwks");
    }

    private sealed class CustomScopeRepositoryWithoutOpenId : IScopeRepository
    {
        public ValueTask<IReadOnlyCollection<ScopeDefinition>> GetScopesAsync(CancellationToken cancellationToken = default)
            => ValueTask.FromResult<IReadOnlyCollection<ScopeDefinition>>([StandardScopes.Profile]);
    }
}
