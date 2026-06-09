using System.Net;
using System.Net.Http.Json;
using System.Text.Json;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Options;
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
        WebApplicationFactory<TestWebAppFactory> factory,
        string baseAddress = "https://test.example.com")
        => factory.CreateClient(new WebApplicationFactoryClientOptions
        {
            BaseAddress = new Uri(baseAddress),
        });

    // ── Status code ───────────────────────────────────────────────────────────────────────────────

    [Fact]
    public async Task GetDiscoveryDocument_returns_200()
    {
        var response = await _client.GetAsync(DiscoveryPath, TestContext.Current.CancellationToken);

        response.StatusCode.Should().Be(HttpStatusCode.OK);
    }

    // ── Content-Type ──────────────────────────────────────────────────────────────────────────────

    [Fact]
    public async Task GetDiscoveryDocument_returns_application_json_content_type()
    {
        var response = await _client.GetAsync(DiscoveryPath, TestContext.Current.CancellationToken);

        response.Content.Headers.ContentType?.MediaType.Should().Be("application/json");
    }

    // ── Cache-Control ─────────────────────────────────────────────────────────────────────────────

    [Fact]
    public async Task GetDiscoveryDocument_returns_Cache_Control_public_max_age_3600()
    {
        var response = await _client.GetAsync(DiscoveryPath, TestContext.Current.CancellationToken);

        response.Headers.CacheControl.Should().NotBeNull();
        response.Headers.CacheControl!.Public.Should().BeTrue();
        response.Headers.CacheControl!.MaxAge.Should().Be(TimeSpan.FromSeconds(3600));
    }

    // ── CORS ──────────────────────────────────────────────────────────────────────────────────────

    [Fact]
    public async Task GetDiscoveryDocument_returns_Access_Control_Allow_Origin_wildcard()
    {
        var response = await _client.GetAsync(DiscoveryPath, TestContext.Current.CancellationToken);

        response.Headers.TryGetValues("Access-Control-Allow-Origin", out var values).Should().BeTrue();
        values.Should().ContainSingle().Which.Should().Be("*");
    }

    // ── Response body ─────────────────────────────────────────────────────────────────────────────

    [Fact]
    public async Task GetDiscoveryDocument_returns_valid_JSON()
    {
        var response = await _client.GetAsync(DiscoveryPath, TestContext.Current.CancellationToken);
        var body = await response.Content.ReadAsStringAsync(TestContext.Current.CancellationToken);

        var act = () => JsonDocument.Parse(body);
        act.Should().NotThrow();
    }

    [Fact]
    public async Task GetDiscoveryDocument_Issuer_matches_configured_Issuer()
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
    public async Task GetDiscoveryDocument_contains_expected_OIDC_discovery_field(string fieldName)
    {
        var doc = await _client.GetFromJsonAsync<JsonDocument>(
            DiscoveryPath,
            TestContext.Current.CancellationToken);

        doc!.RootElement.TryGetProperty(fieldName, out _)
            .Should().BeTrue(because: $"the discovery document should publish the '{fieldName}' field");
    }

    [Fact]
    public async Task GetDiscoveryDocument_serializes_default_metadata_collections_as_expected_strings()
    {
        var doc = await _client.GetFromJsonAsync<JsonDocument>(
            DiscoveryPath,
            TestContext.Current.CancellationToken);

        doc!.RootElement.GetProperty("scopes_supported").EnumerateArray()
            .Select(element => element.GetString())
            .Should().Equal(StandardScopes.All.Select(scope => scope.Name));

        doc.RootElement.GetProperty("response_modes_supported").EnumerateArray()
            .Select(element => element.GetString())
            .Should().Equal("query");

        doc.RootElement.GetProperty("grant_types_supported").EnumerateArray()
            .Select(element => element.GetString())
            .Should().Equal("authorization_code");

        // Test factory adds None on top of the default (ClientSecretBasic only, per ADR 0002).
        doc.RootElement.GetProperty("token_endpoint_auth_methods_supported").EnumerateArray()
            .Select(element => element.GetString())
            .Should().BeEquivalentTo(new[] { "client_secret_basic", "none" });
    }

    [Fact]
    public async Task GetDiscoveryDocument_publishes_repository_scopes_when_using_InMemoryScopeRepository()
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
    public async Task GetDiscoveryDocument_excludes_non_discoverable_scopes_when_using_InMemoryScopeRepository()
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
    public async Task GetUnrelatedPath_is_not_intercepted()
    {
        // The framework must not swallow requests to paths it does not own.
        // A 404 response confirms routing passed through without being intercepted.
        var response = await _client.GetAsync("/ping", TestContext.Current.CancellationToken);

        response.StatusCode.Should().Be(HttpStatusCode.NotFound);
    }

    // ── Method not allowed ────────────────────────────────────────────────────────────────────────

    [Fact]
    public async Task PostDiscoveryDocument_returns_405()
    {
        var response = await _client.PostAsync(
            DiscoveryPath,
            content: null,
            TestContext.Current.CancellationToken);

        response.StatusCode.Should().Be(HttpStatusCode.MethodNotAllowed);
    }

    // ── Path-bearing issuer ───────────────────────────────────────────────────────────────────────

    [Fact]
    public async Task GetDiscoveryDocument_registers_at_Issuer_prefixed_path_for_path_bearing_Issuer()
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
    public async Task GetDiscoveryDocument_returns_404_for_root_path_when_Issuer_has_path()
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
    public void Startup_throws_when_Issuer_is_not_configured()
    {
        using var factory = new TestWebAppFactory(opts => opts.Issuer = null);

        // MapZeeKayDaAuth now forces options validation first, so null issuer failures match
        // ValidateOnStart (OptionsValidationException message text).
        var act = () => factory.CreateClient();

        act.Should().Throw<Exception>().WithMessage("*AuthorizationServerOptions.Issuer must be set to a non-empty value.*");
    }

    [Fact]
    public void Startup_throws_via_ValidateOnStart_for_HTTP_Issuer_without_AllowInsecureIssuer_flag()
    {
        var act = () => new TestWebAppFactory(opts =>
        {
            opts.Issuer = "http://auth.example.com";
            opts.AllowInsecureIssuer = false;
        }).CreateClient();

        act.Should().Throw<Exception>().WithMessage("*HTTPS*");
    }

    [Fact]
    public void Startup_throws_validator_message_for_malformed_Issuer()
    {
        var act = () => new TestWebAppFactory(opts =>
        {
            opts.Issuer = "not-a-valid-uri";
        }).CreateClient();

        act.Should().Throw<Exception>().WithMessage("*not a valid absolute URI*");
    }

    [Fact]
    public void Startup_throws_via_ValidateOnStart_when_endpoint_override_has_different_authority()
    {
        var act = () => new TestWebAppFactory(opts =>
        {
            opts.Issuer = "https://test.example.com";
            opts.TokenEndpoint.Uri = "https://login.example.com/custom/token";
        }).CreateClient();

        act.Should().Throw<Exception>().WithMessage("*same authority*");
    }

    [Fact]
    public void Startup_throws_via_ValidateOnStart_for_custom_scope_repository_without_openid_scope()
    {
        var act = () => new TestWebAppFactory(
            configureBuilder: builder =>
            {
                builder.Services.Replace(
                    ServiceDescriptor.Singleton<IScopeRepository, CustomScopeRepositoryWithoutOpenId>());
            }).CreateClient();

        act.Should().Throw<Exception>().WithMessage($"*{StandardScopes.OpenId.Name}*");
    }

    [Fact]
    public void Startup_succeeds_when_None_auth_method_and_no_AuthorizationCode_grant()
    {
        var act = () => new TestWebAppFactory(opts =>
        {
            opts.TokenEndpoint.AuthMethodsSupported = [TokenEndpointAuthMethods.None];
            opts.GrantTypesSupported = [GrantType.RefreshToken];
        }).CreateClient();

        act.Should().NotThrow();
    }

    [Fact]
    public void Startup_succeeds_when_None_auth_method_and_AuthorizationCode_grant()
    {
        var act = () => new TestWebAppFactory(opts =>
        {
            opts.TokenEndpoint.AuthMethodsSupported = [TokenEndpointAuthMethods.None];
            opts.GrantTypesSupported = [GrantType.AuthorizationCode];
        }).CreateClient();

        act.Should().NotThrow();
    }

    [Fact]
    public void Startup_throws_via_ValidateOnStart_for_out_of_range_GrantType()
    {
        var act = () => new TestWebAppFactory(opts =>
        {
            opts.GrantTypesSupported = [(GrantType)9999];
        }).CreateClient();

        act.Should().Throw<Exception>().WithMessage("*GrantTypesSupported*");
    }

    [Fact]
    public void Startup_throws_via_ValidateOnStart_for_whitespace_TokenEndpointAuthMethod()
    {
        var act = () => new TestWebAppFactory(opts =>
        {
            opts.TokenEndpoint.AuthMethodsSupported = ["   "];
        }).CreateClient();

        act.Should().Throw<Exception>().WithMessage("*TokenEndpoint.AuthMethodsSupported*");
    }

    [Fact]
    public void Startup_throws_via_ValidateOnStart_when_CodeChallengeMethodsSupported_is_empty()
    {
        var act = () => new TestWebAppFactory(opts =>
        {
            opts.AuthorizationEndpoint.CodeChallengeMethodsSupported = [];
        }).CreateClient();

        act.Should().Throw<Exception>().WithMessage("*CodeChallengeMethodsSupported*");
    }

    // ── Configurable Cache-Control ────────────────────────────────────────────────────────────────

    [Fact]
    public async Task GetDiscoveryDocument_reflects_custom_cache_max_age_in_header()
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
    public async Task GetDiscoveryDocument_returns_no_store_for_zero_cache_max_age()
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
    public async Task GetDiscoveryDocument_returns_404_for_wrong_host()
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
    public async Task AdvertisedPreAlphaProtocolEndpoints_return_501(string method, string path)
    {
        using var request = new HttpRequestMessage(new HttpMethod(method), path);

        var response = await _client.SendAsync(request, TestContext.Current.CancellationToken);

        response.StatusCode.Should().Be(HttpStatusCode.NotImplemented);
    }

    [Theory]
    [InlineData("GET", "/custom/authorize?prompt=login")]
    [InlineData("POST", "/custom/token?tenant=1")]
    [InlineData("GET", "/keys")]
    public async Task AdvertisedPreAlphaProtocolEndpoints_return_501_at_published_URIs_when_explicit_overrides_are_configured(string method, string path)
    {
        using var factory = new TestWebAppFactory(opts =>
        {
            opts.Issuer = "https://login.example.com";
            opts.AuthorizationEndpoint.Uri = "https://login.example.com/custom/authorize?prompt=login";
            opts.TokenEndpoint.Uri = "https://login.example.com/custom/token?tenant=1";
            opts.JwksEndpoint.Uri = "https://login.example.com/keys";
        });
        using var client = CreateClient(factory, "https://login.example.com");
        using var request = new HttpRequestMessage(new HttpMethod(method), path);

        var response = await client.SendAsync(request, TestContext.Current.CancellationToken);

        response.StatusCode.Should().Be(HttpStatusCode.NotImplemented);
    }

    [Theory]
    [InlineData("GET", DiscoveryPath)]
    [InlineData("GET", "/connect/authorize")]
    [InlineData("POST", "/connect/authorize")]
    [InlineData("POST", "/connect/token")]
    [InlineData("GET", "/connect/jwks")]
    public async Task HttpRequests_are_rejected_with_421_for_non_loopback_requests(string method, string path)
    {
        using var client = CreateClient(_factory, "http://test.example.com");
        using var request = new HttpRequestMessage(new HttpMethod(method), path);

        var response = await client.SendAsync(request, TestContext.Current.CancellationToken);

        response.StatusCode.Should().Be(HttpStatusCode.MisdirectedRequest);
    }

    [Theory]
    [InlineData("GET", DiscoveryPath, HttpStatusCode.OK)]
    [InlineData("GET", "/connect/authorize", HttpStatusCode.NotImplemented)]
    [InlineData("POST", "/connect/authorize", HttpStatusCode.NotImplemented)]
    [InlineData("POST", "/connect/token", HttpStatusCode.NotImplemented)]
    [InlineData("GET", "/connect/jwks", HttpStatusCode.NotImplemented)]
    public async Task HttpRequests_are_allowed_for_loopback_with_AllowInsecureIssuer_flag(
        string method,
        string path,
        HttpStatusCode expectedStatusCode)
    {
        using var factory = new TestWebAppFactoryWithRemoteIp(IPAddress.Loopback);
        using var client = CreateClient(factory, "http://localhost:5000");
        using var request = new HttpRequestMessage(new HttpMethod(method), path);

        var response = await client.SendAsync(request, TestContext.Current.CancellationToken);

        response.StatusCode.Should().Be(expectedStatusCode);
    }

    // ── Enum field serialization ──────────────────────────────────────────────────────────────────

    [Fact]
    public async Task GetDiscoveryDocument_serializes_required_enum_fields_as_expected_strings()
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
    public async Task GetDiscoveryDocument_derived_endpoints_match_expected_URIs()
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

    // ── CodeChallengeMethodsSupported ─────────────────────────────────────────────────────────────

    [Fact]
    public async Task GetDiscoveryDocument_omits_CodeChallengeMethodsSupported_field_when_null()
    {
        // Default options have CodeChallengeMethodsSupported = null.
        var doc = await _client.GetFromJsonAsync<JsonDocument>(
            DiscoveryPath,
            TestContext.Current.CancellationToken);

        doc!.RootElement.TryGetProperty("code_challenge_methods_supported", out _)
            .Should().BeFalse(because: "the field must be absent when CodeChallengeMethodsSupported is null");
    }

    [Fact]
    public async Task GetDiscoveryDocument_publishes_CodeChallengeMethodsSupported_field_when_S256_is_configured()
    {
        using var factory = new TestWebAppFactory(opts =>
        {
            opts.AuthorizationEndpoint.CodeChallengeMethodsSupported = [CodeChallengeMethod.S256];
        });
        using var client = CreateClient(factory);

        var doc = await client.GetFromJsonAsync<JsonDocument>(
            DiscoveryPath,
            TestContext.Current.CancellationToken);

        doc!.RootElement.TryGetProperty("code_challenge_methods_supported", out var prop)
            .Should().BeTrue(because: "the field must be present when CodeChallengeMethodsSupported is non-null");
        prop.EnumerateArray()
            .Select(e => e.GetString())
            .Should().Equal("S256");
    }

    // ── CORS – wildcard (no allowlist) ────────────────────────────────────────────────────────────

    [Fact]
    public async Task GetDiscoveryDocument_returns_wildcard_CORS_for_empty_allow_list()
    {
        var response = await _client.GetAsync(DiscoveryPath, TestContext.Current.CancellationToken);

        response.Headers.TryGetValues("Access-Control-Allow-Origin", out var values).Should().BeTrue();
        values.Should().ContainSingle().Which.Should().Be("*");
    }

    [Fact]
    public async Task GetDiscoveryDocument_has_no_Vary_Origin_header_for_empty_allow_list()
    {
        var response = await _client.GetAsync(DiscoveryPath, TestContext.Current.CancellationToken);

        // No Vary: Origin in wildcard mode — caches can serve one copy to all origins.
        var varyValues = response.Headers.Vary.SelectMany(v => v.Split(',').Select(s => s.Trim()));
        varyValues.Should().NotContain("Origin", because: "wildcard CORS does not require Vary: Origin");
    }

    // ── CORS – explicit allowlist ─────────────────────────────────────────────────────────────────

    [Fact]
    public async Task GetDiscoveryDocument_returns_specific_origin_for_matching_origin_in_explicit_allow_list()
    {
        using var factory = new TestWebAppFactory(opts =>
            opts.DiscoveryDocument.CorsOrigins.Add("https://app.example.com"));
        using var client = CreateClient(factory);
        client.DefaultRequestHeaders.Add("Origin", "https://app.example.com");

        var response = await client.GetAsync(DiscoveryPath, TestContext.Current.CancellationToken);

        response.Headers.TryGetValues("Access-Control-Allow-Origin", out var values).Should().BeTrue();
        values.Should().ContainSingle().Which.Should().Be("https://app.example.com");
    }

    [Fact]
    public async Task GetDiscoveryDocument_returns_Vary_Origin_header_for_matching_origin_in_explicit_allow_list()
    {
        using var factory = new TestWebAppFactory(opts =>
            opts.DiscoveryDocument.CorsOrigins.Add("https://app.example.com"));
        using var client = CreateClient(factory);
        client.DefaultRequestHeaders.Add("Origin", "https://app.example.com");

        var response = await client.GetAsync(DiscoveryPath, TestContext.Current.CancellationToken);

        var varyValues = response.Headers.Vary.SelectMany(v => v.Split(',').Select(s => s.Trim()));
        varyValues.Should().Contain("Origin");
    }

    [Fact]
    public async Task GetDiscoveryDocument_has_no_ACAO_header_for_non_matching_origin_in_explicit_allow_list()
    {
        using var factory = new TestWebAppFactory(opts =>
            opts.DiscoveryDocument.CorsOrigins.Add("https://app.example.com"));
        using var client = CreateClient(factory);
        client.DefaultRequestHeaders.Add("Origin", "https://evil.example.com");

        var response = await client.GetAsync(DiscoveryPath, TestContext.Current.CancellationToken);

        response.Headers.TryGetValues("Access-Control-Allow-Origin", out _).Should().BeFalse();
    }

    [Fact]
    public async Task GetDiscoveryDocument_returns_Vary_Origin_header_for_non_matching_origin_in_explicit_allow_list()
    {
        using var factory = new TestWebAppFactory(opts =>
            opts.DiscoveryDocument.CorsOrigins.Add("https://app.example.com"));
        using var client = CreateClient(factory);
        client.DefaultRequestHeaders.Add("Origin", "https://evil.example.com");

        var response = await client.GetAsync(DiscoveryPath, TestContext.Current.CancellationToken);

        var varyValues = response.Headers.Vary.SelectMany(v => v.Split(',').Select(s => s.Trim()));
        varyValues.Should().Contain("Origin");
    }

    [Fact]
    public async Task GetDiscoveryDocument_has_no_ACAO_header_when_no_Origin_header_in_explicit_allow_list()
    {
        using var factory = new TestWebAppFactory(opts =>
            opts.DiscoveryDocument.CorsOrigins.Add("https://app.example.com"));
        using var client = CreateClient(factory);

        var response = await client.GetAsync(DiscoveryPath, TestContext.Current.CancellationToken);

        response.Headers.TryGetValues("Access-Control-Allow-Origin", out _).Should().BeFalse();
    }

    [Fact]
    public async Task GetDiscoveryDocument_returns_Vary_Origin_header_when_no_Origin_header_in_explicit_allow_list()
    {
        using var factory = new TestWebAppFactory(opts =>
            opts.DiscoveryDocument.CorsOrigins.Add("https://app.example.com"));
        using var client = CreateClient(factory);

        var response = await client.GetAsync(DiscoveryPath, TestContext.Current.CancellationToken);

        var varyValues = response.Headers.Vary.SelectMany(v => v.Split(',').Select(s => s.Trim()));
        varyValues.Should().Contain("Origin");
    }

    [Fact]
    public async Task GetDiscoveryDocument_emitted_ACAO_value_is_from_allow_list_not_from_request_header()
    {
        // The allowlist stores lowercase canonical entries.
        // The request sends mixed-case. The response must echo the canonical stored value.
        using var factory = new TestWebAppFactory(opts =>
            opts.DiscoveryDocument.CorsOrigins.Add("https://app.example.com"));
        using var client = CreateClient(factory);
        // Send mixed-case — matches case-insensitively but the response must use the stored form.
        client.DefaultRequestHeaders.Add("Origin", "HTTPS://APP.EXAMPLE.COM");

        var response = await client.GetAsync(DiscoveryPath, TestContext.Current.CancellationToken);

        response.Headers.TryGetValues("Access-Control-Allow-Origin", out var values).Should().BeTrue();
        // Must be the stored canonical entry, not the raw request header.
        values.Should().ContainSingle().Which.Should().Be("https://app.example.com");
    }

    // ── CORS startup validation ───────────────────────────────────────────────────────────────────

    [Theory]
    [InlineData("", "empty")]
    [InlineData("https://example.com/path", "path")]
    [InlineData("https://example.com?q=1", "query")]
    [InlineData("https://example.com#frag", "fragment")]
    [InlineData("https://user@example.com", "userinfo")]
    [InlineData("*", "wildcard")]
    [InlineData("https://*.example.com", "wildcard")]
    [InlineData("null", "null literal")]
    [InlineData("https://example.com\r\n", "CRLF")]
    [InlineData("http://app.example.com", "http scheme without AllowInsecureIssuer")]
    public void Startup_throws_via_ValidateOnStart_for_invalid_CORS_origin(string invalidOrigin, string reason)
    {
        var act = () => new TestWebAppFactory(opts =>
            opts.DiscoveryDocument.CorsOrigins.Add(invalidOrigin)).CreateClient();

        act.Should().Throw<Exception>(because: $"'{invalidOrigin}' is invalid ({reason})");
    }

    [Fact]
    public void Startup_throws_via_ValidateOnStart_for_invalid_ReferrerPolicy()
    {
        var act = () => new TestWebAppFactory(opts =>
            opts.SecurityHeaders.ReferrerPolicy = (ZeeKayDa.Auth.ReferrerPolicy)9999).CreateClient();

        act.Should().Throw<Exception>().WithMessage("*ReferrerPolicy*");
    }

    [Fact]
    public void Startup_throws_via_ValidateOnStart_for_invalid_CrossOriginResourcePolicy()
    {
        var act = () => new TestWebAppFactory(opts =>
            opts.SecurityHeaders.CrossOriginResourcePolicy = (ZeeKayDa.Auth.CrossOriginResourcePolicy)9999).CreateClient();

        act.Should().Throw<Exception>().WithMessage("*CrossOriginResourcePolicy*");
    }

    [Fact]
    public void Startup_makes_CorsOriginAllowList_read_only()
    {
        using var factory = new TestWebAppFactory(opts =>
            opts.DiscoveryDocument.CorsOrigins.Add("https://app.example.com"));
        using var client = CreateClient(factory);
        using var scope = factory.Services.CreateScope();
        var options = scope.ServiceProvider.GetRequiredService<IOptions<AuthorizationServerOptions>>().Value;

        options.DiscoveryDocument.CorsOrigins.IsReadOnly.Should().BeTrue();
        var act = () => options.DiscoveryDocument.CorsOrigins.Add("https://admin.example.com");
        act.Should().Throw<NotSupportedException>();
    }

    // ── Defensive security headers ────────────────────────────────────────────────────────────────

    [Fact]
    public async Task GetDiscoveryDocument_returns_X_Content_Type_Options_nosniff_header()
    {
        var response = await _client.GetAsync(DiscoveryPath, TestContext.Current.CancellationToken);

        response.Headers.TryGetValues("X-Content-Type-Options", out var values).Should().BeTrue();
        values.Should().ContainSingle().Which.Should().Be("nosniff");
    }

    [Fact]
    public async Task GetDiscoveryDocument_has_no_X_Content_Type_Options_header_when_content_type_options_disabled()
    {
        using var factory = new TestWebAppFactory(opts =>
            opts.SecurityHeaders.ContentTypeOptionsNoSniff = false);
        using var client = CreateClient(factory);

        var response = await client.GetAsync(DiscoveryPath, TestContext.Current.CancellationToken);

        response.Headers.TryGetValues("X-Content-Type-Options", out _).Should().BeFalse();
    }

    [Fact]
    public async Task GetDiscoveryDocument_returns_Referrer_Policy_no_referrer_header()
    {
        var response = await _client.GetAsync(DiscoveryPath, TestContext.Current.CancellationToken);

        response.Headers.TryGetValues("Referrer-Policy", out var values).Should().BeTrue();
        values.Should().ContainSingle().Which.Should().Be("no-referrer");
    }

    [Fact]
    public async Task GetDiscoveryDocument_reflects_custom_ReferrerPolicy_in_header()
    {
        using var factory = new TestWebAppFactory(opts =>
            opts.SecurityHeaders.ReferrerPolicy = ZeeKayDa.Auth.ReferrerPolicy.StrictOriginWhenCrossOrigin);
        using var client = CreateClient(factory);

        var response = await client.GetAsync(DiscoveryPath, TestContext.Current.CancellationToken);

        response.Headers.TryGetValues("Referrer-Policy", out var values).Should().BeTrue();
        values.Should().ContainSingle().Which.Should().Be("strict-origin-when-cross-origin");
    }

    [Fact]
    public async Task GetDiscoveryDocument_returns_Cross_Origin_Resource_Policy_cross_origin_header()
    {
        var response = await _client.GetAsync(DiscoveryPath, TestContext.Current.CancellationToken);

        response.Headers.TryGetValues("Cross-Origin-Resource-Policy", out var values).Should().BeTrue();
        values.Should().ContainSingle().Which.Should().Be("cross-origin");
    }

    [Fact]
    public async Task GetDiscoveryDocument_reflects_custom_CrossOriginResourcePolicy_in_header()
    {
        using var factory = new TestWebAppFactory(opts =>
            opts.SecurityHeaders.CrossOriginResourcePolicy = ZeeKayDa.Auth.CrossOriginResourcePolicy.SameOrigin);
        using var client = CreateClient(factory);

        var response = await client.GetAsync(DiscoveryPath, TestContext.Current.CancellationToken);

        response.Headers.TryGetValues("Cross-Origin-Resource-Policy", out var values).Should().BeTrue();
        values.Should().ContainSingle().Which.Should().Be("same-origin");
    }

    // ── Route-group isolation ─────────────────────────────────────────────────────────────────────

    [Fact]
    public async Task NonZeeKayDaRoute_does_not_receive_ZeeKayDa_security_headers()
    {
        // TestWebAppFactoryWithPing adds a /ping route outside the ZeeKayDa group.
        using var factory = new TestWebAppFactoryWithPing();
        using var client = CreateClient(factory);

        var response = await client.GetAsync("/ping", TestContext.Current.CancellationToken);

        response.StatusCode.Should().Be(HttpStatusCode.OK);
        response.Headers.TryGetValues("X-Content-Type-Options", out _).Should().BeFalse(
            because: "ZeeKayDa security headers must not leak to application routes");
        response.Headers.TryGetValues("Referrer-Policy", out _).Should().BeFalse();
        response.Headers.TryGetValues("Cross-Origin-Resource-Policy", out _).Should().BeFalse();
    }

    // ── Insecure-issuer header ────────────────────────────────────────────────────────────────────

    [Fact]
    public async Task GetDiscoveryDocument_returns_insecure_issuer_header_when_AllowInsecureIssuer_is_true()
    {
        using var factory = new TestWebAppFactoryWithRemoteIp(IPAddress.Loopback);
        using var client = CreateClient(factory, "http://localhost:5000");

        var response = await client.GetAsync(DiscoveryPath, TestContext.Current.CancellationToken);

        response.Headers.TryGetValues("X-ZeeKayDa-Insecure-Issuer", out var values).Should().BeTrue();
        values.Should().ContainSingle().Which.Should().Be("true");
    }

    [Fact]
    public async Task GetDiscoveryDocument_has_no_insecure_issuer_header_when_AllowInsecureIssuer_is_false()
    {
        var response = await _client.GetAsync(DiscoveryPath, TestContext.Current.CancellationToken);

        response.Headers.TryGetValues("X-ZeeKayDa-Insecure-Issuer", out _).Should().BeFalse();
    }

    // ── Vary pipeline safety ──────────────────────────────────────────────────────────────────────

    [Fact]
    public async Task GetDiscoveryDocument_appends_to_existing_Vary_header_for_explicit_allow_list()
    {
        // Even if upstream middleware adds Vary: Accept-Encoding, our Vary: Origin must be
        // appended, not replace it.
        using var factory = new TestWebAppFactoryWithVaryMiddleware(
            varyToAdd: "Accept-Encoding",
            configureOptions: opts => opts.DiscoveryDocument.CorsOrigins.Add("https://app.example.com"));
        using var client = CreateClient(factory);
        client.DefaultRequestHeaders.Add("Origin", "https://app.example.com");

        var response = await client.GetAsync(DiscoveryPath, TestContext.Current.CancellationToken);

        var varyValues = response.Headers.Vary
            .SelectMany(v => v.Split(',').Select(s => s.Trim()))
            .ToList();
        varyValues.Should().Contain("Accept-Encoding");
        varyValues.Should().Contain("Origin");
    }
}
