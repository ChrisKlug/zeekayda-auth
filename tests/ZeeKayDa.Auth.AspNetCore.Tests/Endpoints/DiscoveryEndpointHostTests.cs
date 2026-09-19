using System.Net;
using System.Net.Http.Json;
using System.Text.Json;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using ZeeKayDa.Auth.Authorization;
using ZeeKayDa.Auth.Scopes;
using ZeeKayDa.Auth.Security;
using ZeeKayDa.Auth.Tokens;

namespace ZeeKayDa.Auth.AspNetCore.Tests.Endpoints;

/// <summary>
/// The parts of discovery that only a real host can answer: where the routes are registered, the
/// issuer-host constraint, the headers the endpoint group's conventions add, and what startup does
/// with a broken configuration. The handler's own behaviour — the document and the headers it writes
/// itself — is covered host-free in <see cref="DiscoveryEndpointTests"/>.
/// </summary>
[Collection(DefaultHostCollection.Name)]
public sealed class DiscoveryEndpointHostTests(DefaultHostFixture host)
{
    private const string DiscoveryPath = "/.well-known/openid-configuration";
    private const string OAuthMetadataPath = "/.well-known/oauth-authorization-server";

    private static CancellationToken Cancellation => TestContext.Current.CancellationToken;

    private static HttpClient CreateClient(
        WebApplicationFactory<TestWebAppFactory> factory,
        string baseAddress = "https://test.example.com")
        => factory.CreateClient(new WebApplicationFactoryClientOptions
        {
            BaseAddress = new Uri(baseAddress),
        });

    // ── Unrelated paths ───────────────────────────────────────────────────────────────────────────

    [Fact]
    public async Task GetUnrelatedPath_is_not_intercepted()
    {
        // The framework must not swallow requests to paths it does not own.
        // A 404 response confirms routing passed through without being intercepted.
        var response = await host.Client.GetAsync("/ping", Cancellation);

        response.StatusCode.Should().Be(HttpStatusCode.NotFound);
    }

    // ── Method not allowed ────────────────────────────────────────────────────────────────────────

    [Fact]
    public async Task PostDiscoveryDocument_returns_405()
    {
        var response = await host.Client.PostAsync(DiscoveryPath, content: null, Cancellation);

        response.StatusCode.Should().Be(HttpStatusCode.MethodNotAllowed);
    }

    // ── Anonymous access ──────────────────────────────────────────────────────────────────────────

    [Fact]
    public async Task GetDiscoveryDocument_returns_200_under_a_host_wide_fallback_authorization_policy()
    {
        using var factory = new TestWebAppFactoryWithFallbackAuthorizationPolicy();
        using var client = CreateClient(factory);

        // The canary proves the fallback policy is actually enforced on this host...
        var hostRoute = await client.GetAsync("/host-route", Cancellation);
        hostRoute.StatusCode.Should().Be(HttpStatusCode.Unauthorized);

        // ...and the discovery document must remain anonymously readable regardless.
        var response = await client.GetAsync(DiscoveryPath, Cancellation);
        response.StatusCode.Should().Be(HttpStatusCode.OK);
    }

    [Fact]
    public async Task GetOAuthMetadata_returns_200_under_a_host_wide_fallback_authorization_policy()
    {
        using var factory = new TestWebAppFactoryWithFallbackAuthorizationPolicy();
        using var client = CreateClient(factory);

        var response = await client.GetAsync(OAuthMetadataPath, Cancellation);

        response.StatusCode.Should().Be(HttpStatusCode.OK);
    }

    // ── Path-bearing issuer ───────────────────────────────────────────────────────────────────────

    [Fact]
    public async Task GetDiscoveryDocument_registers_at_Issuer_prefixed_path_for_path_bearing_Issuer()
    {
        using var factory = new TestWebAppFactory(opts => opts.Issuer = "https://test.example.com/tenant1");
        using var client = CreateClient(factory);

        var response = await client.GetAsync("/tenant1/.well-known/openid-configuration", Cancellation);

        response.StatusCode.Should().Be(HttpStatusCode.OK);

        var doc = await response.Content.ReadFromJsonAsync<JsonDocument>(Cancellation);
        doc!.RootElement.GetProperty("issuer").GetString()
            .Should().Be("https://test.example.com/tenant1");
    }

    [Fact]
    public async Task GetDiscoveryDocument_returns_404_for_root_path_when_Issuer_has_path()
    {
        using var factory = new TestWebAppFactory(opts => opts.Issuer = "https://test.example.com/tenant1");
        using var client = CreateClient(factory);

        // When the issuer has a path, the root discovery path is not registered.
        var response = await client.GetAsync(DiscoveryPath, Cancellation);

        response.StatusCode.Should().Be(HttpStatusCode.NotFound);
    }

    // ── RFC 8414 Authorization Server Metadata address ────────────────────────────────────────────

    [Fact]
    public async Task GetOAuthMetadata_serves_the_same_document_as_the_OpenID_Connect_path()
    {
        var oidc = await host.Client.GetStringAsync(DiscoveryPath, Cancellation);
        var response = await host.Client.GetAsync(OAuthMetadataPath, Cancellation);

        response.StatusCode.Should().Be(HttpStatusCode.OK);
        response.Content.Headers.ContentType?.MediaType.Should().Be("application/json");
        (await response.Content.ReadAsStringAsync(Cancellation)).Should().Be(oidc,
            because: "one document is published at both addresses");
    }

    [Fact]
    public async Task GetOAuthMetadata_applies_the_same_public_metadata_headers()
    {
        var response = await host.Client.GetAsync(OAuthMetadataPath, Cancellation);

        response.Headers.CacheControl!.Public.Should().BeTrue();
        response.Headers.CacheControl!.MaxAge.Should().Be(TimeSpan.FromSeconds(3600));
        response.Headers.GetValues("Access-Control-Allow-Origin").Should().ContainSingle().Which.Should().Be("*");
    }

    [Fact]
    public async Task GetOAuthMetadata_inserts_the_well_known_segment_before_the_Issuer_path()
    {
        using var factory = new TestWebAppFactory(opts => opts.Issuer = "https://test.example.com/tenant1");
        using var client = CreateClient(factory);

        var response = await client.GetAsync("/.well-known/oauth-authorization-server/tenant1", Cancellation);

        response.StatusCode.Should().Be(HttpStatusCode.OK);
        var doc = await response.Content.ReadFromJsonAsync<JsonDocument>(Cancellation);
        doc!.RootElement.GetProperty("issuer").GetString().Should().Be("https://test.example.com/tenant1",
            because: "RFC 8414 §3.3 requires the issuer to match the one the metadata URL was built from");
    }

    [Fact]
    public async Task GetOAuthMetadata_is_also_served_at_the_appended_form_so_a_path_prefix_proxy_reaches_it()
    {
        using var factory = new TestWebAppFactory(opts => opts.Issuer = "https://test.example.com/tenant1");
        using var client = CreateClient(factory);

        var response = await client.GetAsync("/tenant1/.well-known/oauth-authorization-server", Cancellation);

        response.StatusCode.Should().Be(HttpStatusCode.OK,
            because: "a proxy forwarding only /tenant1/* must reach the OAuth document as it reaches the OpenID Connect one");
        var doc = await response.Content.ReadFromJsonAsync<JsonDocument>(Cancellation);
        doc!.RootElement.GetProperty("issuer").GetString().Should().Be("https://test.example.com/tenant1");
    }

    [Fact]
    public async Task GetOAuthMetadata_returns_404_at_the_root_form_when_Issuer_has_path()
    {
        using var factory = new TestWebAppFactory(opts => opts.Issuer = "https://test.example.com/tenant1");
        using var client = CreateClient(factory);

        var response = await client.GetAsync(OAuthMetadataPath, Cancellation);

        response.StatusCode.Should().Be(HttpStatusCode.NotFound,
            because: "the root address belongs to a root issuer, not to tenant1");
    }

    [Theory]
    [InlineData("/.well-known/oauth-authorization-server/TENANT1")]
    [InlineData("/TENANT1/.well-known/oauth-authorization-server")]
    [InlineData("/TENANT1/.well-known/openid-configuration")]
    [InlineData("/tenant1/.well-known/OPENID-CONFIGURATION")]
    public async Task GetDiscoveryDocument_returns_404_when_the_path_differs_from_the_route_only_in_case(string path)
    {
        using var factory = new TestWebAppFactory(opts => opts.Issuer = "https://test.example.com/tenant1");
        using var client = CreateClient(factory);

        var response = await client.GetAsync(path, Cancellation);

        response.StatusCode.Should().Be(HttpStatusCode.NotFound,
            because: "the issuer path is case-sensitive, so /TENANT1 must not be answered with tenant1's document");
    }

    [Fact]
    public async Task GetOAuthMetadata_is_served_on_a_host_without_the_authorization_code_grant()
    {
        using var factory = new TestWebAppFactory(opts =>
        {
            opts.GrantTypesSupported = [GrantType.ClientCredentials];
            opts.AuthorizationEndpoint.CodeChallengeMethodsSupported = null;
        });
        using var client = CreateClient(factory);

        var oidc = await client.GetAsync(DiscoveryPath, Cancellation);
        var oauth = await client.GetAsync(OAuthMetadataPath, Cancellation);

        oidc.StatusCode.Should().Be(HttpStatusCode.OK,
            because: "resource servers find jwks_uri under the OpenID Connect path even on a non-OP host");
        oauth.StatusCode.Should().Be(HttpStatusCode.OK);
    }

    // ── Startup validation ────────────────────────────────────────────────────────────────────────

    [Fact]
    public void Startup_throws_when_Issuer_is_not_configured()
    {
        using var factory = new TestWebAppFactory(opts => opts.Issuer = null);

        // MapZeeKayDaAuth forces options validation first, so a null issuer fails the way
        // ValidateOnStart reports it (OptionsValidationException message text).
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
            opts.CorsOrigins.Add(invalidOrigin)).CreateClient();

        act.Should().Throw<Exception>(because: $"'{invalidOrigin}' is invalid ({reason})");
    }

    [Fact]
    public void Startup_throws_via_ValidateOnStart_for_invalid_ReferrerPolicy()
    {
        var act = () => new TestWebAppFactory(opts =>
            opts.SecurityHeaders.ReferrerPolicy = (ReferrerPolicy)9999).CreateClient();

        act.Should().Throw<Exception>().WithMessage("*ReferrerPolicy*");
    }

    [Fact]
    public void Startup_throws_via_ValidateOnStart_for_invalid_CrossOriginResourcePolicy()
    {
        var act = () => new TestWebAppFactory(opts =>
            opts.SecurityHeaders.CrossOriginResourcePolicy = (CrossOriginResourcePolicy)9999).CreateClient();

        act.Should().Throw<Exception>().WithMessage("*CrossOriginResourcePolicy*");
    }

    // ── Host binding ──────────────────────────────────────────────────────────────────────────────

    [Fact]
    public async Task GetDiscoveryDocument_returns_404_for_wrong_host()
    {
        var client = host.ClientFor("https://other.example.com");

        var response = await client.GetAsync(DiscoveryPath, Cancellation);

        response.StatusCode.Should().Be(HttpStatusCode.NotFound);
    }

    [Fact]
    public async Task GetOAuthMetadata_returns_404_for_wrong_host()
    {
        var client = host.ClientFor("https://other.example.com");

        var response = await client.GetAsync(OAuthMetadataPath, Cancellation);

        response.StatusCode.Should().Be(HttpStatusCode.NotFound,
            because: "the RFC 8414 address is host-bound like every other route, so it cannot answer as this issuer on another binding");
    }

    // ── Protocol endpoints ────────────────────────────────────────────────────────────────────────

    // The token endpoint validates requests too: a bodiless POST is invalid_request (400).
    // TokenEndpointTests owns its behaviour; this row only pins that the route is mapped.
    [Theory]
    [InlineData("POST", "/connect/token")]
    public async Task TokenEndpoint_is_mapped_and_validates(string method, string path)
    {
        using var request = new HttpRequestMessage(new HttpMethod(method), path);

        var response = await host.Client.SendAsync(request, Cancellation);

        response.StatusCode.Should().Be(HttpStatusCode.BadRequest);
    }

    // The authorization endpoint validates requests, so a parameterless request is a phase-1
    // validation failure (400). AuthorizationEndpointTests owns its behaviour; these rows only pin
    // that the route is mapped and reachable.
    [Theory]
    [InlineData("GET", "/connect/authorize")]
    [InlineData("POST", "/connect/authorize")]
    public async Task AuthorizeEndpoint_is_mapped_and_validates(string method, string path)
    {
        using var request = new HttpRequestMessage(new HttpMethod(method), path);

        var response = await host.Client.SendAsync(request, Cancellation);

        response.StatusCode.Should().Be(HttpStatusCode.BadRequest);
    }

    [Theory]
    [InlineData("GET", "/custom/authorize?prompt=login", HttpStatusCode.BadRequest)]
    [InlineData("POST", "/custom/token?tenant=1", HttpStatusCode.BadRequest)]
    public async Task AdvertisedProtocolEndpoints_answer_at_published_URIs_when_explicit_overrides_are_configured(
        string method, string path, HttpStatusCode expectedStatusCode)
    {
        using var factory = new TestWebAppFactory(opts =>
        {
            opts.Issuer = "https://login.example.com";
            opts.AuthorizationEndpoint.Uri = "https://login.example.com/custom/authorize?prompt=login";
            opts.TokenEndpoint.Uri = "https://login.example.com/custom/token?tenant=1";
        });
        using var client = CreateClient(factory, "https://login.example.com");
        using var request = new HttpRequestMessage(new HttpMethod(method), path);

        var response = await client.SendAsync(request, Cancellation);

        response.StatusCode.Should().Be(expectedStatusCode);
    }

    [Theory]
    [InlineData("GET", DiscoveryPath)]
    [InlineData("GET", "/connect/authorize")]
    [InlineData("POST", "/connect/authorize")]
    [InlineData("POST", "/connect/token")]
    [InlineData("GET", "/connect/jwks")]
    public async Task HttpRequests_are_rejected_with_421_for_non_loopback_requests(string method, string path)
    {
        var client = host.ClientFor("http://test.example.com");
        using var request = new HttpRequestMessage(new HttpMethod(method), path);

        var response = await client.SendAsync(request, Cancellation);

        response.StatusCode.Should().Be(HttpStatusCode.MisdirectedRequest);
    }

    [Theory]
    [InlineData("GET", DiscoveryPath, HttpStatusCode.OK)]
    [InlineData("GET", "/connect/authorize", HttpStatusCode.BadRequest)]
    [InlineData("POST", "/connect/authorize", HttpStatusCode.BadRequest)]
    [InlineData("POST", "/connect/token", HttpStatusCode.BadRequest)]
    [InlineData("GET", "/connect/jwks", HttpStatusCode.OK)]
    public async Task HttpRequests_are_allowed_for_loopback_with_AllowInsecureIssuer_flag(
        string method,
        string path,
        HttpStatusCode expectedStatusCode)
    {
        using var factory = new TestWebAppFactoryWithRemoteIp(IPAddress.Loopback);
        using var client = CreateClient(factory, "http://localhost:5000");
        using var request = new HttpRequestMessage(new HttpMethod(method), path);

        var response = await client.SendAsync(request, Cancellation);

        response.StatusCode.Should().Be(expectedStatusCode);
    }

    // ── Defensive security headers ────────────────────────────────────────────────────────────────
    //
    // Added by the endpoint group's convention in MapZeeKayDaAuth, not by the handler, so these
    // cannot move to a host-free test.

    [Fact]
    public async Task GetDiscoveryDocument_returns_X_Content_Type_Options_nosniff_header()
    {
        var response = await host.Client.GetAsync(DiscoveryPath, Cancellation);

        response.Headers.TryGetValues("X-Content-Type-Options", out var values).Should().BeTrue();
        values.Should().ContainSingle().Which.Should().Be("nosniff");
    }

    [Fact]
    public async Task GetDiscoveryDocument_has_no_X_Content_Type_Options_header_when_content_type_options_disabled()
    {
        using var factory = new TestWebAppFactory(opts =>
            opts.SecurityHeaders.ContentTypeOptionsNoSniff = false);
        using var client = CreateClient(factory);

        var response = await client.GetAsync(DiscoveryPath, Cancellation);

        response.Headers.TryGetValues("X-Content-Type-Options", out _).Should().BeFalse();
    }

    [Fact]
    public async Task GetDiscoveryDocument_returns_Referrer_Policy_no_referrer_header()
    {
        var response = await host.Client.GetAsync(DiscoveryPath, Cancellation);

        response.Headers.TryGetValues("Referrer-Policy", out var values).Should().BeTrue();
        values.Should().ContainSingle().Which.Should().Be("no-referrer");
    }

    [Fact]
    public async Task GetDiscoveryDocument_reflects_custom_ReferrerPolicy_in_header()
    {
        using var factory = new TestWebAppFactory(opts =>
            opts.SecurityHeaders.ReferrerPolicy = ReferrerPolicy.StrictOriginWhenCrossOrigin);
        using var client = CreateClient(factory);

        var response = await client.GetAsync(DiscoveryPath, Cancellation);

        response.Headers.TryGetValues("Referrer-Policy", out var values).Should().BeTrue();
        values.Should().ContainSingle().Which.Should().Be("strict-origin-when-cross-origin");
    }

    [Fact]
    public async Task GetDiscoveryDocument_returns_Cross_Origin_Resource_Policy_same_origin_header()
    {
        var response = await host.Client.GetAsync(DiscoveryPath, Cancellation);

        response.Headers.TryGetValues("Cross-Origin-Resource-Policy", out var values).Should().BeTrue();
        values.Should().ContainSingle().Which.Should().Be("same-origin");
    }

    [Fact]
    public async Task GetDiscoveryDocument_reflects_custom_CrossOriginResourcePolicy_in_header()
    {
        using var factory = new TestWebAppFactory(opts =>
            opts.SecurityHeaders.CrossOriginResourcePolicy = CrossOriginResourcePolicy.SameOrigin);
        using var client = CreateClient(factory);

        var response = await client.GetAsync(DiscoveryPath, Cancellation);

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

        var response = await client.GetAsync("/ping", Cancellation);

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

        var response = await client.GetAsync(DiscoveryPath, Cancellation);

        response.Headers.TryGetValues("X-ZeeKayDa-Insecure-Issuer", out var values).Should().BeTrue();
        values.Should().ContainSingle().Which.Should().Be("true");
    }

    [Fact]
    public async Task GetDiscoveryDocument_has_no_insecure_issuer_header_when_AllowInsecureIssuer_is_false()
    {
        var response = await host.Client.GetAsync(DiscoveryPath, Cancellation);

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
            configureOptions: opts => opts.CorsOrigins.Add("https://app.example.com"));
        using var client = CreateClient(factory);
        client.DefaultRequestHeaders.Add("Origin", "https://app.example.com");

        var response = await client.GetAsync(DiscoveryPath, Cancellation);

        var varyValues = response.Headers.Vary
            .SelectMany(v => v.Split(',').Select(s => s.Trim()))
            .ToList();
        varyValues.Should().Contain("Accept-Encoding");
        varyValues.Should().Contain("Origin");
    }

    private sealed class CustomScopeRepositoryWithoutOpenId : IScopeRepository
    {
        public ValueTask<IReadOnlyCollection<ScopeDefinition>> GetScopesAsync(CancellationToken cancellationToken = default)
            => ValueTask.FromResult<IReadOnlyCollection<ScopeDefinition>>([StandardScopes.Profile]);
    }
}
