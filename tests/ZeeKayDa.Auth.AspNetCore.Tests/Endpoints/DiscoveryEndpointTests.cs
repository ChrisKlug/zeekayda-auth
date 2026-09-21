using System.Net;
using System.Net.Http.Json;
using System.Text.Json;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Options;
using ZeeKayDa.Auth.AspNetCore.Endpoints;
using ZeeKayDa.Auth.Authorization;
using ZeeKayDa.Auth.Scopes;
using ZeeKayDa.Auth.Security;
using ZeeKayDa.Auth.Tokens;

namespace ZeeKayDa.Auth.AspNetCore.Tests.Endpoints;

/// <summary>
/// What the discovery endpoint's handler produces for a request: the status, the response headers it
/// writes itself, and the document. Where the route is registered, whether the group's conventions
/// apply, and what startup does with a broken configuration all live in
/// <see cref="DiscoveryEndpointHostTests"/>, because none of them is the handler's behaviour.
/// </summary>
public sealed class DiscoveryEndpointTests
{
    private const string DiscoveryPath = "/.well-known/openid-configuration";

    private static Task<HttpResponseMessage> GetAsync(EndpointHost host, string? origin = null)
    {
        var request = host.Get(DiscoveryPath);

        if (origin is not null)
            request.WithHeader("Origin", origin);

        return host.InvokeAsync<DiscoveryEndpoint>(e => e.Handle, request);
    }

    private static async Task<JsonElement> GetDocumentAsync(EndpointHost host)
    {
        using var response = await GetAsync(host);
        var body = await response.Content.ReadAsStringAsync(TestContext.Current.CancellationToken);

        return JsonDocument.Parse(body).RootElement;
    }

    private static IEnumerable<string> VaryValues(HttpResponseMessage response)
        => response.Headers.Vary.SelectMany(v => v.Split(',').Select(s => s.Trim()));

    // ── Status code ───────────────────────────────────────────────────────────────────────────────

    [Fact]
    public async Task GetDiscoveryDocument_returns_200()
    {
        using var response = await GetAsync(EndpointHost.Default);

        response.StatusCode.Should().Be(HttpStatusCode.OK);
    }

    // ── Content-Type ──────────────────────────────────────────────────────────────────────────────

    [Fact]
    public async Task GetDiscoveryDocument_returns_application_json_content_type()
    {
        using var response = await GetAsync(EndpointHost.Default);

        response.Content.Headers.ContentType?.MediaType.Should().Be("application/json");
    }

    // ── Cache-Control ─────────────────────────────────────────────────────────────────────────────

    [Fact]
    public async Task GetDiscoveryDocument_returns_Cache_Control_public_max_age_3600()
    {
        using var response = await GetAsync(EndpointHost.Default);

        response.Headers.CacheControl.Should().NotBeNull();
        response.Headers.CacheControl!.Public.Should().BeTrue();
        response.Headers.CacheControl!.MaxAge.Should().Be(TimeSpan.FromSeconds(3600));
    }

    // ── CORS ──────────────────────────────────────────────────────────────────────────────────────

    [Fact]
    public async Task GetDiscoveryDocument_returns_Access_Control_Allow_Origin_wildcard()
    {
        using var response = await GetAsync(EndpointHost.Default);

        response.Headers.TryGetValues("Access-Control-Allow-Origin", out var values).Should().BeTrue();
        values.Should().ContainSingle().Which.Should().Be("*");
    }

    // ── Response body ─────────────────────────────────────────────────────────────────────────────

    [Fact]
    public async Task GetDiscoveryDocument_returns_valid_JSON()
    {
        using var response = await GetAsync(EndpointHost.Default);
        var body = await response.Content.ReadAsStringAsync(TestContext.Current.CancellationToken);

        var act = () => JsonDocument.Parse(body);
        act.Should().NotThrow();
    }

    [Fact]
    public async Task GetDiscoveryDocument_Issuer_matches_configured_Issuer()
    {
        var doc = await GetDocumentAsync(EndpointHost.Default);

        doc.GetProperty("issuer").GetString().Should().Be("https://test.example.com");
    }

    [Theory]
    [InlineData("issuer")]
    [InlineData("authorization_endpoint")]
    [InlineData("token_endpoint")]
    [InlineData("jwks_uri")]
    [InlineData("end_session_endpoint")]
    [InlineData("response_types_supported")]
    [InlineData("scopes_supported")]
    [InlineData("response_modes_supported")]
    [InlineData("grant_types_supported")]
    [InlineData("token_endpoint_auth_methods_supported")]
    [InlineData("subject_types_supported")]
    [InlineData("id_token_signing_alg_values_supported")]
    [InlineData("claims_supported")]
    public async Task GetDiscoveryDocument_contains_expected_OIDC_discovery_field(string fieldName)
    {
        var doc = await GetDocumentAsync(EndpointHost.Default);

        doc.TryGetProperty(fieldName, out _)
            .Should().BeTrue(because: $"the discovery document should publish the '{fieldName}' field");
    }

    [Fact]
    public async Task GetDiscoveryDocument_omits_authorization_endpoint_on_a_host_without_the_code_grant()
    {
        // The endpoint is not served on such a host, so the metadata does not name it: a document
        // pointing at a 404 is worse than one without the field (RFC 8414 §2).
        using var host = new EndpointHost(opts => opts.GrantTypesSupported = [GrantType.ClientCredentials]);

        var doc = await GetDocumentAsync(host);

        doc.TryGetProperty("authorization_endpoint", out _).Should().BeFalse();
        doc.TryGetProperty("response_types_supported", out _).Should().BeFalse("a zero-element claim is omitted, not published empty");
        doc.TryGetProperty("response_modes_supported", out _).Should().BeFalse();
        doc.TryGetProperty("code_challenge_methods_supported", out _).Should().BeFalse();
        doc.TryGetProperty("claims_supported", out _).Should().BeFalse(
            "such a host issues no ID token and answers no UserInfo request, so it can supply none of them");
        doc.TryGetProperty("end_session_endpoint", out _).Should().BeFalse("without the code grant nobody signs in, so there is no session to end");
        doc.TryGetProperty("token_endpoint", out _).Should().BeTrue("the token endpoint is what such a host serves");
    }

    [Fact]
    public async Task GetDiscoveryDocument_derives_end_session_endpoint_from_the_issuer()
    {
        var doc = await GetDocumentAsync(EndpointHost.Default);

        doc.GetProperty("end_session_endpoint").GetString()
            .Should().Be("https://test.example.com/connect/endsession");
    }

    [Fact]
    public async Task GetDiscoveryDocument_publishes_the_end_session_endpoint_override()
    {
        using var host = new EndpointHost(opts => opts.EndSessionEndpoint.Uri = "https://test.example.com/signout");

        var doc = await GetDocumentAsync(host);

        doc.GetProperty("end_session_endpoint").GetString().Should().Be("https://test.example.com/signout");
    }

    [Fact]
    public async Task The_document_a_host_without_the_code_grant_publishes_reads_back_into_the_public_type()
    {
        // The omitted fields are optional on the way in as well: a consumer binding the document
        // to OpenIdConfigurationDocument must not be told a required member is missing.
        using var host = new EndpointHost(opts => opts.GrantTypesSupported = [GrantType.ClientCredentials]);
        using var response = await GetAsync(host);
        var json = await response.Content.ReadAsStringAsync(TestContext.Current.CancellationToken);

        var document = JsonSerializer.Deserialize(json, ZeeKayDaJsonSerializerContext.Default.OpenIdConfigurationDocument);

        document.Should().NotBeNull();
        document!.AuthorizationEndpoint.Should().BeNull();
        document.ResponseTypesSupported.Should().BeNull();
        document.ResponseModesSupported.Should().BeNull();
        document.TokenEndpoint.Should().Be("https://test.example.com/connect/token");
        document.GrantTypesSupported.Should().Equal(GrantType.ClientCredentials);
    }

    [Fact]
    public async Task GetDiscoveryDocument_serializes_default_metadata_collections_as_expected_strings()
    {
        var doc = await GetDocumentAsync(EndpointHost.Default);

        doc.GetProperty("scopes_supported").EnumerateArray()
            .Select(element => element.GetString())
            .Should().Equal(StandardScopes.All.Select(scope => scope.Name));

        doc.GetProperty("response_modes_supported").EnumerateArray()
            .Select(element => element.GetString())
            .Should().Equal("query");

        doc.GetProperty("grant_types_supported").EnumerateArray()
            .Select(element => element.GetString())
            .Should().Equal("authorization_code");

        // The default test configuration adds None on top of the default (ClientSecretBasic only).
        doc.GetProperty("token_endpoint_auth_methods_supported").EnumerateArray()
            .Select(element => element.GetString())
            .Should().BeEquivalentTo(new[] { "client_secret_basic", "none" });
    }

    [Fact]
    public async Task GetDiscoveryDocument_publishes_repository_scopes_when_using_InMemoryScopeRepository()
    {
        using var host = new EndpointHost(
            configureBuilder: builder => builder.AddInMemoryScopes(
            [
                new ScopeDefinition
                {
                    Name = StandardScopes.OpenId.Name,
                    IdTokenClaims = ["sub"],
                    AccessTokenClaims = ["role"],
                },
                new ScopeDefinition
                {
                    Name = StandardScopes.Profile.Name,
                    IdTokenClaims = ["name"],
                    AccessTokenClaims = ["name"],
                },
            ]));

        var doc = await GetDocumentAsync(host);

        doc.GetProperty("scopes_supported").EnumerateArray()
            .Select(element => element.GetString())
            .Should().Equal(StandardScopes.OpenId.Name, StandardScopes.Profile.Name);
    }

    [Fact]
    public async Task GetDiscoveryDocument_excludes_non_discoverable_scopes_when_using_InMemoryScopeRepository()
    {
        using var host = new EndpointHost(
            configureBuilder: builder => builder.AddInMemoryScopes(
            [
                new ScopeDefinition { Name = StandardScopes.OpenId.Name },
                new ScopeDefinition
                {
                    Name = "internal.admin",
                    IsDiscoverable = false,
                    AccessTokenClaims = ["role"],
                },
            ]));

        var doc = await GetDocumentAsync(host);

        doc.GetProperty("scopes_supported").EnumerateArray()
            .Select(element => element.GetString())
            .Should().Equal(StandardScopes.OpenId.Name);
    }

    // ── Configurable Cache-Control ────────────────────────────────────────────────────────────────

    [Fact]
    public async Task GetDiscoveryDocument_reflects_custom_cache_max_age_in_header()
    {
        using var host = new EndpointHost(opts => opts.DiscoveryDocument.CacheMaxAge = TimeSpan.FromSeconds(300));

        using var response = await GetAsync(host);

        response.Headers.CacheControl!.ToString().Should().Contain("max-age=300");
    }

    [Fact]
    public async Task GetDiscoveryDocument_returns_no_store_for_zero_cache_max_age()
    {
        using var host = new EndpointHost(opts => opts.DiscoveryDocument.CacheMaxAge = TimeSpan.Zero);

        using var response = await GetAsync(host);

        response.Headers.CacheControl!.ToString().Should().Be("no-store");
    }

    // ── Enum field serialization ──────────────────────────────────────────────────────────────────

    [Fact]
    public async Task GetDiscoveryDocument_serializes_required_enum_fields_as_expected_strings()
    {
        var doc = await GetDocumentAsync(EndpointHost.Default);

        doc.GetProperty("response_types_supported").EnumerateArray()
            .Select(e => e.GetString()).Should().Equal("code");

        doc.GetProperty("id_token_signing_alg_values_supported").EnumerateArray()
            .Select(e => e.GetString()).Should().Equal("RS256");

        doc.GetProperty("subject_types_supported").EnumerateArray()
            .Select(e => e.GetString()).Should().Equal("public");
    }

    // ── Derived endpoint URIs ─────────────────────────────────────────────────────────────────────

    [Fact]
    public async Task GetDiscoveryDocument_derived_endpoints_match_expected_URIs()
    {
        var doc = await GetDocumentAsync(EndpointHost.Default);

        // The default test configuration's issuer is "https://test.example.com".
        doc.GetProperty("authorization_endpoint").GetString()
            .Should().Be("https://test.example.com/connect/authorize");

        doc.GetProperty("token_endpoint").GetString()
            .Should().Be("https://test.example.com/connect/token");

        doc.GetProperty("jwks_uri").GetString()
            .Should().Be("https://test.example.com/connect/jwks");
    }

    // ── CodeChallengeMethodsSupported ─────────────────────────────────────────────────────────────

    [Fact]
    public async Task GetDiscoveryDocument_publishes_S256_by_default()
    {
        // The default is [S256]: the token endpoint enforces it, so it is advertised from the first start.
        var doc = await GetDocumentAsync(EndpointHost.Default);

        doc.GetProperty("code_challenge_methods_supported").EnumerateArray()
            .Select(e => e.GetString())
            .Should().Equal("S256");
    }

    [Fact]
    public async Task GetDiscoveryDocument_publishes_CodeChallengeMethodsSupported_field_when_S256_is_configured()
    {
        using var host = new EndpointHost(opts =>
            opts.AuthorizationEndpoint.CodeChallengeMethodsSupported = [CodeChallengeMethod.S256]);

        var doc = await GetDocumentAsync(host);

        doc.TryGetProperty("code_challenge_methods_supported", out var prop)
            .Should().BeTrue(because: "the field must be present when CodeChallengeMethodsSupported is non-null");
        prop.EnumerateArray()
            .Select(e => e.GetString())
            .Should().Equal("S256");
    }

    // ── CORS – wildcard (no allowlist) ────────────────────────────────────────────────────────────

    [Fact]
    public async Task GetDiscoveryDocument_returns_wildcard_CORS_for_empty_allow_list()
    {
        using var response = await GetAsync(EndpointHost.Default);

        response.Headers.TryGetValues("Access-Control-Allow-Origin", out var values).Should().BeTrue();
        values.Should().ContainSingle().Which.Should().Be("*");
    }

    [Fact]
    public async Task GetDiscoveryDocument_has_no_Vary_Origin_header_for_empty_allow_list()
    {
        using var response = await GetAsync(EndpointHost.Default);

        // No Vary: Origin in wildcard mode — caches can serve one copy to all origins.
        VaryValues(response).Should().NotContain("Origin", because: "wildcard CORS does not require Vary: Origin");
    }

    // ── CORS – explicit allowlist ─────────────────────────────────────────────────────────────────

    [Fact]
    public async Task GetDiscoveryDocument_returns_specific_origin_for_matching_origin_in_explicit_allow_list()
    {
        using var host = new EndpointHost(opts => opts.CorsOrigins.Add("https://app.example.com"));

        using var response = await GetAsync(host, origin: "https://app.example.com");

        response.Headers.TryGetValues("Access-Control-Allow-Origin", out var values).Should().BeTrue();
        values.Should().ContainSingle().Which.Should().Be("https://app.example.com");
    }

    [Fact]
    public async Task GetDiscoveryDocument_returns_Vary_Origin_header_for_matching_origin_in_explicit_allow_list()
    {
        using var host = new EndpointHost(opts => opts.CorsOrigins.Add("https://app.example.com"));

        using var response = await GetAsync(host, origin: "https://app.example.com");

        VaryValues(response).Should().Contain("Origin");
    }

    [Fact]
    public async Task GetDiscoveryDocument_has_no_ACAO_header_for_non_matching_origin_in_explicit_allow_list()
    {
        using var host = new EndpointHost(opts => opts.CorsOrigins.Add("https://app.example.com"));

        using var response = await GetAsync(host, origin: "https://evil.example.com");

        response.Headers.TryGetValues("Access-Control-Allow-Origin", out _).Should().BeFalse();
    }

    [Fact]
    public async Task GetDiscoveryDocument_returns_Vary_Origin_header_for_non_matching_origin_in_explicit_allow_list()
    {
        using var host = new EndpointHost(opts => opts.CorsOrigins.Add("https://app.example.com"));

        using var response = await GetAsync(host, origin: "https://evil.example.com");

        VaryValues(response).Should().Contain("Origin");
    }

    [Fact]
    public async Task GetDiscoveryDocument_has_no_ACAO_header_when_no_Origin_header_in_explicit_allow_list()
    {
        using var host = new EndpointHost(opts => opts.CorsOrigins.Add("https://app.example.com"));

        using var response = await GetAsync(host);

        response.Headers.TryGetValues("Access-Control-Allow-Origin", out _).Should().BeFalse();
    }

    [Fact]
    public async Task GetDiscoveryDocument_returns_Vary_Origin_header_when_no_Origin_header_in_explicit_allow_list()
    {
        using var host = new EndpointHost(opts => opts.CorsOrigins.Add("https://app.example.com"));

        using var response = await GetAsync(host);

        VaryValues(response).Should().Contain("Origin");
    }

    [Fact]
    public async Task GetDiscoveryDocument_emitted_ACAO_value_is_from_allow_list_not_from_request_header()
    {
        // The allowlist stores lowercase canonical entries. The request sends mixed-case, which
        // matches case-insensitively, but the response must echo the canonical stored value.
        using var host = new EndpointHost(opts => opts.CorsOrigins.Add("https://app.example.com"));

        using var response = await GetAsync(host, origin: "HTTPS://APP.EXAMPLE.COM");

        response.Headers.TryGetValues("Access-Control-Allow-Origin", out var values).Should().BeTrue();
        values.Should().ContainSingle().Which.Should().Be("https://app.example.com");
    }

    [Fact]
    public async Task Startup_makes_CorsOriginAllowList_read_only()
    {
        using var host = new EndpointHost(opts => opts.CorsOrigins.Add("https://app.example.com"));
        await host.EnsureStartedAsync();

        var options = host.Services.GetRequiredService<IOptions<AuthorizationServerOptions>>().Value;

        options.CorsOrigins.IsReadOnly.Should().BeTrue();
        var act = () => options.CorsOrigins.Add("https://admin.example.com");
        act.Should().Throw<NotSupportedException>();
    }

    // ── Startup validation ────────────────────────────────────────────────────────────────────────
    //
    // Host-free: the startup phase runs the same gates, verifiers and activators a host runs.
    // Startup aggregates every failing check into one exception carrying each root cause beneath it,
    // so these assert against the whole chain. DiscoveryEndpointHostTests keeps the one test proving
    // that a host refuses to start at all.

    [Fact]
    public async Task Startup_rejects_an_Issuer_that_is_not_configured()
    {
        using var host = new EndpointHost(opts => opts.Issuer = null);

        var failure = await host.StartupFailureAsync();

        failure.AllMessages().Should().Contain("AuthorizationServerOptions.Issuer must be set to a non-empty value.");
    }

    [Fact]
    public async Task Startup_rejects_an_HTTP_Issuer_without_the_AllowInsecureIssuer_flag()
    {
        using var host = new EndpointHost(opts =>
        {
            opts.Issuer = "http://auth.example.com";
            opts.AllowInsecureIssuer = false;
        });

        var failure = await host.StartupFailureAsync();

        failure.AllMessages().Should().Contain("Only 'https' is permitted");
    }

    [Fact]
    public async Task Startup_rejects_a_malformed_Issuer()
    {
        using var host = new EndpointHost(opts => opts.Issuer = "not-a-valid-uri");

        var failure = await host.StartupFailureAsync();

        failure.AllMessages().Should().Contain("not a valid absolute URI");
    }

    [Fact]
    public async Task Startup_rejects_an_endpoint_override_on_a_different_authority()
    {
        using var host = new EndpointHost(opts =>
        {
            opts.Issuer = "https://test.example.com";
            opts.TokenEndpoint.Uri = "https://login.example.com/custom/token";
        });

        var failure = await host.StartupFailureAsync();

        failure.AllMessages().Should().Contain("same authority");
    }

    [Fact]
    public async Task Startup_rejects_a_custom_scope_repository_without_the_openid_scope()
    {
        using var host = new EndpointHost(
            configureBuilder: builder => builder.Services.Replace(
                ServiceDescriptor.Singleton<IScopeRepository, CustomScopeRepositoryWithoutOpenId>()));

        var failure = await host.StartupFailureAsync();

        failure.AllMessages().Should().Contain(StandardScopes.OpenId.Name);
    }

    [Fact]
    public async Task Startup_accepts_the_None_auth_method_without_the_AuthorizationCode_grant()
    {
        using var host = new EndpointHost(opts =>
        {
            opts.TokenEndpoint.AuthMethodsSupported = [TokenEndpointAuthMethods.None];
            opts.GrantTypesSupported = [GrantType.RefreshToken];
        });

        var act = async () => await host.EnsureStartedAsync();

        await act.Should().NotThrowAsync();
    }

    [Fact]
    public async Task Startup_accepts_the_None_auth_method_with_the_AuthorizationCode_grant()
    {
        using var host = new EndpointHost(opts =>
        {
            opts.TokenEndpoint.AuthMethodsSupported = [TokenEndpointAuthMethods.None];
            opts.GrantTypesSupported = [GrantType.AuthorizationCode];
        });

        var act = async () => await host.EnsureStartedAsync();

        await act.Should().NotThrowAsync();
    }

    [Fact]
    public async Task Startup_rejects_an_out_of_range_GrantType()
    {
        using var host = new EndpointHost(opts => opts.GrantTypesSupported = [(GrantType)9999]);

        var failure = await host.StartupFailureAsync();

        failure.AllMessages().Should().Contain("GrantTypesSupported");
    }

    [Fact]
    public async Task Startup_rejects_a_whitespace_TokenEndpointAuthMethod()
    {
        using var host = new EndpointHost(opts => opts.TokenEndpoint.AuthMethodsSupported = ["   "]);

        var failure = await host.StartupFailureAsync();

        failure.AllMessages().Should().Contain("TokenEndpoint.AuthMethodsSupported");
    }

    [Fact]
    public async Task Startup_rejects_an_empty_CodeChallengeMethodsSupported()
    {
        using var host = new EndpointHost(opts => opts.AuthorizationEndpoint.CodeChallengeMethodsSupported = []);

        var failure = await host.StartupFailureAsync();

        failure.AllMessages().Should().Contain("CodeChallengeMethodsSupported");
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
    public async Task Startup_rejects_an_invalid_CORS_origin(string invalidOrigin, string reason)
    {
        using var host = new EndpointHost(opts => opts.CorsOrigins.Add(invalidOrigin));

        var act = async () => await host.EnsureStartedAsync();

        await act.Should().ThrowAsync<Exception>(because: $"'{invalidOrigin}' is invalid ({reason})");
    }

    [Fact]
    public async Task Startup_rejects_an_invalid_ReferrerPolicy()
    {
        using var host = new EndpointHost(opts => opts.SecurityHeaders.ReferrerPolicy = (ReferrerPolicy)9999);

        var failure = await host.StartupFailureAsync();

        failure.AllMessages().Should().Contain("ReferrerPolicy");
    }

    [Fact]
    public async Task Startup_rejects_an_invalid_CrossOriginResourcePolicy()
    {
        using var host = new EndpointHost(
            opts => opts.SecurityHeaders.CrossOriginResourcePolicy = (CrossOriginResourcePolicy)9999);

        var failure = await host.StartupFailureAsync();

        failure.AllMessages().Should().Contain("CrossOriginResourcePolicy");
    }

    private sealed class CustomScopeRepositoryWithoutOpenId : IScopeRepository
    {
        public ValueTask<IReadOnlyCollection<ScopeDefinition>> GetScopesAsync(CancellationToken cancellationToken = default)
            => ValueTask.FromResult<IReadOnlyCollection<ScopeDefinition>>([StandardScopes.Profile]);
    }

    [Fact]
    public async Task A_scope_repository_breaking_its_contract_answers_500_with_no_configuration_detail()
    {
        // The one anonymous endpoint the framework serves. ValidatedScopeCatalog names the scope
        // and the audience string it refused, and letting that exception escape hands both to the
        // host's error handling — on WebApplication.CreateBuilder in Development, straight onto
        // the developer exception page for an unauthenticated caller.
        var repository = new MutableScopeRepository([StandardScopes.OpenId]);
        using var host = new EndpointHost(
            configureBuilder: builder => builder.Services.AddSingleton<IScopeRepository>(repository));

        // Served once first, so startup has passed and the repository breaks only afterwards.
        (await GetAsync(host)).Dispose();
        repository.Scopes = [StandardScopes.OpenId, new ScopeDefinition { Name = "orders.read", Audience = "orders" }];

        using var response = await GetAsync(host);
        var body = await response.Content.ReadAsStringAsync(TestContext.Current.CancellationToken);

        response.StatusCode.Should().Be(HttpStatusCode.InternalServerError);
        body.Should().NotContain("orders.read").And.NotContain("scopes.audience.invalid");
    }

    [Fact]
    public async Task A_failed_discovery_response_is_not_given_the_cache_headers_of_a_valid_one()
    {
        // A cached 500 would outlive the misconfiguration that caused it.
        var repository = new MutableScopeRepository([StandardScopes.OpenId]);
        using var host = new EndpointHost(
            configureBuilder: builder => builder.Services.AddSingleton<IScopeRepository>(repository));

        (await GetAsync(host)).Dispose();
        repository.Scopes = [StandardScopes.Profile];

        using var response = await GetAsync(host);

        response.StatusCode.Should().Be(HttpStatusCode.InternalServerError);
        response.Headers.CacheControl.Should().BeNull();
    }

    [Fact]
    public async Task A_repository_throwing_anything_else_answers_500_without_the_exception_text()
    {
        // The contract exception is not the only way this endpoint can fail. A repository that
        // starts cleanly and later throws a database error carries that layer's message, which
        // routinely contains a connection string, and this is the only anonymous endpoint the
        // framework serves.
        var repository = new ThrowingAfterStartupRepository();
        using var host = new EndpointHost(
            configureBuilder: builder => builder.Services.AddSingleton<IScopeRepository>(repository));

        (await GetAsync(host)).Dispose();
        repository.Fail = true;

        using var response = await GetAsync(host);
        var body = await response.Content.ReadAsStringAsync(TestContext.Current.CancellationToken);

        response.StatusCode.Should().Be(HttpStatusCode.InternalServerError);
        body.Should().NotContain("Password=").And.NotContain("Server=db");
    }

    /// <summary>Answers correctly until <see cref="Fail"/> is set, then throws as a store would.</summary>
    private sealed class ThrowingAfterStartupRepository : IScopeRepository
    {
        public bool Fail { get; set; }

        public ValueTask<IReadOnlyCollection<ScopeDefinition>> GetScopesAsync(CancellationToken cancellationToken = default) =>
            Fail
                ? throw new InvalidOperationException("Login failed for Server=db;Password=hunter2")
                : ValueTask.FromResult<IReadOnlyCollection<ScopeDefinition>>([StandardScopes.OpenId]);
    }

    private sealed class MutableScopeRepository(IReadOnlyCollection<ScopeDefinition> scopes) : IScopeRepository
    {
        public IReadOnlyCollection<ScopeDefinition> Scopes { get; set; } = scopes;

        public ValueTask<IReadOnlyCollection<ScopeDefinition>> GetScopesAsync(CancellationToken cancellationToken = default) =>
            ValueTask.FromResult(Scopes);
    }
}
