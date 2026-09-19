using System.Net;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Security.Claims;
using System.Text.Json;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Routing;
using Microsoft.AspNetCore.WebUtilities;
using Microsoft.Extensions.DependencyInjection;
using ZeeKayDa.Auth.AspNetCore.Interaction;
using ZeeKayDa.Auth.AspNetCore.Tests.Interaction;
using ZeeKayDa.Auth.Authorization;
using ZeeKayDa.Auth.Claims;
using ZeeKayDa.Auth.Clients;
using ZeeKayDa.Auth.Scopes;

namespace ZeeKayDa.Auth.AspNetCore.Tests.Endpoints;

/// <summary>
/// The userinfo endpoint end to end: a real access token, obtained by really signing in and
/// really redeeming a code, is presented back and answered with the subject's claims. The
/// refusals — no token, a token this server did not issue, one without <c>openid</c>, a subject
/// the provider has since disowned — are recorded by the tests that prove them.
/// </summary>
public sealed class UserInfoEndpointTests : IDisposable
{
    private const string UserInfoPath = "/connect/userinfo";
    private const string TokenPath = "/connect/token";
    private const string Issuer = "https://test.example.com";
    private const string Redirect = "https://test.example.com/callback";
    private const string LoginPath = "/account/login";
    private const string App = "app";
    private const string Subject = "user-1";
    private const string OrdersAudience = "https://orders.example.com/";

    // RFC 7636 Appendix B.
    private const string Verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
    private const string CodeChallenge = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM";

    private static readonly ClaimRecord[] DefaultPool =
    [
        new("name", "Chris Example"),
        new("email", "chris@example.com"),
        new("email_verified", true),
        new("customer_number", "CUST-00042"),
        new("role", "orders-admin-4e1"),
    ];

    private readonly ScriptedClaimsProvider _provider = new();
    private readonly MutableScopeRepository _scopes = new(
    [
        .. StandardScopes.All,
        new ScopeDefinition { Name = "orders.read", Audience = OrdersAudience, AccessTokenClaims = ["role"], UserInfoClaims = ["customer_number"] },
    ]);
    private readonly TestWebAppFactory _factory;
    private readonly HttpClient _client;

    public UserInfoEndpointTests()
    {
        _factory = new TestWebAppFactory(
            configureBuilder: builder =>
            {
                builder.Services.AddSingleton<IScopeRepository>(_scopes);
                builder.Services.AddSingleton<IClaimsProvider>(_provider);
                builder.AddInMemoryClients(clients => clients
                    .Add(ClientRegistration.CreatePublic(App, [Redirect], [], ["openid", "profile", "email", "orders.read"]) with { RequireConsent = false }));
            },
            mapEndpoints: MapLoginPage);
        _client = _factory.CreateClient(new() { BaseAddress = new Uri(Issuer), AllowAutoRedirect = false, HandleCookies = true });
    }

    public void Dispose()
    {
        _client.Dispose();
        _factory.Dispose();
    }

    private static CancellationToken Cancellation => TestContext.Current.CancellationToken;

    // ── The claims it answers ─────────────────────────────────────────────────────────────────

    [Fact]
    public async Task A_bearer_token_is_answered_with_sub_and_the_claims_its_scopes_unlock()
    {
        var claims = await GetUserInfoAsync(await AccessTokenAsync("openid profile"));

        claims.GetProperty("sub").GetString().Should().Be(Subject);
        claims.GetProperty("name").GetString().Should().Be("Chris Example");
        claims.TryGetProperty("email", out _).Should().BeFalse("the email scope was not granted");
    }

    [Fact]
    public async Task The_email_scope_unlocks_email_and_a_boolean_email_verified()
    {
        var claims = await GetUserInfoAsync(await AccessTokenAsync("openid email"));

        claims.GetProperty("email").GetString().Should().Be("chris@example.com");
        claims.GetProperty("email_verified").ValueKind.Should().Be(JsonValueKind.True, "a boolean on the wire, not the string \"true\"");
    }

    [Fact]
    public async Task A_userinfo_only_claim_reaches_userinfo_and_no_token()
    {
        var claims = await GetUserInfoAsync(await AccessTokenAsync("openid orders.read"));

        claims.GetProperty("customer_number").GetString().Should().Be("CUST-00042");
        claims.TryGetProperty("role", out _).Should().BeFalse("role is an access-token claim of that scope, not a userinfo one");
    }

    [Fact]
    public async Task A_claim_the_provider_does_not_return_is_absent_rather_than_null()
    {
        _provider.Script = _ => Resolved([new("name", "Chris Example")]);

        var claims = await GetUserInfoAsync(await AccessTokenAsync("openid profile email"));

        claims.TryGetProperty("email", out _).Should().BeFalse("OpenID Connect Core §5.3.2: an unavailable claim is omitted, never null");
    }

    [Fact]
    public async Task A_provider_cannot_override_sub()
    {
        _provider.Script = _ => Resolved([new("name", "Chris Example"), new("sub", "mallory")]);

        var claims = await GetUserInfoAsync(await AccessTokenAsync("openid profile"));

        claims.GetProperty("sub").GetString().Should().Be(Subject);
    }

    [Fact]
    public async Task The_claims_are_resolved_fresh_with_no_family_id()
    {
        var token = await AccessTokenAsync("openid profile");
        _provider.Reset();

        await GetUserInfoAsync(token);

        var context = _provider.Calls.Should().ContainSingle().Subject;
        context.Sub.Should().Be(Subject);
        context.Scopes.Should().Equal("openid", "profile");
        context.FamilyId.Should().BeNull("there is no grant at userinfo, only a token proving one existed");
    }

    [Fact]
    public async Task A_second_call_asks_the_provider_again()
    {
        var token = await AccessTokenAsync("openid profile");
        _provider.Reset();

        await GetUserInfoAsync(token);
        await GetUserInfoAsync(token);

        _provider.Calls.Should().HaveCount(2, "nothing is cached here; a changed subject must show up at the next call");
    }

    [Fact]
    public async Task The_response_is_json_and_never_cached()
    {
        var response = await GetAsync(await AccessTokenAsync("openid profile"));

        response.Content.Headers.ContentType!.MediaType.Should().Be("application/json");
        response.Headers.CacheControl!.NoStore.Should().BeTrue("the claims are personal data read with a credential");
    }

    // ── How the token may be presented ────────────────────────────────────────────────────────

    [Fact]
    public async Task The_token_may_be_presented_in_a_form_post()
    {
        var token = await AccessTokenAsync("openid profile");
        using var form = new FormUrlEncodedContent(new Dictionary<string, string> { ["access_token"] = token });

        var response = await _client.PostAsync(UserInfoPath, form, Cancellation);

        response.StatusCode.Should().Be(HttpStatusCode.OK, "RFC 6750 §2.2 allows the form-encoded body parameter");
        (await ClaimsOf(response)).GetProperty("sub").GetString().Should().Be(Subject);
    }

    [Fact]
    public async Task Presenting_the_token_twice_over_is_invalid_request()
    {
        var token = await AccessTokenAsync("openid profile");
        using var form = new FormUrlEncodedContent(new Dictionary<string, string> { ["access_token"] = token });
        using var request = new HttpRequestMessage(HttpMethod.Post, UserInfoPath) { Content = form };
        request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", token);

        var response = await _client.SendAsync(request, Cancellation);

        response.StatusCode.Should().Be(HttpStatusCode.BadRequest);
        Challenge(response).Should().Contain("error=\"invalid_request\"");
    }

    [Fact]
    public async Task A_repeated_access_token_field_alongside_a_valid_header_is_invalid_request()
    {
        // The repeated field must not read as no field at all: that would let a request present
        // its token twice and be answered from the header as though it had presented it once.
        var token = await AccessTokenAsync("openid profile");
        using var form = new StringContent(
            $"access_token={Uri.EscapeDataString(token)}&access_token=second",
            System.Text.Encoding.UTF8,
            "application/x-www-form-urlencoded");
        using var request = new HttpRequestMessage(HttpMethod.Post, UserInfoPath) { Content = form };
        request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", token);

        var response = await _client.SendAsync(request, Cancellation);

        response.StatusCode.Should().Be(HttpStatusCode.BadRequest);
        Challenge(response).Should().Contain("error=\"invalid_request\"");
    }

    [Fact]
    public async Task A_repeated_access_token_field_on_its_own_is_invalid_request_not_a_bare_challenge()
    {
        var token = await AccessTokenAsync("openid profile");
        using var form = new StringContent(
            $"access_token={Uri.EscapeDataString(token)}&access_token=second",
            System.Text.Encoding.UTF8,
            "application/x-www-form-urlencoded");

        var response = await _client.PostAsync(UserInfoPath, form, Cancellation);

        response.StatusCode.Should().Be(HttpStatusCode.BadRequest,
            "RFC 6750 §3.1: a request repeating a parameter is malformed, not one that forgot its token");
        Challenge(response).Should().Contain("error=\"invalid_request\"");
    }

    [Fact]
    public async Task A_bearer_header_with_nothing_after_the_scheme_is_invalid_request()
    {
        using var request = new HttpRequestMessage(HttpMethod.Get, UserInfoPath);
        request.Headers.TryAddWithoutValidation("Authorization", "Bearer");

        var response = await _client.SendAsync(request, Cancellation);

        response.StatusCode.Should().Be(HttpStatusCode.BadRequest);
        Challenge(response).Should().Contain("error=\"invalid_request\"");
    }

    [Fact]
    public async Task Two_authorization_headers_are_invalid_request()
    {
        var token = await AccessTokenAsync("openid profile");
        using var request = new HttpRequestMessage(HttpMethod.Get, UserInfoPath);
        request.Headers.TryAddWithoutValidation("Authorization", $"Bearer {token}");
        request.Headers.TryAddWithoutValidation("Authorization", $"Bearer {token}");

        var response = await _client.SendAsync(request, Cancellation);

        response.StatusCode.Should().Be(HttpStatusCode.BadRequest);
        Challenge(response).Should().Contain("error=\"invalid_request\"");
    }

    [Fact]
    public async Task Two_authorization_headers_are_invalid_request_whatever_scheme_they_name()
    {
        using var request = new HttpRequestMessage(HttpMethod.Get, UserInfoPath);
        request.Headers.TryAddWithoutValidation("Authorization", "Basic dXNlcjpwYXNz");
        request.Headers.TryAddWithoutValidation("Authorization", "Basic dXNlcjpwYXNz");

        var response = await _client.SendAsync(request, Cancellation);

        response.StatusCode.Should().Be(HttpStatusCode.BadRequest,
            "RFC 9110 §11.6.2 allows one Authorization header; two is malformed however they read");
        Challenge(response).Should().Contain("error=\"invalid_request\"");
    }

    [Fact]
    public async Task A_header_naming_another_scheme_gets_the_bare_challenge()
    {
        using var request = new HttpRequestMessage(HttpMethod.Get, UserInfoPath);
        request.Headers.TryAddWithoutValidation("Authorization", "Basic dXNlcjpwYXNz");

        var response = await _client.SendAsync(request, Cancellation);

        response.StatusCode.Should().Be(HttpStatusCode.Unauthorized,
            "the bare challenge is what tells a client which scheme this endpoint wants");
        Challenge(response).Should().NotContain("error=");
    }

    [Fact]
    public async Task A_token_in_the_query_string_is_not_read_at_all()
    {
        var token = await AccessTokenAsync("openid profile");

        var response = await _client.GetAsync(
            QueryHelpers.AddQueryString(UserInfoPath, "access_token", token), Cancellation);

        response.StatusCode.Should().Be(HttpStatusCode.Unauthorized,
            "RFC 6750 §2.3 is deprecated: a credential in a URI reaches logs and referrers");
    }

    // ── Refusals ──────────────────────────────────────────────────────────────────────────────

    [Fact]
    public async Task A_request_with_no_token_is_challenged_without_naming_an_error()
    {
        var response = await _client.GetAsync(UserInfoPath, Cancellation);

        response.StatusCode.Should().Be(HttpStatusCode.Unauthorized);
        var challenge = Challenge(response);
        challenge.Should().StartWith("Bearer");
        challenge.Should().NotContain("error=", "RFC 6750 §3.1: a client that simply forgot the header is told nothing more");
    }

    [Theory]
    [InlineData("not-a-token")]
    [InlineData("a.b.c")]
    public async Task A_token_this_server_did_not_issue_is_invalid_token(string token)
    {
        var response = await GetAsync(token);

        response.StatusCode.Should().Be(HttpStatusCode.Unauthorized);
        Challenge(response).Should().Contain("error=\"invalid_token\"");
    }

    [Fact]
    public async Task The_id_token_issued_alongside_is_not_spendable_here()
    {
        // Refused on two independent counts — its typ is JWT, and its aud is the client rather
        // than this server. AccessTokenValidatorTests isolates each; this proves the refusal
        // reaches the wire for a real token pair.
        var tokens = await ExchangeAsync("openid profile");

        var response = await GetAsync(tokens.GetProperty("id_token").GetString()!);

        response.StatusCode.Should().Be(HttpStatusCode.Unauthorized);
    }

    [Fact]
    public async Task A_token_whose_payload_was_edited_is_refused()
    {
        var token = await AccessTokenAsync("openid profile");
        var segments = token.Split('.');
        var payload = JsonDocument.Parse(Base64UrlTextEncoder.Decode(segments[1])).RootElement;
        var forged = payload.EnumerateObject().ToDictionary(
            property => property.Name,
            property => property.Name == "sub" ? (object?)"mallory" : JsonSerializer.Deserialize<JsonElement>(property.Value.GetRawText()));

        var response = await GetAsync(
            $"{segments[0]}.{Base64UrlTextEncoder.Encode(JsonSerializer.SerializeToUtf8Bytes(forged))}.{segments[2]}");

        response.StatusCode.Should().Be(HttpStatusCode.Unauthorized);
    }

    [Fact]
    public async Task A_subject_the_provider_has_since_disowned_is_invalid_token()
    {
        var token = await AccessTokenAsync("openid profile");
        _provider.Script = _ => new ClaimsResolutionResult.SubjectInvalid();

        var response = await GetAsync(token);

        response.StatusCode.Should().Be(HttpStatusCode.Unauthorized);
        Challenge(response).Should().Contain("error=\"invalid_token\"");
        (await response.Content.ReadAsStringAsync(Cancellation)).Should().BeEmpty(
            "a protected resource reports a refusal in WWW-Authenticate, not in a body");
    }

    [Fact]
    public async Task A_provider_that_throws_answers_500_and_no_claim_value_reaches_the_caller()
    {
        var token = await AccessTokenAsync("openid profile");
        _provider.Script = _ => throw new InvalidOperationException("Could not load chris@example.com");

        var response = await GetAsync(token);

        response.StatusCode.Should().Be(HttpStatusCode.InternalServerError);
        (await response.Content.ReadAsStringAsync(Cancellation)).Should().NotContain("chris@example.com");
    }

    [Fact]
    public async Task A_GET_is_answered_and_a_DELETE_is_405()
    {
        var token = await AccessTokenAsync("openid profile");
        using var request = new HttpRequestMessage(HttpMethod.Delete, UserInfoPath);
        request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", token);

        var response = await _client.SendAsync(request, Cancellation);

        response.StatusCode.Should().Be(HttpStatusCode.MethodNotAllowed);
    }

    [Fact]
    public async Task The_endpoint_is_404_on_a_host_that_is_not_the_issuer()
    {
        var token = await AccessTokenAsync("openid profile");
        using var client = _factory.CreateClient(new() { BaseAddress = new Uri("https://other.example.com"), AllowAutoRedirect = false });
        client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", token);

        var response = await client.GetAsync(UserInfoPath, Cancellation);

        response.StatusCode.Should().Be(HttpStatusCode.NotFound);
    }

    // ── CORS ──────────────────────────────────────────────────────────────────────────────────

    [Fact]
    public async Task The_default_allowlist_answers_every_origin()
    {
        var response = await GetAsync(await AccessTokenAsync("openid profile"));

        response.Headers.GetValues("Access-Control-Allow-Origin").Should().ContainSingle().Which.Should().Be("*");
    }

    [Fact]
    public async Task A_preflight_is_answered_with_the_methods_and_headers_a_browser_needs()
    {
        using var request = new HttpRequestMessage(HttpMethod.Options, UserInfoPath);
        request.Headers.Add("Origin", "https://app.example.com");
        request.Headers.Add("Access-Control-Request-Method", "GET");
        request.Headers.Add("Access-Control-Request-Headers", "authorization");

        var response = await _client.SendAsync(request, Cancellation);

        response.StatusCode.Should().Be(HttpStatusCode.NoContent);
        response.Headers.GetValues("Access-Control-Allow-Methods").Should().ContainSingle()
            .Which.Should().Contain("GET").And.Contain("POST");
        response.Headers.GetValues("Access-Control-Allow-Headers").Should().ContainSingle()
            .Which.Should().Contain("Authorization", Exactly.Once());
    }

    [Fact]
    public async Task A_preflight_carries_no_allow_credentials_so_the_wildcard_stays_safe()
    {
        using var request = new HttpRequestMessage(HttpMethod.Options, UserInfoPath);
        request.Headers.Add("Origin", "https://app.example.com");

        var response = await _client.SendAsync(request, Cancellation);

        response.Headers.Contains("Access-Control-Allow-Credentials").Should().BeFalse(
            "no endpoint here authenticates with a cookie, and the wildcard is only safe without it");
    }

    [Fact]
    public async Task A_cross_origin_caller_may_read_the_challenge()
    {
        // WWW-Authenticate is not CORS-safelisted, so without this a browser script sees a bare
        // 401 and the deliberate split between invalid_token and insufficient_scope buys nothing.
        var response = await _client.GetAsync(UserInfoPath, Cancellation);

        response.Headers.GetValues("Access-Control-Expose-Headers").Should().ContainSingle()
            .Which.Should().Contain("WWW-Authenticate");
    }

    [Fact]
    public async Task The_claims_response_carries_no_allow_credentials()
    {
        var response = await GetAsync(await AccessTokenAsync("openid profile"));

        response.Headers.Contains("Access-Control-Allow-Credentials").Should().BeFalse(
            "the wildcard origin is only safe while no response enables a credentialed request");
    }

    [Fact]
    public async Task A_scope_whose_audience_turned_ambiguous_still_answers_userinfo()
    {
        // Userinfo's response has no audience, so a scope set that names two resource servers is
        // no bearing on it and must not turn a valid call into a server error.
        var token = await AccessTokenAsync("openid orders.read");
        _scopes.Scopes =
        [
            .. StandardScopes.All,
            new ScopeDefinition { Name = "orders.read", Audience = "https://elsewhere.example.com/", UserInfoClaims = ["customer_number"] },
        ];

        var claims = await GetUserInfoAsync(token);

        claims.GetProperty("customer_number").GetString().Should().Be("CUST-00042");
    }

    [Fact]
    public async Task The_provider_is_asked_only_for_the_claim_types_userinfo_will_keep()
    {
        var token = await AccessTokenAsync("openid orders.read");
        _provider.Reset();

        await GetUserInfoAsync(token);

        var context = _provider.Calls.Should().ContainSingle().Subject;
        context.ClaimTypes.Should().Contain("customer_number");
        context.ClaimTypes.Should().NotContain("role",
            "role is an access-token claim of that scope; fetching it here is I/O on personal data nothing uses");
    }

    [Fact]
    public async Task An_explicit_allowlist_answers_a_listed_origin_with_its_own_entry()
    {
        using var factory = new TestWebAppFactory(
            configureOptions: opts => opts.CorsOrigins.Add("https://app.example.com"),
            configureBuilder: builder => builder.Services.AddSingleton<IClaimsProvider>(_provider));
        using var client = factory.CreateClient(new() { BaseAddress = new Uri(Issuer) });
        client.DefaultRequestHeaders.Add("Origin", "https://app.example.com");

        var response = await client.GetAsync(UserInfoPath, Cancellation);

        response.Headers.GetValues("Access-Control-Allow-Origin").Should().ContainSingle()
            .Which.Should().Be("https://app.example.com");
    }

    [Fact]
    public async Task An_unlisted_origin_gets_no_allow_origin_header()
    {
        using var factory = new TestWebAppFactory(
            configureOptions: opts => opts.CorsOrigins.Add("https://app.example.com"),
            configureBuilder: builder => builder.Services.AddSingleton<IClaimsProvider>(_provider));
        using var client = factory.CreateClient(new() { BaseAddress = new Uri(Issuer) });
        client.DefaultRequestHeaders.Add("Origin", "https://evil.example.com");

        var response = await client.GetAsync(UserInfoPath, Cancellation);

        response.Headers.Contains("Access-Control-Allow-Origin").Should().BeFalse();
    }

    // ── Discovery and mapping ─────────────────────────────────────────────────────────────────

    [Fact]
    public async Task Discovery_publishes_the_endpoint_this_host_actually_serves()
    {
        var document = await _client.GetFromJsonAsync<JsonElement>(
            "/.well-known/openid-configuration", Cancellation);

        document.GetProperty("userinfo_endpoint").GetString().Should().Be(Issuer + UserInfoPath);
    }

    [Fact]
    public async Task A_host_serving_no_code_grant_publishes_no_userinfo_endpoint_and_serves_none()
    {
        using var factory = new TestWebAppFactory(
            configureOptions: opts =>
            {
                // client_credentials needs a non-"none" method advertised; "none" stays for the
                // default public test client the factory registers.
                opts.GrantTypesSupported = [GrantType.ClientCredentials];
            },
            configureBuilder: builder => builder.Services.AddSingleton<IClaimsProvider>(_provider));
        using var client = factory.CreateClient(new() { BaseAddress = new Uri(Issuer) });

        var document = await client.GetFromJsonAsync<JsonElement>("/.well-known/openid-configuration", Cancellation);
        var response = await client.GetAsync(UserInfoPath, Cancellation);

        document.TryGetProperty("userinfo_endpoint", out _).Should().BeFalse(
            "no grant here issues an access token for an end user");
        response.StatusCode.Should().Be(HttpStatusCode.NotFound, "the metadata and the route must never disagree");
    }

    [Fact]
    public async Task A_path_bearing_issuer_serves_userinfo_under_its_path()
    {
        using var factory = new TestWebAppFactory(
            configureOptions: opts => opts.Issuer = Issuer + "/tenant1",
            configureBuilder: builder => builder.Services.AddSingleton<IClaimsProvider>(_provider));
        using var client = factory.CreateClient(new() { BaseAddress = new Uri(Issuer) });

        var response = await client.GetAsync("/tenant1" + UserInfoPath, Cancellation);

        response.StatusCode.Should().Be(HttpStatusCode.Unauthorized, "the route exists; it just got no token");
    }

    // ── Driving the flow ──────────────────────────────────────────────────────────────────────

    private static void MapLoginPage(IEndpointRouteBuilder endpoints) =>
        endpoints.MapPost(LoginPath, async (HttpContext context, ILoginInteraction login) =>
            await login.SignInAsync(
                new ClaimsPrincipal(new ClaimsIdentity([new Claim("sub", Subject)], "test")),
                AuthenticationMethods.Password));

    private async Task<string> AccessTokenAsync(string scope) =>
        (await ExchangeAsync(scope)).GetProperty("access_token").GetString()!;

    private async Task<JsonElement> ExchangeAsync(string scope)
    {
        var url = QueryHelpers.AddQueryString("/connect/authorize", new Dictionary<string, string?>
        {
            ["client_id"] = App,
            ["redirect_uri"] = Redirect,
            ["response_type"] = "code",
            ["scope"] = scope,
            ["nonce"] = "n-0S6_WzA2Mj",
            ["code_challenge"] = CodeChallenge,
            ["code_challenge_method"] = "S256",
        });

        var response = await _client.GetAsync(url, Cancellation);
        response.StatusCode.Should().Be(HttpStatusCode.Redirect);

        if (response.Headers.Location!.OriginalString.StartsWith(LoginPath, StringComparison.Ordinal))
        {
            var location = response.Headers.Location!.OriginalString;
            var interactionId = QueryHelpers.ParseQuery(location[location.IndexOf('?')..])[InteractionHandoff.InteractionIdParameter].ToString();
            using var login = new FormUrlEncodedContent([]);
            response = await _client.PostAsync(
                QueryHelpers.AddQueryString(LoginPath, InteractionHandoff.InteractionIdParameter, interactionId), login, Cancellation);
        }

        var code = response.ShouldHaveIssuedCodeTo(Redirect);

        using var form = new FormUrlEncodedContent(new Dictionary<string, string>
        {
            ["grant_type"] = "authorization_code",
            ["code"] = code,
            ["redirect_uri"] = Redirect,
            ["client_id"] = App,
            ["code_verifier"] = Verifier,
        });

        var tokens = await _client.PostAsync(TokenPath, form, Cancellation);
        tokens.StatusCode.Should().Be(HttpStatusCode.OK, await tokens.Content.ReadAsStringAsync(Cancellation));

        return JsonDocument.Parse(await tokens.Content.ReadAsStringAsync(Cancellation)).RootElement.Clone();
    }

    private Task<HttpResponseMessage> GetAsync(string accessToken)
    {
        var request = new HttpRequestMessage(HttpMethod.Get, UserInfoPath);
        request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", accessToken);
        return _client.SendAsync(request, Cancellation);
    }

    private async Task<JsonElement> GetUserInfoAsync(string accessToken)
    {
        var response = await GetAsync(accessToken);
        response.StatusCode.Should().Be(HttpStatusCode.OK, await response.Content.ReadAsStringAsync(Cancellation));
        return await ClaimsOf(response);
    }

    private static async Task<JsonElement> ClaimsOf(HttpResponseMessage response) =>
        JsonDocument.Parse(await response.Content.ReadAsStringAsync(Cancellation)).RootElement.Clone();

    private static string Challenge(HttpResponseMessage response) =>
        response.Headers.WwwAuthenticate.Should().ContainSingle().Subject.ToString();

    private static ClaimsResolutionResult Resolved(IReadOnlyList<ClaimRecord> claims) =>
        new ClaimsResolutionResult.Resolved { Claims = claims };

    /// <summary>A scope repository whose definitions a test can change between requests.</summary>
    private sealed class MutableScopeRepository(IReadOnlyCollection<ScopeDefinition> scopes) : IScopeRepository
    {
        public IReadOnlyCollection<ScopeDefinition> Scopes { get; set; } = scopes;

        public ValueTask<IReadOnlyCollection<ScopeDefinition>> GetScopesAsync(CancellationToken cancellationToken = default) =>
            ValueTask.FromResult(Scopes);
    }

    /// <summary>Answers from <see cref="Script"/> when set, otherwise the default pool; records every context it is handed.</summary>
    private sealed class ScriptedClaimsProvider : IClaimsProvider
    {
        private readonly List<ClaimsProviderContext> _calls = [];

        public Func<ClaimsProviderContext, ClaimsResolutionResult>? Script { get; set; }

        public IReadOnlyList<ClaimsProviderContext> Calls
        {
            get { lock (_calls) return [.. _calls]; }
        }

        public void Reset()
        {
            lock (_calls) _calls.Clear();
        }

        public ValueTask<ClaimsResolutionResult> GetClaimsAsync(ClaimsProviderContext context, CancellationToken cancellationToken = default)
        {
            lock (_calls) _calls.Add(context);

            return ValueTask.FromResult(Script is { } script ? script(context) : Resolved(DefaultPool));
        }
    }
}
