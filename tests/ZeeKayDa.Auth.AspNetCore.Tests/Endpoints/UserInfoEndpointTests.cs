using System.Net;
using System.Text.Json;
using Microsoft.AspNetCore.WebUtilities;
using Microsoft.Extensions.DependencyInjection;
using ZeeKayDa.Auth.AspNetCore.Endpoints;
using ZeeKayDa.Auth.Claims;
using ZeeKayDa.Auth.Clients;
using ZeeKayDa.Auth.Scopes;
using ZeeKayDa.Auth.Tokens;

namespace ZeeKayDa.Auth.AspNetCore.Tests.Endpoints;

/// <summary>
/// The userinfo endpoint handler's own behaviour: what it answers a live access token with, how it
/// reads a bearer credential, and the refusals it writes itself — no token, a token this server did
/// not issue, one without <c>openid</c>, a subject the provider has since disowned. Where the route
/// is registered, what a real flow's tokens do here, and method or host dispatch all live in
/// <see cref="UserInfoEndpointHostTests"/>, because none of them is the handler's own behaviour.
/// </summary>
public sealed class UserInfoEndpointTests : IDisposable
{
    private const string UserInfoPath = "/connect/userinfo";
    private const string Issuer = "https://test.example.com";
    private const string Redirect = "https://test.example.com/callback";
    private const string App = "app";
    private const string Subject = "user-1";
    private const string OrdersAudience = "https://orders.example.com/";

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
    private readonly EndpointHost _host;

    public UserInfoEndpointTests()
    {
        _host = new EndpointHost(
            configureBuilder: builder =>
            {
                builder.Services.AddSingleton<IScopeRepository>(_scopes);
                builder.Services.AddSingleton<IClaimsProvider>(_provider);
                builder.AddInMemoryClients(clients => clients
                    .Add(ClientRegistration.CreatePublic(App, [Redirect], [], ["openid", "profile", "email", "orders.read"]) with { RequireConsent = false }));
            });
    }

    public void Dispose() => _host.Dispose();

    private static CancellationToken Cancellation => TestContext.Current.CancellationToken;

    // ── The claims it answers ─────────────────────────────────────────────────────────────────

    [Fact]
    public async Task A_bearer_token_is_answered_with_sub_and_the_claims_its_scopes_unlock()
    {
        var claims = await GetUserInfoAsync(await MintAccessTokenAsync("openid profile"));

        claims.GetProperty("sub").GetString().Should().Be(Subject);
        claims.GetProperty("name").GetString().Should().Be("Chris Example");
        claims.TryGetProperty("email", out _).Should().BeFalse("the email scope was not granted");
    }

    [Fact]
    public async Task The_email_scope_unlocks_email_and_a_boolean_email_verified()
    {
        var claims = await GetUserInfoAsync(await MintAccessTokenAsync("openid email"));

        claims.GetProperty("email").GetString().Should().Be("chris@example.com");
        claims.GetProperty("email_verified").ValueKind.Should().Be(JsonValueKind.True, "a boolean on the wire, not the string \"true\"");
    }

    [Fact]
    public async Task A_userinfo_only_claim_reaches_userinfo_and_no_token()
    {
        var claims = await GetUserInfoAsync(await MintAccessTokenAsync("openid orders.read"));

        claims.GetProperty("customer_number").GetString().Should().Be("CUST-00042");
        claims.TryGetProperty("role", out _).Should().BeFalse("role is an access-token claim of that scope, not a userinfo one");
    }

    [Fact]
    public async Task A_claim_the_provider_does_not_return_is_absent_rather_than_null()
    {
        _provider.Script = _ => Resolved([new("name", "Chris Example")]);

        var claims = await GetUserInfoAsync(await MintAccessTokenAsync("openid profile email"));

        claims.TryGetProperty("email", out _).Should().BeFalse("OpenID Connect Core §5.3.2: an unavailable claim is omitted, never null");
    }

    [Fact]
    public async Task A_provider_cannot_override_sub()
    {
        _provider.Script = _ => Resolved([new("name", "Chris Example"), new("sub", "mallory")]);

        var claims = await GetUserInfoAsync(await MintAccessTokenAsync("openid profile"));

        claims.GetProperty("sub").GetString().Should().Be(Subject);
    }

    [Fact]
    public async Task The_claims_are_resolved_fresh_with_no_family_id()
    {
        var token = await MintAccessTokenAsync("openid profile");
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
        var token = await MintAccessTokenAsync("openid profile");
        _provider.Reset();

        await GetUserInfoAsync(token);
        await GetUserInfoAsync(token);

        _provider.Calls.Should().HaveCount(2, "nothing is cached here; a changed subject must show up at the next call");
    }

    [Fact]
    public async Task The_response_is_json_and_never_cached()
    {
        using var response = await GetAsync(await MintAccessTokenAsync("openid profile"));

        response.Content.Headers.ContentType!.MediaType.Should().Be("application/json");
        response.Headers.CacheControl!.NoStore.Should().BeTrue("the claims are personal data read with a credential");
    }

    // ── How the token may be presented ────────────────────────────────────────────────────────

    [Fact]
    public async Task The_token_may_be_presented_in_a_form_post()
    {
        var token = await MintAccessTokenAsync("openid profile");
        var request = _host.Post(UserInfoPath).WithForm(new Dictionary<string, string> { ["access_token"] = token });

        using var response = await _host.InvokeAsync<UserInfoEndpoint>(e => e.HandleAsync, request);

        response.StatusCode.Should().Be(HttpStatusCode.OK, "RFC 6750 §2.2 allows the form-encoded body parameter");
        (await ClaimsOf(response)).GetProperty("sub").GetString().Should().Be(Subject);
    }

    [Fact]
    public async Task Presenting_the_token_twice_over_is_invalid_request()
    {
        var token = await MintAccessTokenAsync("openid profile");
        var request = _host.Post(UserInfoPath)
            .WithForm(new Dictionary<string, string> { ["access_token"] = token })
            .WithHeader("Authorization", $"Bearer {token}");

        using var response = await _host.InvokeAsync<UserInfoEndpoint>(e => e.HandleAsync, request);

        response.StatusCode.Should().Be(HttpStatusCode.BadRequest);
        Challenge(response).Should().Contain("error=\"invalid_request\"");
    }

    [Fact]
    public async Task A_repeated_access_token_field_alongside_a_valid_header_is_invalid_request()
    {
        // The repeated field must not read as no field at all: that would let a request present
        // its token twice and be answered from the header as though it had presented it once.
        var token = await MintAccessTokenAsync("openid profile");
        var request = _host.Post(UserInfoPath)
            .WithBody($"access_token={Uri.EscapeDataString(token)}&access_token=second", "application/x-www-form-urlencoded")
            .WithHeader("Authorization", $"Bearer {token}");

        using var response = await _host.InvokeAsync<UserInfoEndpoint>(e => e.HandleAsync, request);

        response.StatusCode.Should().Be(HttpStatusCode.BadRequest);
        Challenge(response).Should().Contain("error=\"invalid_request\"");
    }

    [Fact]
    public async Task A_repeated_access_token_field_on_its_own_is_invalid_request_not_a_bare_challenge()
    {
        var token = await MintAccessTokenAsync("openid profile");
        var request = _host.Post(UserInfoPath)
            .WithBody($"access_token={Uri.EscapeDataString(token)}&access_token=second", "application/x-www-form-urlencoded");

        using var response = await _host.InvokeAsync<UserInfoEndpoint>(e => e.HandleAsync, request);

        response.StatusCode.Should().Be(HttpStatusCode.BadRequest,
            "RFC 6750 §3.1: a request repeating a parameter is malformed, not one that forgot its token");
        Challenge(response).Should().Contain("error=\"invalid_request\"");
    }

    [Fact]
    public async Task A_bearer_header_with_nothing_after_the_scheme_is_invalid_request()
    {
        var request = _host.Get(UserInfoPath).WithHeader("Authorization", "Bearer");

        using var response = await _host.InvokeAsync<UserInfoEndpoint>(e => e.HandleAsync, request);

        response.StatusCode.Should().Be(HttpStatusCode.BadRequest);
        Challenge(response).Should().Contain("error=\"invalid_request\"");
    }

    [Fact]
    public async Task A_header_naming_another_scheme_gets_the_bare_challenge()
    {
        var request = _host.Get(UserInfoPath).WithHeader("Authorization", "Basic dXNlcjpwYXNz");

        using var response = await _host.InvokeAsync<UserInfoEndpoint>(e => e.HandleAsync, request);

        response.StatusCode.Should().Be(HttpStatusCode.Unauthorized,
            "the bare challenge is what tells a client which scheme this endpoint wants");
        Challenge(response).Should().NotContain("error=");
    }

    [Fact]
    public async Task A_token_in_the_query_string_is_not_read_at_all()
    {
        var token = await MintAccessTokenAsync("openid profile");
        var request = _host.Get(QueryHelpers.AddQueryString(UserInfoPath, "access_token", token));

        using var response = await _host.InvokeAsync<UserInfoEndpoint>(e => e.HandleAsync, request);

        response.StatusCode.Should().Be(HttpStatusCode.Unauthorized,
            "RFC 6750 §2.3 is deprecated: a credential in a URI reaches logs and referrers");
    }

    // ── Refusals ──────────────────────────────────────────────────────────────────────────────

    [Fact]
    public async Task A_request_with_no_token_is_challenged_without_naming_an_error()
    {
        using var response = await _host.InvokeAsync<UserInfoEndpoint>(e => e.HandleAsync, _host.Get(UserInfoPath));

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
        using var response = await GetAsync(token);

        response.StatusCode.Should().Be(HttpStatusCode.Unauthorized);
        Challenge(response).Should().Contain("error=\"invalid_token\"");
    }

    [Fact]
    public async Task A_token_whose_payload_was_edited_is_refused()
    {
        var token = await MintAccessTokenAsync("openid profile");
        var segments = token.Split('.');
        var payload = JsonDocument.Parse(Base64UrlTextEncoder.Decode(segments[1])).RootElement;
        var forged = payload.EnumerateObject().ToDictionary(
            property => property.Name,
            property => property.Name == "sub" ? (object?)"mallory" : JsonSerializer.Deserialize<JsonElement>(property.Value.GetRawText()));

        using var response = await GetAsync(
            $"{segments[0]}.{Base64UrlTextEncoder.Encode(JsonSerializer.SerializeToUtf8Bytes(forged))}.{segments[2]}");

        response.StatusCode.Should().Be(HttpStatusCode.Unauthorized);
    }

    [Fact]
    public async Task A_token_without_the_openid_scope_is_insufficient_scope()
    {
        var token = await MintAccessTokenAsync(scope: "profile");

        using var response = await GetAsync(token);

        response.StatusCode.Should().Be(HttpStatusCode.Forbidden,
            "the client can act on this one by asking for the scope, so RFC 6750 §3.1 gives it its own code");
        var challenge = Challenge(response);
        challenge.Should().Contain("error=\"insufficient_scope\"");
        challenge.Should().Contain("scope=\"openid\"", "the challenge must say which scope would satisfy it");
    }

    [Fact]
    public async Task A_token_this_server_signed_for_another_audience_is_invalid_token()
    {
        var token = await MintAccessTokenAsync(scope: "openid", audience: OrdersAudience);

        using var response = await GetAsync(token);

        response.StatusCode.Should().Be(HttpStatusCode.Unauthorized,
            "RFC 9068 §4: a resource server rejects a token that was not addressed to it, however it was signed");
        Challenge(response).Should().Contain("error=\"invalid_token\"");
    }

    [Fact]
    public async Task A_subject_the_provider_has_since_disowned_is_invalid_token()
    {
        var token = await MintAccessTokenAsync("openid profile");
        _provider.Script = _ => new ClaimsResolutionResult.SubjectInvalid();

        using var response = await GetAsync(token);

        response.StatusCode.Should().Be(HttpStatusCode.Unauthorized);
        Challenge(response).Should().Contain("error=\"invalid_token\"");
        (await response.Content.ReadAsStringAsync(Cancellation)).Should().BeEmpty(
            "a protected resource reports a refusal in WWW-Authenticate, not in a body");
    }

    [Fact]
    public async Task A_provider_that_throws_answers_500_and_no_claim_value_reaches_the_caller()
    {
        var token = await MintAccessTokenAsync("openid profile");
        _provider.Script = _ => throw new InvalidOperationException("Could not load chris@example.com");

        using var response = await GetAsync(token);

        response.StatusCode.Should().Be(HttpStatusCode.InternalServerError);
        (await response.Content.ReadAsStringAsync(Cancellation)).Should().NotContain("chris@example.com");
    }

    // ── CORS ──────────────────────────────────────────────────────────────────────────────────

    [Fact]
    public async Task The_default_allowlist_answers_every_origin()
    {
        using var response = await GetAsync(await MintAccessTokenAsync("openid profile"));

        response.Headers.GetValues("Access-Control-Allow-Origin").Should().ContainSingle().Which.Should().Be("*");
    }

    [Fact]
    public async Task A_preflight_is_answered_with_the_methods_and_headers_a_browser_needs()
    {
        var request = _host.Request("OPTIONS", UserInfoPath)
            .WithHeader("Origin", "https://app.example.com")
            .WithHeader("Access-Control-Request-Method", "GET")
            .WithHeader("Access-Control-Request-Headers", "authorization");

        using var response = await _host.InvokeAsync<UserInfoEndpoint>(e => e.HandlePreflight, request);

        response.StatusCode.Should().Be(HttpStatusCode.NoContent);
        response.Headers.GetValues("Access-Control-Allow-Methods").Should().ContainSingle()
            .Which.Should().Contain("GET").And.Contain("POST");
        response.Headers.GetValues("Access-Control-Allow-Headers").Should().ContainSingle()
            .Which.Should().Contain("Authorization", Exactly.Once());
    }

    [Fact]
    public async Task A_preflight_carries_no_allow_credentials_so_the_wildcard_stays_safe()
    {
        var request = _host.Request("OPTIONS", UserInfoPath).WithHeader("Origin", "https://app.example.com");

        using var response = await _host.InvokeAsync<UserInfoEndpoint>(e => e.HandlePreflight, request);

        response.Headers.Contains("Access-Control-Allow-Credentials").Should().BeFalse(
            "no endpoint here authenticates with a cookie, and the wildcard is only safe without it");
    }

    [Fact]
    public async Task A_cross_origin_caller_may_read_the_challenge()
    {
        // WWW-Authenticate is not CORS-safelisted, so without this a browser script sees a bare
        // 401 and the deliberate split between invalid_token and insufficient_scope buys nothing.
        using var response = await _host.InvokeAsync<UserInfoEndpoint>(e => e.HandleAsync, _host.Get(UserInfoPath));

        response.Headers.GetValues("Access-Control-Expose-Headers").Should().ContainSingle()
            .Which.Should().Contain("WWW-Authenticate");
    }

    [Fact]
    public async Task The_claims_response_carries_no_allow_credentials()
    {
        using var response = await GetAsync(await MintAccessTokenAsync("openid profile"));

        response.Headers.Contains("Access-Control-Allow-Credentials").Should().BeFalse(
            "the wildcard origin is only safe while no response enables a credentialed request");
    }

    [Fact]
    public async Task A_scope_whose_audience_turned_ambiguous_still_answers_userinfo()
    {
        // Userinfo's response has no audience, so a scope set that names two resource servers is
        // no bearing on it and must not turn a valid call into a server error.
        var token = await MintAccessTokenAsync("openid orders.read");
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
        var token = await MintAccessTokenAsync("openid orders.read");
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
        using var host = new EndpointHost(
            opts => opts.CorsOrigins.Add("https://app.example.com"),
            configureBuilder: builder => builder.Services.AddSingleton<IClaimsProvider>(_provider));
        var request = host.Get(UserInfoPath).WithHeader("Origin", "https://app.example.com");

        using var response = await host.InvokeAsync<UserInfoEndpoint>(e => e.HandleAsync, request);

        response.Headers.GetValues("Access-Control-Allow-Origin").Should().ContainSingle()
            .Which.Should().Be("https://app.example.com");
    }

    [Fact]
    public async Task An_unlisted_origin_gets_no_allow_origin_header()
    {
        using var host = new EndpointHost(
            opts => opts.CorsOrigins.Add("https://app.example.com"),
            configureBuilder: builder => builder.Services.AddSingleton<IClaimsProvider>(_provider));
        var request = host.Get(UserInfoPath).WithHeader("Origin", "https://evil.example.com");

        using var response = await host.InvokeAsync<UserInfoEndpoint>(e => e.HandleAsync, request);

        response.Headers.Contains("Access-Control-Allow-Origin").Should().BeFalse();
    }

    // ── Driving a request ─────────────────────────────────────────────────────────────────────

    private Task<HttpResponseMessage> GetAsync(string accessToken) =>
        _host.InvokeAsync<UserInfoEndpoint>(e => e.HandleAsync,
            _host.Get(UserInfoPath).WithHeader("Authorization", $"Bearer {accessToken}"));

    private async Task<JsonElement> GetUserInfoAsync(string accessToken)
    {
        using var response = await GetAsync(accessToken);
        response.StatusCode.Should().Be(HttpStatusCode.OK, await response.Content.ReadAsStringAsync(Cancellation));
        return await ClaimsOf(response);
    }

    /// <summary>
    /// An access token signed by this container's own ring, carrying exactly the claims asked
    /// for. The ring builds the header from the key it resolves, so the token is indistinguishable
    /// from one the framework issued.
    /// </summary>
    private async Task<string> MintAccessTokenAsync(string scope, string? audience = null)
    {
        await _host.EnsureStartedAsync();
        var ring = _host.Resolve<ISigningKeyRing>();
        var claims = new Dictionary<string, object?>(StringComparer.Ordinal)
        {
            ["iss"] = Issuer,
            ["sub"] = Subject,
            ["aud"] = audience ?? Issuer,
            ["client_id"] = App,
            ["iat"] = DateTimeOffset.UtcNow.ToUnixTimeSeconds(),
            ["exp"] = DateTimeOffset.UtcNow.AddMinutes(10).ToUnixTimeSeconds(),
            ["jti"] = Guid.NewGuid().ToString("N"),
            ["scope"] = scope,
        };

        var outcome = await ring.SignAsync(claims, static (signing, state) =>
        {
            var header = Base64UrlTextEncoder.Encode(JsonSerializer.SerializeToUtf8Bytes(
                new Dictionary<string, object?>(StringComparer.Ordinal)
                {
                    ["alg"] = "RS256",
                    ["typ"] = "at+jwt",
                    ["kid"] = signing.Key.Kid,
                }));
            var payload = Base64UrlTextEncoder.Encode(JsonSerializer.SerializeToUtf8Bytes(state));
            return System.Text.Encoding.ASCII.GetBytes($"{header}.{payload}");
        }, Cancellation);

        return $"{System.Text.Encoding.ASCII.GetString(outcome.SigningInput.Span)}." +
            Base64UrlTextEncoder.Encode(outcome.Signature.ToArray());
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
