using System.Buffers.Text;
using System.Net;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.AspNetCore.Routing;
using Microsoft.AspNetCore.WebUtilities;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Time.Testing;
using ZeeKayDa.Auth.AspNetCore.Interaction;
using ZeeKayDa.Auth.AspNetCore.Tests.Interaction;
using ZeeKayDa.Auth.Authorization;
using ZeeKayDa.Auth.Clients;
using ZeeKayDa.Auth.Stores;
using ZeeKayDa.Auth.Tokens;

namespace ZeeKayDa.Auth.AspNetCore.Tests.Endpoints;

/// <summary>
/// Integration tests for the token endpoint: a code obtained through the real authorization
/// flow is exchanged over HTTP, and what comes back is verified against the JWKS the same host
/// serves. The security decisions here — PKCE for every client, a burnt code on any binding
/// failure, a replay revoking its family — are recorded by the tests that prove them.
/// </summary>
public sealed class TokenEndpointTests : IDisposable
{
    private const string TokenPath = "/connect/token";
    private const string JwksPath = "/connect/jwks";
    private const string Issuer = "https://test.example.com";
    private const string RegisteredRedirect = "https://test.example.com/callback";
    private const string LoginPath = "/account/login";
    private const string ConsentPath = FlowAssertions.ConsentPath;
    private const string PublicClient = "public-client";
    private const string ConfidentialClient = "confidential-client";
    private const string ConfidentialSecret = "very-secret";
    private const string OtherClient = "other-client";
    private const string NoCodeGrantClient = "no-code-grant-client";
    private const string Nonce = "n-0S6_WzA2Mj";

    // RFC 7636 Appendix B.
    private const string Verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
    private const string Challenge = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM";
    private const string WrongVerifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXl";

    private static readonly DateTimeOffset Now = new(2026, 9, 13, 12, 0, 0, TimeSpan.Zero);

    private readonly FakeTimeProvider _time = new(Now);
    private readonly CapturingLoggerProvider _logs = new();
    private readonly RecordingRefreshTokenStore _refreshTokens = new();
    private readonly SwitchableBackingStore _backingStore = new();
    private readonly TestWebAppFactory _factory;
    private readonly HttpClient _client;

    public TokenEndpointTests()
    {
        _factory = NewFactory();
        _client = NewClient(_factory);
    }

    public void Dispose()
    {
        _client.Dispose();
        _factory.Dispose();
    }

    private static CancellationToken Cancellation => TestContext.Current.CancellationToken;

    private TestWebAppFactory NewFactory(Action<AuthorizationServerOptions>? configureOptions = null) => new(
        configureOptions: options =>
        {
            options.AuthorizationEndpoint.AuthorizationCodeLifetime = TimeSpan.FromSeconds(60);
            configureOptions?.Invoke(options);
        },
        configureBuilder: builder =>
        {
            builder.Services.AddSingleton<TimeProvider>(_time);
            builder.Services.AddLogging(logging => logging.AddProvider(_logs));
            builder.AddInMemoryClients(clients => clients
                .Add(PublicRegistration())
                .Add(NoCodeGrantRegistration())
                .AddConfidential(ConfidentialClient, ConfidentialSecret, [RegisteredRedirect], [], ["openid", "profile"])
                .AddPublic(OtherClient, ["https://other.example.com/callback"], [], ["openid"]));

            // The interaction and code stores are the framework's; the refresh-token store is
            // a recorder, so a replay's family revocation is observable.
            builder.AddInMemoryInteractionStore(allowOutsideDevelopment: true);
            builder.AddAuthorizationCodeStore<SwitchableBackingStore>();
            builder.Services.AddSingleton<IAuthorizationCodeBackingStore>(_backingStore);
            builder.Services.AddSingleton<IRefreshTokenStore>(_refreshTokens);
        },
        mapEndpoints: MapHostPages);

    /// <summary>A first-party public client: no consent, so sign-in ends the flow with a code.</summary>
    private static ClientRegistration PublicRegistration() =>
        ClientRegistration.CreatePublic(PublicClient, [RegisteredRedirect], [], ["openid", "profile", "email"])
            with
        { RequireConsent = false };

    private static ClientRegistration NoCodeGrantRegistration() =>
        ClientRegistration.CreatePublic(NoCodeGrantClient, [RegisteredRedirect], [], ["openid"])
            with
        { AllowedGrantTypes = new HashSet<GrantType> { GrantType.RefreshToken } };

    private static HttpClient NewClient(WebApplicationFactory<TestWebAppFactory> factory) => factory.CreateClient(new()
    {
        BaseAddress = new Uri(Issuer),
        AllowAutoRedirect = false,
        HandleCookies = true,
    });

    private static void MapHostPages(IEndpointRouteBuilder endpoints)
    {
        endpoints.MapPost(LoginPath, async (HttpContext context, ILoginInteraction login) =>
        {
            var form = await context.Request.ReadFormAsync(context.RequestAborted);
            var subject = form["sub"].FirstOrDefault() ?? "user-1";

            await login.SignInAsync(
                new ClaimsPrincipal(new ClaimsIdentity([new Claim("sub", subject)], "test")),
                AuthenticationMethods.Password);
        });

        endpoints.MapPost(ConsentPath, async (HttpContext context, IConsentInteraction consent) =>
        {
            var form = await context.Request.ReadFormAsync(context.RequestAborted);
            await consent.GrantAsync(form["scope"].Select(scope => scope ?? string.Empty));
        });
    }

    // ── Driving the authorization flow to a code ──────────────────────────────────────────────

    private static Dictionary<string, string?> AuthorizeQuery(string clientId = PublicClient, string scope = "openid profile") => new()
    {
        ["client_id"] = clientId,
        ["redirect_uri"] = RegisteredRedirect,
        ["response_type"] = "code",
        ["scope"] = scope,
        ["nonce"] = Nonce,
        ["code_challenge"] = Challenge,
        ["code_challenge_method"] = "S256",
    };

    private static string InteractionIdFrom(HttpResponseMessage response)
    {
        var location = response.Headers.Location!.OriginalString;
        return QueryHelpers.ParseQuery(location[location.IndexOf('?')..])[InteractionHandoff.InteractionIdParameter]!;
    }

    private static FormUrlEncodedContent Form(params (string Key, string Value)[] fields) =>
        new(fields.Select(field => KeyValuePair.Create(field.Key, field.Value)));

    /// <summary>
    /// Authorize and follow the flow to a code: sign in when the host asks, consent when the
    /// client asks. A browser that already holds an SSO session is handed the code straight away.
    /// </summary>
    private Task<string> ObtainCodeAsync(string clientId = PublicClient, string scope = "openid profile") =>
        ObtainCodeWithAsync(_client, clientId, scope);

    private static async Task<string> ObtainCodeWithAsync(HttpClient client, string clientId = PublicClient, string scope = "openid profile")
    {
        var response = await client.GetAsync(QueryHelpers.AddQueryString("/connect/authorize", AuthorizeQuery(clientId, scope)), Cancellation);
        response.StatusCode.Should().Be(HttpStatusCode.Redirect);

        if (IsHandoffTo(response, LoginPath))
        {
            using var login = Form(("sub", "user-1"));
            response = await client.PostAsync(
                QueryHelpers.AddQueryString(LoginPath, InteractionHandoff.InteractionIdParameter, InteractionIdFrom(response)),
                login,
                Cancellation);
        }

        if (IsHandoffTo(response, ConsentPath))
        {
            using var grant = Form([.. scope.Split(' ').Select(s => ("scope", s))]);
            response = await client.PostAsync(
                QueryHelpers.AddQueryString(ConsentPath, InteractionHandoff.InteractionIdParameter, InteractionIdFrom(response)),
                grant,
                Cancellation);
        }

        return response.ShouldHaveIssuedCodeTo(RegisteredRedirect);
    }

    private static bool IsHandoffTo(HttpResponseMessage response, string path) =>
        response.Headers.Location!.OriginalString.StartsWith(path, StringComparison.Ordinal);

    // ── The token request ─────────────────────────────────────────────────────────────────────

    private static Dictionary<string, string> TokenForm(string code, string clientId = PublicClient, string verifier = Verifier) => new(StringComparer.Ordinal)
    {
        ["grant_type"] = "authorization_code",
        ["code"] = code,
        ["redirect_uri"] = RegisteredRedirect,
        ["client_id"] = clientId,
        ["code_verifier"] = verifier,
    };

    private Task<HttpResponseMessage> PostTokenAsync(Dictionary<string, string> form, (string Id, string Secret)? basic = null) =>
        PostTokenAsync(form.Select(field => KeyValuePair.Create(field.Key, field.Value)), basic);

    private async Task<HttpResponseMessage> PostTokenAsync(IEnumerable<KeyValuePair<string, string>> fields, (string Id, string Secret)? basic = null)
    {
        using var request = new HttpRequestMessage(HttpMethod.Post, TokenPath)
        {
            Content = new FormUrlEncodedContent(fields),
        };

        if (basic is { } credentials)
        {
            request.Headers.Authorization = new AuthenticationHeaderValue(
                "Basic",
                Convert.ToBase64String(Encoding.UTF8.GetBytes($"{credentials.Id}:{credentials.Secret}")));
        }

        return await _client.SendAsync(request, Cancellation);
    }

    private static async Task<JsonElement> ReadJsonAsync(HttpResponseMessage response)
    {
        var body = await response.Content.ReadAsStringAsync(Cancellation);
        return JsonDocument.Parse(body).RootElement.Clone();
    }

    private static async Task ShouldBeErrorAsync(HttpResponseMessage response, string error, HttpStatusCode status = HttpStatusCode.BadRequest)
    {
        response.StatusCode.Should().Be(status);
        response.Content.Headers.ContentType!.MediaType.Should().Be("application/json");
        var body = await ReadJsonAsync(response);
        body.GetProperty("error").GetString().Should().Be(error);
        body.GetProperty("error_description").GetString().Should().NotBeNullOrEmpty();
    }

    // ── Reading the tokens back ───────────────────────────────────────────────────────────────

    private static JsonElement Header(string jwt) => ParseSegment(jwt.Split('.')[0]);

    private static JsonElement Claims(string jwt) => ParseSegment(jwt.Split('.')[1]);

    private static JsonElement ParseSegment(string segment) =>
        JsonDocument.Parse(Base64Url.DecodeFromChars(segment)).RootElement.Clone();

    /// <summary>The signature verifies with the JWKS key the header's <c>kid</c> names, as any relying party checks it.</summary>
    private async Task ShouldVerifyAgainstServedJwksAsync(string jwt)
    {
        var parts = jwt.Split('.');
        parts.Should().HaveCount(3, "a compact JWS has three segments");
        var kid = Header(jwt).GetProperty("kid").GetString();

        var jwks = await _client.GetFromJsonAsync<JsonDocument>(JwksPath, Cancellation);
        var jwk = jwks!.RootElement.GetProperty("keys").EnumerateArray()
            .Single(key => key.GetProperty("kid").GetString() == kid);

        using var rsa = RSA.Create(new RSAParameters
        {
            Modulus = Base64Url.DecodeFromChars(jwk.GetProperty("n").GetString()),
            Exponent = Base64Url.DecodeFromChars(jwk.GetProperty("e").GetString()),
        });
        rsa.VerifyData(
                Encoding.ASCII.GetBytes($"{parts[0]}.{parts[1]}"),
                Base64Url.DecodeFromChars(parts[2]),
                HashAlgorithmName.SHA256,
                RSASignaturePadding.Pkcs1)
            .Should().BeTrue("the token was signed by the key the JWKS publishes under that kid");
    }

    /// <summary>
    /// No code, verifier, or issued token reaches a log sink. Hosting's own request logging is
    /// excluded: it is the host's, not the framework's.
    /// </summary>
    private void LogsShouldCarryNoProtocolMaterial(params string?[] material)
    {
        var secrets = material.Where(value => !string.IsNullOrEmpty(value)).ToArray();

        _logs.Entries
            .Where(entry => !entry.Category.StartsWith("Microsoft.AspNetCore.Hosting", StringComparison.Ordinal))
            .Should().NotContain(
                entry => secrets.Any(value => entry.Message.Contains(value!, StringComparison.Ordinal)),
                "codes, verifiers and tokens never reach a log sink");
    }

    // ── The success path ──────────────────────────────────────────────────────────────────────

    [Fact]
    public async Task A_valid_exchange_answers_with_an_access_token_and_an_ID_token()
    {
        var code = await ObtainCodeAsync();

        var response = await PostTokenAsync(TokenForm(code));

        response.StatusCode.Should().Be(HttpStatusCode.OK);
        response.Content.Headers.ContentType!.MediaType.Should().Be("application/json");
        var body = await ReadJsonAsync(response);
        body.GetProperty("token_type").GetString().Should().Be("Bearer");
        body.GetProperty("expires_in").GetInt64().Should().Be(3600, "the server default is one hour");
        body.GetProperty("scope").GetString().Should().Be("openid profile");
        body.GetProperty("access_token").GetString().Should().MatchRegex(@"^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$");
        body.GetProperty("id_token").GetString().Should().MatchRegex(@"^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$");
        LogsShouldCarryNoProtocolMaterial(code, Verifier, body.GetProperty("access_token").GetString(), body.GetProperty("id_token").GetString());
    }

    [Fact]
    public async Task A_token_response_is_never_cacheable()
    {
        var code = await ObtainCodeAsync();

        var response = await PostTokenAsync(TokenForm(code));

        response.Headers.CacheControl!.NoStore.Should().BeTrue("RFC 6749 §5.1");
        response.Headers.Pragma.Should().Contain(directive => directive.Name == "no-cache");
    }

    [Fact]
    public async Task The_access_token_is_a_JWT_carrying_the_grant_and_verifiable_against_the_served_JWKS()
    {
        var code = await ObtainCodeAsync();

        var body = await ReadJsonAsync(await PostTokenAsync(TokenForm(code)));

        var accessToken = body.GetProperty("access_token").GetString()!;
        var header = Header(accessToken);
        header.GetProperty("typ").GetString().Should().Be("at+jwt", "RFC 9068 §2.1");
        header.GetProperty("alg").GetString().Should().Be("RS256");
        var claims = Claims(accessToken);
        claims.GetProperty("iss").GetString().Should().Be(Issuer);
        claims.GetProperty("sub").GetString().Should().Be("user-1");
        claims.GetProperty("aud").GetString().Should().Be(Issuer, "the issuer hosts userinfo, the one resource openid grants access to");
        claims.GetProperty("client_id").GetString().Should().Be(PublicClient);
        claims.GetProperty("scope").GetString().Should().Be("openid profile");
        claims.GetProperty("iat").GetInt64().Should().Be(Now.ToUnixTimeSeconds());
        claims.GetProperty("exp").GetInt64().Should().Be(Now.AddHours(1).ToUnixTimeSeconds());
        claims.GetProperty("auth_time").GetInt64().Should().Be(Now.ToUnixTimeSeconds());
        claims.GetProperty("jti").GetString().Should().MatchRegex("^[A-Za-z0-9_-]{43}$", "a 256-bit CSPRNG value, fresh per token");
        claims.GetProperty("amr").EnumerateArray().Select(e => e.GetString()).Should().Equal(AuthenticationMethods.Password);
        await ShouldVerifyAgainstServedJwksAsync(accessToken);
    }

    [Fact]
    public async Task The_ID_token_is_a_JWT_carrying_the_request_binding_and_verifiable_against_the_served_JWKS()
    {
        var code = await ObtainCodeAsync();

        var body = await ReadJsonAsync(await PostTokenAsync(TokenForm(code)));

        var idToken = body.GetProperty("id_token").GetString()!;
        Header(idToken).GetProperty("typ").GetString().Should().Be("JWT");
        var claims = Claims(idToken);
        claims.GetProperty("iss").GetString().Should().Be(Issuer);
        claims.GetProperty("sub").GetString().Should().Be("user-1");
        claims.GetProperty("aud").GetString().Should().Be(PublicClient, "the requesting client is the one audience");
        claims.GetProperty("nonce").GetString().Should().Be(Nonce, "the nonce binds the token to the request that asked for it");
        claims.GetProperty("iat").GetInt64().Should().Be(Now.ToUnixTimeSeconds());
        claims.GetProperty("exp").GetInt64().Should().Be(Now.AddMinutes(5).ToUnixTimeSeconds(), "the server default is five minutes");
        claims.GetProperty("auth_time").GetInt64().Should().Be(Now.ToUnixTimeSeconds());
        claims.TryGetProperty("scope", out _).Should().BeFalse();
        claims.TryGetProperty("client_id", out _).Should().BeFalse();
        await ShouldVerifyAgainstServedJwksAsync(idToken);
    }

    [Fact]
    public async Task Two_exchanges_mint_distinct_jti_values()
    {
        var first = Claims((await ReadJsonAsync(await PostTokenAsync(TokenForm(await ObtainCodeAsync())))).GetProperty("access_token").GetString()!);
        var second = Claims((await ReadJsonAsync(await PostTokenAsync(TokenForm(await ObtainCodeAsync())))).GetProperty("access_token").GetString()!);

        first.GetProperty("jti").GetString().Should().NotBe(second.GetProperty("jti").GetString());
    }

    [Fact]
    public async Task A_confidential_client_authenticates_with_client_secret_basic()
    {
        var code = await ObtainCodeAsync(ConfidentialClient);
        var form = TokenForm(code, ConfidentialClient);
        form.Remove("client_id");

        var response = await PostTokenAsync(form, basic: (ConfidentialClient, ConfidentialSecret));

        response.StatusCode.Should().Be(HttpStatusCode.OK);
        var body = await ReadJsonAsync(response);
        Claims(body.GetProperty("id_token").GetString()!).GetProperty("aud").GetString().Should().Be(ConfidentialClient);
        Claims(body.GetProperty("access_token").GetString()!).GetProperty("client_id").GetString().Should().Be(ConfidentialClient);
    }

    // ── Lifetimes ─────────────────────────────────────────────────────────────────────────────

    [Fact]
    public async Task Server_wide_lifetimes_set_the_expiry_of_both_tokens()
    {
        using var factory = NewFactory(options =>
        {
            options.TokenEndpoint.AccessTokenLifetime = TimeSpan.FromMinutes(20);
            options.TokenEndpoint.IdTokenLifetime = TimeSpan.FromMinutes(2);
        });
        using var client = NewClient(factory);
        var code = await ObtainCodeWithAsync(client);

        var body = await ReadJsonAsync(await PostTokenWithAsync(client, TokenForm(code)));

        body.GetProperty("expires_in").GetInt64().Should().Be(1200);
        Claims(body.GetProperty("access_token").GetString()!).GetProperty("exp").GetInt64().Should().Be(Now.AddMinutes(20).ToUnixTimeSeconds());
        Claims(body.GetProperty("id_token").GetString()!).GetProperty("exp").GetInt64().Should().Be(Now.AddMinutes(2).ToUnixTimeSeconds());
    }

    [Fact]
    public async Task A_client_override_replaces_the_server_lifetime_for_that_client_only()
    {
        using var factory = new TestWebAppFactory(
            configureBuilder: builder =>
            {
                builder.Services.AddSingleton<TimeProvider>(_time);
                builder.AddInMemoryClients(clients => clients.Add(PublicRegistration() with
                {
                    AccessTokenLifetime = TimeSpan.FromMinutes(10),
                    IdTokenLifetime = TimeSpan.FromMinutes(1),
                }));
            },
            mapEndpoints: MapHostPages);
        using var client = NewClient(factory);
        var code = await ObtainCodeWithAsync(client);

        var body = await ReadJsonAsync(await PostTokenWithAsync(client, TokenForm(code)));

        body.GetProperty("expires_in").GetInt64().Should().Be(600);
        Claims(body.GetProperty("access_token").GetString()!).GetProperty("exp").GetInt64().Should().Be(Now.AddMinutes(10).ToUnixTimeSeconds());
        Claims(body.GetProperty("id_token").GetString()!).GetProperty("exp").GetInt64().Should().Be(Now.AddMinutes(1).ToUnixTimeSeconds());
    }

    [Fact]
    public async Task The_tokens_are_issued_from_the_registration_that_authenticated_never_from_a_second_lookup()
    {
        // A repository whose answer changes between two reads within one request: the first read
        // is the authentication, and what the credential was checked against is what the grant
        // must use — a later read could hand the request lifetimes and grants nobody authenticated.
        var repository = new FirstReadThenOtherRepository(
            first: PublicRegistration() with { AccessTokenLifetime = TimeSpan.FromMinutes(10) },
            other: PublicRegistration() with { AccessTokenLifetime = TimeSpan.FromMinutes(20) });
        using var factory = new TestWebAppFactory(
            configureBuilder: builder =>
            {
                builder.Services.AddSingleton<TimeProvider>(_time);
                builder.Services.AddSingleton<IClientRepository>(repository);
            },
            mapEndpoints: MapHostPages);
        using var client = NewClient(factory);
        var code = await ObtainCodeWithAsync(client);
        repository.ResetToFirst();

        var body = await ReadJsonAsync(await PostTokenWithAsync(client, TokenForm(code)));

        body.GetProperty("expires_in").GetInt64().Should().Be(600, "the lifetime comes from the registration the credential was checked against");
        repository.ReadsSinceReset.Should().Be(1, "the token request reads the repository once, for authentication, and never again");
    }

    // ── PKCE ──────────────────────────────────────────────────────────────────────────────────

    [Fact]
    public async Task A_request_without_a_code_verifier_is_refused_for_every_client()
    {
        var code = await ObtainCodeAsync();
        var form = TokenForm(code);
        form.Remove("code_verifier");

        var response = await PostTokenAsync(form);

        await ShouldBeErrorAsync(response, "invalid_request");
    }

    [Theory]
    [InlineData("tooshort")]
    [InlineData("dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk=")]
    public async Task A_malformed_code_verifier_is_refused_before_the_code_is_touched(string verifier)
    {
        var code = await ObtainCodeAsync();

        var refused = await PostTokenAsync(TokenForm(code, verifier: verifier));
        var retried = await PostTokenAsync(TokenForm(code));

        await ShouldBeErrorAsync(refused, "invalid_request");
        retried.StatusCode.Should().Be(HttpStatusCode.OK, "a request refused at the shape check consumed nothing");
    }

    [Fact]
    public async Task A_code_verifier_that_does_not_match_the_challenge_is_refused_and_burns_the_code()
    {
        var code = await ObtainCodeAsync();

        var refused = await PostTokenAsync(TokenForm(code, verifier: WrongVerifier));
        var retried = await PostTokenAsync(TokenForm(code));

        await ShouldBeErrorAsync(refused, "invalid_grant");
        await ShouldBeErrorAsync(retried, "invalid_grant");
        LogsShouldCarryNoProtocolMaterial(code, Verifier, WrongVerifier);
    }

    // ── What the code is bound to ─────────────────────────────────────────────────────────────

    [Fact]
    public async Task A_code_presented_by_another_client_is_refused_and_left_for_its_owner()
    {
        var code = await ObtainCodeAsync();

        var refused = await PostTokenAsync(TokenForm(code, OtherClient));
        var owner = await PostTokenAsync(TokenForm(code));

        await ShouldBeErrorAsync(refused, "invalid_grant");
        owner.StatusCode.Should().Be(HttpStatusCode.OK, "a mismatch is checked without consuming, so the legitimate client is not denied service");
    }

    [Fact]
    public async Task A_redirect_uri_that_differs_from_the_one_the_code_was_issued_to_is_refused_and_burns_the_code()
    {
        var code = await ObtainCodeAsync();
        var form = TokenForm(code);
        form["redirect_uri"] = "https://test.example.com/Callback";

        var refused = await PostTokenAsync(form);
        var retried = await PostTokenAsync(TokenForm(code));

        await ShouldBeErrorAsync(refused, "invalid_grant");
        await ShouldBeErrorAsync(retried, "invalid_grant");
    }

    [Fact]
    public async Task A_code_is_single_use()
    {
        var code = await ObtainCodeAsync();

        var first = await PostTokenAsync(TokenForm(code));
        var replay = await PostTokenAsync(TokenForm(code));

        first.StatusCode.Should().Be(HttpStatusCode.OK);
        await ShouldBeErrorAsync(replay, "invalid_grant");
    }

    [Fact]
    public async Task A_replayed_code_revokes_the_family_its_first_exchange_started()
    {
        var code = await ObtainCodeAsync();

        await PostTokenAsync(TokenForm(code));
        await PostTokenAsync(TokenForm(code));

        _refreshTokens.RevokedFamilies.Should().ContainSingle()
            .Which.Should().MatchRegex("^[A-Za-z0-9_-]{43}$", "the family id is a 256-bit CSPRNG value, minted before the redemption");
        _refreshTokens.RevocationWasCancellable.Should().BeFalse("a client dropping the connection must not cancel the server's own security action");
    }

    [Fact]
    public async Task Every_code_starts_its_own_family()
    {
        var first = await ObtainCodeAsync();
        var second = await ObtainCodeAsync();

        foreach (var code in new[] { first, second })
        {
            await PostTokenAsync(TokenForm(code));
            await PostTokenAsync(TokenForm(code));
        }

        _refreshTokens.RevokedFamilies.Should().HaveCount(2).And.OnlyHaveUniqueItems("a family id is never reused across codes");
    }

    [Fact]
    public async Task An_expired_code_is_refused()
    {
        var code = await ObtainCodeAsync();
        _time.Advance(TimeSpan.FromSeconds(60) + TimeSpan.FromSeconds(5) + TimeSpan.FromSeconds(1));

        var response = await PostTokenAsync(TokenForm(code));

        await ShouldBeErrorAsync(response, "invalid_grant");
    }

    [Fact]
    public async Task A_code_the_store_has_never_seen_is_refused()
    {
        var response = await PostTokenAsync(TokenForm(StoreKeyGenerator.Generate()));

        await ShouldBeErrorAsync(response, "invalid_grant");
    }

    // ── The client ────────────────────────────────────────────────────────────────────────────

    [Fact]
    public async Task An_unknown_client_is_refused_with_invalid_client()
    {
        var response = await PostTokenAsync(TokenForm(StoreKeyGenerator.Generate(), clientId: "nobody"));

        await ShouldBeErrorAsync(response, "invalid_client");
        response.Headers.WwwAuthenticate.Should().BeEmpty("the client did not use the Authorization header");
    }

    [Fact]
    public async Task A_wrong_secret_over_Basic_is_refused_with_401_and_a_matching_challenge()
    {
        var form = TokenForm(StoreKeyGenerator.Generate(), ConfidentialClient);
        form.Remove("client_id");

        var response = await PostTokenAsync(form, basic: (ConfidentialClient, "not-the-secret"));

        await ShouldBeErrorAsync(response, "invalid_client", HttpStatusCode.Unauthorized);
        response.Headers.WwwAuthenticate.Should().ContainSingle().Which.Scheme.Should().Be("Basic");
    }

    [Fact]
    public async Task A_failed_attempt_over_another_Authorization_scheme_is_401_with_a_challenge_naming_that_scheme()
    {
        var form = TokenForm(StoreKeyGenerator.Generate());
        form.Remove("client_id");
        using var request = new HttpRequestMessage(HttpMethod.Post, TokenPath) { Content = new FormUrlEncodedContent(form) };
        request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", "not-a-client-credential");

        var response = await _client.SendAsync(request, Cancellation);

        await ShouldBeErrorAsync(response, "invalid_client", HttpStatusCode.Unauthorized);
        response.Headers.WwwAuthenticate.Should().ContainSingle().Which.Scheme.Should().Be("Bearer", "RFC 6749 §5.2: the challenge matches the scheme the client used");
    }

    [Fact]
    public async Task Two_Authorization_headers_are_refused_as_a_malformed_request_without_a_challenge()
    {
        var form = TokenForm(StoreKeyGenerator.Generate(), ConfidentialClient);
        using var request = new HttpRequestMessage(HttpMethod.Post, TokenPath) { Content = new FormUrlEncodedContent(form) };
        request.Headers.TryAddWithoutValidation("Authorization", ["Basic YTpi", "Basic Yzpk"]);

        var response = await _client.SendAsync(request, Cancellation);

        await ShouldBeErrorAsync(response, "invalid_client");
        response.Headers.WwwAuthenticate.Should().BeEmpty("two headers is not an authentication attempt but a malformed one (RFC 7235 §4.2)");
    }

    [Fact]
    public async Task The_token_endpoint_is_reachable_under_a_host_fallback_authorization_policy()
    {
        using var factory = new TestWebAppFactoryWithFallbackAuthorizationPolicy();
        using var client = NewClient(factory);

        var canary = await client.GetAsync("/host-route", Cancellation);
        var response = await PostTokenWithAsync(client, TokenForm(StoreKeyGenerator.Generate(), clientId: "test-client"));

        canary.StatusCode.Should().Be(HttpStatusCode.Unauthorized, "the fallback policy is in force on the host's own routes");
        await ShouldBeErrorAsync(response, "invalid_grant");
    }

    [Fact]
    public async Task A_confidential_client_without_credentials_is_refused()
    {
        var code = await ObtainCodeAsync(ConfidentialClient);

        var response = await PostTokenAsync(TokenForm(code, ConfidentialClient));

        await ShouldBeErrorAsync(response, "invalid_client");
    }

    [Fact]
    public async Task A_request_naming_no_client_is_refused_with_invalid_client()
    {
        var form = TokenForm(StoreKeyGenerator.Generate());
        form.Remove("client_id");

        var response = await PostTokenAsync(form);

        await ShouldBeErrorAsync(response, "invalid_client");
    }

    [Fact]
    public async Task A_client_not_allowed_the_code_grant_is_refused_with_unauthorized_client()
    {
        var response = await PostTokenAsync(TokenForm(StoreKeyGenerator.Generate(), NoCodeGrantClient));

        await ShouldBeErrorAsync(response, "unauthorized_client");
    }

    // ── The request's shape ───────────────────────────────────────────────────────────────────

    [Fact]
    public async Task A_grant_type_other_than_authorization_code_is_unsupported()
    {
        var form = TokenForm(StoreKeyGenerator.Generate());
        form["grant_type"] = "refresh_token";

        var response = await PostTokenAsync(form);

        await ShouldBeErrorAsync(response, "unsupported_grant_type");
    }

    [Fact]
    public async Task A_host_that_does_not_serve_the_code_grant_refuses_the_exchange_before_naming_a_client()
    {
        // A code issued before the grant was switched off, or one shared across hosts through a
        // common store, must not be redeemable on a host whose configuration no longer serves it.
        var repository = new FirstReadThenOtherRepository(PublicRegistration(), PublicRegistration());
        using var factory = new TestWebAppFactory(
            configureOptions: options => options.GrantTypesSupported = [GrantType.ClientCredentials],
            configureBuilder: builder => builder.Services.AddSingleton<IClientRepository>(repository));
        using var client = NewClient(factory);
        repository.ResetToFirst();

        var response = await PostTokenWithAsync(client, TokenForm(StoreKeyGenerator.Generate()));

        await ShouldBeErrorAsync(response, "unsupported_grant_type");
        repository.ReadsSinceReset.Should().Be(0, "the refusal precedes client identification and touches nothing");
    }

    [Theory]
    [InlineData("grant_type")]
    [InlineData("code")]
    [InlineData("redirect_uri")]
    public async Task A_missing_required_parameter_is_invalid_request(string parameter)
    {
        var form = TokenForm(StoreKeyGenerator.Generate());
        form.Remove(parameter);

        var response = await PostTokenAsync(form);

        await ShouldBeErrorAsync(response, "invalid_request");
    }

    [Fact]
    public async Task A_repeated_parameter_is_invalid_request_and_its_name_is_not_echoed()
    {
        // The key is attacker-chosen; RFC 6749 §5.2 restricts what an error_description may carry.
        var fields = TokenForm(StoreKeyGenerator.Generate()).ToList();
        fields.Add(KeyValuePair.Create("0001<x>", "one"));
        fields.Add(KeyValuePair.Create("0001<x>", "two"));

        var response = await PostTokenAsync(fields);

        await ShouldBeErrorAsync(response, "invalid_request");
        (await ReadJsonAsync(response)).GetProperty("error_description").GetString()
            .Should().Be("A parameter must not be repeated.");
    }

    [Fact]
    public async Task A_multipart_body_is_invalid_request_and_consumes_nothing()
    {
        var code = await ObtainCodeAsync();
        using var multipart = new MultipartFormDataContent();
        foreach (var (key, value) in TokenForm(code))
            multipart.Add(new StringContent(value), key);

        var refused = await _client.PostAsync(TokenPath, multipart, Cancellation);
        var retried = await PostTokenAsync(TokenForm(code));

        await ShouldBeErrorAsync(refused, "invalid_request");
        retried.StatusCode.Should().Be(HttpStatusCode.OK, "RFC 6749 §4.1.3 names one serialization, and a body in another is refused unread");
    }

    [Fact]
    public async Task A_body_the_form_reader_refuses_is_invalid_request_with_the_no_store_headers_intact()
    {
        // One over the host's default form value-count limit.
        var fields = Enumerable.Range(0, 1025).Select(i => KeyValuePair.Create("p" + i, "v"));

        var response = await PostTokenAsync(fields);

        await ShouldBeErrorAsync(response, "invalid_request");
        response.Headers.CacheControl!.NoStore.Should().BeTrue();
    }

    [Fact]
    public async Task A_body_that_is_not_form_encoded_is_invalid_request()
    {
        using var request = new HttpRequestMessage(HttpMethod.Post, TokenPath)
        {
            Content = new StringContent("{\"grant_type\":\"authorization_code\"}", Encoding.UTF8, "application/json"),
        };

        var response = await _client.SendAsync(request, Cancellation);

        await ShouldBeErrorAsync(response, "invalid_request");
        response.Headers.CacheControl!.NoStore.Should().BeTrue("error responses are not cacheable either");
    }

    [Fact]
    public async Task The_token_endpoint_answers_POST_only()
    {
        var response = await _client.GetAsync(TokenPath, Cancellation);

        response.StatusCode.Should().Be(HttpStatusCode.MethodNotAllowed);
    }

    // ── Faults ────────────────────────────────────────────────────────────────────────────────

    [Fact]
    public async Task A_store_failure_during_redemption_is_server_error_and_names_no_material()
    {
        var code = await ObtainCodeAsync();
        _backingStore.Fail = true;

        var response = await PostTokenAsync(TokenForm(code));

        await ShouldBeErrorAsync(response, "server_error", HttpStatusCode.InternalServerError);
        _logs.Entries.Should().Contain(entry => entry.Level == LogLevel.Error && entry.Message.Contains(PublicClient, StringComparison.Ordinal));
        LogsShouldCarryNoProtocolMaterial(code, Verifier);
    }

    [Fact]
    public async Task A_replay_whose_family_revocation_fails_is_still_refused_and_the_failure_is_logged()
    {
        var code = await ObtainCodeAsync();
        await PostTokenAsync(TokenForm(code));
        _refreshTokens.FailRevocation = true;

        var replay = await PostTokenAsync(TokenForm(code));

        await ShouldBeErrorAsync(replay, "invalid_grant");
        _logs.Entries.Should().Contain(entry => entry.Level == LogLevel.Error && entry.Message.Contains("family", StringComparison.Ordinal));
    }

    [Fact]
    public async Task A_signing_failure_is_server_error_and_no_token_leaves()
    {
        using var factory = new TestWebAppFactory(
            configureBuilder: builder =>
            {
                builder.Services.AddSingleton<TimeProvider>(_time);
                builder.AddInMemoryClients(clients => clients.Add(PublicRegistration()));
                builder.Services.AddKeyedSingleton<ITokenIssuer>(TokenKind.IdToken, new FailingTokenIssuer());
            },
            mapEndpoints: MapHostPages);
        using var client = NewClient(factory);
        var code = await ObtainCodeWithAsync(client);

        var response = await PostTokenWithAsync(client, TokenForm(code));

        await ShouldBeErrorAsync(response, "server_error", HttpStatusCode.InternalServerError);
        var body = await response.Content.ReadAsStringAsync(Cancellation);
        body.Should().NotContain("access_token", "the access token was signed before the ID token failed, and must not leave alone");
    }

    // ── Helpers for hosts other than the default ──────────────────────────────────────────────

    private static async Task<HttpResponseMessage> PostTokenWithAsync(HttpClient client, Dictionary<string, string> form)
    {
        using var content = new FormUrlEncodedContent(form);
        return await client.PostAsync(TokenPath, content, Cancellation);
    }

    // ── Fakes ─────────────────────────────────────────────────────────────────────────────────

    /// <summary>A repository answering with one registration on the first read after a reset and another on every read after it.</summary>
    private sealed class FirstReadThenOtherRepository(IClientRegistration first, IClientRegistration other) : IClientRepository
    {
        private int _reads;

        public int ReadsSinceReset => Volatile.Read(ref _reads);

        public void ResetToFirst() => Interlocked.Exchange(ref _reads, 0);

        public ValueTask<IClientRegistration?> FindByClientIdAsync(string clientId, CancellationToken cancellationToken = default)
        {
            var registration = Interlocked.Increment(ref _reads) == 1 ? first : other;
            return new(string.Equals(registration.ClientId, clientId, StringComparison.Ordinal) ? registration : null);
        }
    }

    /// <summary>An issuer standing in for a signing key ring that cannot sign.</summary>
    private sealed class FailingTokenIssuer : ITokenIssuer
    {
        public ValueTask<IssuedToken> IssueAsync(TokenIssuanceContext context, TokenPayload payload, CancellationToken cancellationToken = default) =>
            throw new InvalidOperationException("The signing key ring is unavailable.");
    }

    /// <summary>A refresh-token store that records which families were revoked; nothing else is reached in this flow.</summary>
    private sealed class RecordingRefreshTokenStore : IRefreshTokenStore
    {
        private readonly List<string> _revoked = [];

        public bool FailRevocation { get; set; }

        public bool RevocationWasCancellable { get; private set; }

        public IReadOnlyList<string> RevokedFamilies
        {
            get { lock (_revoked) return [.. _revoked]; }
        }

        public Task StoreAsync(string tokenHandle, RefreshTokenEntry entry, CancellationToken cancellationToken) =>
            throw new NotSupportedException("The code grant issues no refresh token yet.");

        public ValueTask<RefreshTokenEntry?> FindAsync(string tokenHandle, CancellationToken cancellationToken) =>
            throw new NotSupportedException();

        public ValueTask<RefreshTokenConsumptionResult> TryConsumeAsync(string tokenHandle, string clientId, CancellationToken cancellationToken) =>
            throw new NotSupportedException();

        public Task RevokeFamilyAsync(string familyId, CancellationToken cancellationToken)
        {
            RevocationWasCancellable = cancellationToken.CanBeCanceled;

            if (FailRevocation)
                throw new ZeeKayDaStoreException("The grant store is unreachable.");

            lock (_revoked) _revoked.Add(familyId);
            return Task.CompletedTask;
        }

        void IRefreshTokenStore.SealAsFrameworkOwnedProtocol() { }
    }

    /// <summary>An in-memory backing store that can be made to fail every operation, as an unreachable cache would.</summary>
    private sealed class SwitchableBackingStore : IAuthorizationCodeBackingStore
    {
        private readonly InMemoryAuthorizationCodeBackingStore _inner = new();

        public bool Fail { get; set; }

        public ValueTask<bool> TryInsertAsync(StoreKey key, ReadOnlyMemory<byte> value, DateTimeOffset expiresAt, CancellationToken cancellationToken) =>
            Fail ? throw new IOException("The cache is unreachable.") : _inner.TryInsertAsync(key, value, expiresAt, cancellationToken);

        public ValueTask<ReadOnlyMemory<byte>?> GetAsync(StoreKey key, CancellationToken cancellationToken) =>
            Fail ? throw new IOException("The cache is unreachable.") : _inner.GetAsync(key, cancellationToken);

        public ValueTask RemoveAsync(StoreKey key, CancellationToken cancellationToken) =>
            Fail ? throw new IOException("The cache is unreachable.") : _inner.RemoveAsync(key, cancellationToken);
    }

    /// <summary>Captures every log entry the host writes, after the framework's redaction.</summary>
    private sealed class CapturingLoggerProvider : ILoggerProvider
    {
        private readonly List<(string Category, LogLevel Level, string Message)> _entries = [];

        public IReadOnlyList<(string Category, LogLevel Level, string Message)> Entries
        {
            get { lock (_entries) return [.. _entries]; }
        }

        public ILogger CreateLogger(string categoryName) => new Logger(this, categoryName);

        public void Dispose()
        {
        }

        private void Add(string category, LogLevel level, string message)
        {
            lock (_entries) _entries.Add((category, level, message));
        }

        private sealed class Logger(CapturingLoggerProvider owner, string category) : ILogger
        {
            public IDisposable? BeginScope<TState>(TState state) where TState : notnull => null;

            public bool IsEnabled(LogLevel logLevel) => true;

            public void Log<TState>(LogLevel logLevel, EventId eventId, TState state, Exception? exception, Func<TState, Exception?, string> formatter) =>
                owner.Add(category, logLevel, formatter(state, exception) + (exception is null ? string.Empty : " " + exception));
        }
    }
}
