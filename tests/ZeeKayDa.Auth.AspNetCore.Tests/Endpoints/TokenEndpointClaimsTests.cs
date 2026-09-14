using System.Buffers.Text;
using System.Net;
using System.Security.Claims;
using System.Text.Json;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.AspNetCore.Routing;
using Microsoft.AspNetCore.TestHost;
using Microsoft.AspNetCore.WebUtilities;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using ZeeKayDa.Auth.AspNetCore.Interaction;
using ZeeKayDa.Auth.AspNetCore.Tests.Interaction;
using ZeeKayDa.Auth.Authorization;
using ZeeKayDa.Auth.Claims;
using ZeeKayDa.Auth.Clients;
using ZeeKayDa.Auth.Scopes;
using ZeeKayDa.Auth.Tokens;

namespace ZeeKayDa.Auth.AspNetCore.Tests.Endpoints;

/// <summary>
/// The claims seam and claim selection, end to end: a host's <see cref="IClaimsProvider"/> is
/// asked for the subject's claims on every exchange, the granted scopes and the client's
/// additions decide which of them each token carries, and the granted scopes decide the access
/// token's audience. The refusals — a subject the provider rejects, a provider that faults, a
/// misconfigured client — are recorded by the tests that prove them.
/// </summary>
public sealed class TokenEndpointClaimsTests : IDisposable
{
    private const string TokenPath = "/connect/token";
    private const string Issuer = "https://test.example.com";
    private const string Redirect = "https://test.example.com/callback";
    private const string LoginPath = "/account/login";
    private const string OrdersAudience = "https://orders.example.com/";
    private const string ReportsAudience = "https://reports.example.com/";
    private const string App = "app";
    private const string TenantApp = "tenant-app";
    private const string Subject = "user-1";
    private const string Nonce = "n-0S6_WzA2Mj";

    // RFC 7636 Appendix B.
    private const string Verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
    private const string Challenge = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM";

    private static readonly ClaimRecord[] DefaultPool =
    [
        new("name", "Chris"),
        new("email", "chris@example.com"),
        new("email_verified", true),
        new("role", "admin"),
        new("role", "editor"),
        new("tenant", "acme"),
        new("customer_number", "C-1"),
    ];

    private readonly ScriptedClaimsProvider _provider = new();
    private readonly MutableScopeRepository _scopes = new(
    [
        .. StandardScopes.All,
        new ScopeDefinition { Name = "orders.read", Audience = OrdersAudience, AccessTokenClaims = ["role"], UserInfoClaims = ["customer_number"] },
        new ScopeDefinition { Name = "orders.write", Audience = OrdersAudience, AccessTokenClaims = ["role"] },
        new ScopeDefinition { Name = "reports.read", Audience = ReportsAudience },
    ]);
    private readonly CapturingLoggerProvider _logs = new();
    private readonly TestWebAppFactory _factory;
    private readonly HttpClient _client;

    public TokenEndpointClaimsTests()
    {
        _factory = new TestWebAppFactory(
            configureBuilder: builder =>
            {
                builder.Services.AddLogging(logging => logging.AddProvider(_logs));
                builder.Services.AddSingleton<IScopeRepository>(_scopes);
                builder.Services.AddSingleton<IClaimsProvider>(_provider);
                builder.AddInMemoryClients(clients => clients
                    .Add(ClientRegistration.CreatePublic(App, [Redirect], [], ["openid", "profile", "email", "address", "orders.read", "orders.write", "reports.read"]) with { RequireConsent = false })
                    .Add(ClientRegistration.CreatePublic(TenantApp, [Redirect], [], ["openid", "profile"]) with
                    {
                        RequireConsent = false,
                        AdditionalIdTokenClaims = ["tenant"],
                        AdditionalAccessTokenClaims = ["tenant"],
                    }));
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

    // ── Selection by scope ────────────────────────────────────────────────────────────────────

    [Fact]
    public async Task Profile_yields_name_in_the_ID_token_and_not_email()
    {
        var tokens = await ExchangeAsync(scope: "openid profile");

        tokens.IdToken.GetProperty("name").GetString().Should().Be("Chris");
        tokens.IdToken.TryGetProperty("email", out _).Should().BeFalse();
        tokens.AccessToken.TryGetProperty("name", out _).Should().BeFalse("no scope unlocks name in the access token");
    }

    [Fact]
    public async Task Adding_the_email_scope_yields_email_and_a_boolean_email_verified()
    {
        var tokens = await ExchangeAsync(scope: "openid profile email");

        tokens.IdToken.GetProperty("email").GetString().Should().Be("chris@example.com");
        tokens.IdToken.GetProperty("email_verified").ValueKind.Should().Be(JsonValueKind.True, "a boolean on the wire, not the string \"true\"");
    }

    [Fact]
    public async Task An_API_scope_routes_its_claims_to_the_access_token()
    {
        var tokens = await ExchangeAsync(scope: "openid orders.read");

        tokens.AccessToken.GetProperty("role").EnumerateArray().Select(role => role.GetString()).Should().Equal("admin", "editor");
        tokens.IdToken.TryGetProperty("role", out _).Should().BeFalse();
        tokens.IdToken.TryGetProperty("customer_number", out _).Should().BeFalse("a userinfo-only claim reaches no token");
        tokens.AccessToken.TryGetProperty("customer_number", out _).Should().BeFalse();
    }

    [Fact]
    public async Task Both_tokens_come_from_one_resolution()
    {
        await ExchangeAsync(scope: "openid profile orders.read");

        _provider.Calls.Should().ContainSingle("the provider is asked once per exchange, and both tokens are selected from that answer");
    }

    [Fact]
    public async Task The_provider_is_told_the_subject_the_scopes_the_claim_types_to_fetch_and_the_family()
    {
        await ExchangeAsync(clientId: TenantApp, scope: "openid profile");

        var context = _provider.Calls.Should().ContainSingle().Subject;
        context.Sub.Should().Be(Subject);
        context.Scopes.Should().Equal("openid", "profile");
        context.ClaimTypes.Should().Contain(["name", "given_name", "tenant"]).And.NotContain("email");
        context.FamilyId.Should().NotBeNullOrEmpty();
    }

    [Fact]
    public async Task A_claim_the_provider_does_not_return_is_absent_from_the_token()
    {
        _provider.Script = _ => Resolved([new("name", "Chris")]);

        var tokens = await ExchangeAsync(scope: "openid profile email");

        tokens.IdToken.TryGetProperty("email", out _).Should().BeFalse("OpenID Connect Core §5.3.2: an unavailable claim is omitted, never null");
    }

    // ── Reserved names ────────────────────────────────────────────────────────────────────────

    [Theory]
    [InlineData("sub")]
    [InlineData("iss")]
    [InlineData("aud")]
    public async Task A_provider_cannot_override_a_protocol_claim(string reserved)
    {
        _provider.Script = _ => Resolved([new("name", "Chris"), new(reserved, "attacker")]);

        var tokens = await ExchangeAsync(scope: "openid profile");

        tokens.IdToken.GetProperty("sub").GetString().Should().Be(Subject);
        tokens.IdToken.GetProperty("iss").GetString().Should().Be(Issuer);
        tokens.IdToken.GetProperty("aud").GetString().Should().Be(App);
        tokens.AccessToken.GetProperty("sub").GetString().Should().Be(Subject);
        tokens.AccessToken.GetProperty("aud").GetString().Should().Be(Issuer);
    }

    // ── Client additions ──────────────────────────────────────────────────────────────────────

    [Fact]
    public async Task A_client_addition_yields_the_claim_when_the_provider_returns_it()
    {
        var tokens = await ExchangeAsync(clientId: TenantApp, scope: "openid profile");

        tokens.IdToken.GetProperty("tenant").GetString().Should().Be("acme");
        tokens.AccessToken.GetProperty("tenant").GetString().Should().Be("acme");
    }

    [Fact]
    public async Task A_client_without_the_addition_does_not_receive_the_claim()
    {
        var tokens = await ExchangeAsync(clientId: App, scope: "openid profile");

        tokens.IdToken.TryGetProperty("tenant", out _).Should().BeFalse();
    }

    [Fact]
    public void A_client_addition_naming_a_claim_a_scope_unlocks_fails_startup()
    {
        using var factory = new StartupFactory(clients => clients.Add(
            ClientRegistration.CreatePublic("bad", [Redirect], [], ["openid"]) with { AdditionalAccessTokenClaims = ["email"] }));

        var act = () => factory.CreateClient();

        ExceptionChain.FindInChain<ZeeKayDaConfigurationException>(act.Should().Throw<Exception>().Which)!
            .AggregatedFailures.Should().Contain(f => f.Code == "client.claim_additions.scope_claim");
    }

    [Fact]
    public async Task A_client_addition_that_collides_with_a_scope_added_after_startup_is_refused_at_the_next_request()
    {
        // The startup guard cannot see a scope added later; the per-request guard can.
        _scopes.Scopes = [.. _scopes.Scopes, new ScopeDefinition { Name = "hr", UserInfoClaims = ["tenant"] }];

        var response = await _client.GetAsync(AuthorizeUrl(TenantApp, "openid profile"), Cancellation);

        response.StatusCode.Should().Be(HttpStatusCode.Redirect);
        var query = QueryHelpers.ParseQuery(new Uri(response.Headers.Location!.OriginalString).Query);
        query["error"].ToString().Should().Be("server_error");
        query["error_description"].ToString().Should().NotContain("tenant");
        _logs.Entries.Should().Contain(entry => entry.Level == LogLevel.Error && entry.Message.Contains("'tenant'", StringComparison.Ordinal));
    }

    // ── Audience ──────────────────────────────────────────────────────────────────────────────

    [Fact]
    public async Task Identity_scopes_alone_yield_the_issuer_as_a_string_audience()
    {
        var tokens = await ExchangeAsync(scope: "openid profile");

        tokens.AccessToken.GetProperty("aud").GetString().Should().Be(Issuer);
    }

    [Fact]
    public async Task One_API_scope_with_openid_yields_a_two_element_audience()
    {
        var tokens = await ExchangeAsync(scope: "openid orders.read");

        tokens.AccessToken.GetProperty("aud").EnumerateArray().Select(aud => aud.GetString()).Should().Equal(OrdersAudience, Issuer);
        tokens.IdToken.GetProperty("aud").GetString().Should().Be(App, "the ID token's audience is the client regardless");
    }

    [Fact]
    public async Task Two_scopes_sharing_an_audience_are_one_API()
    {
        var tokens = await ExchangeAsync(scope: "openid orders.read orders.write");

        tokens.AccessToken.GetProperty("aud").EnumerateArray().Select(aud => aud.GetString()).Should().Equal(OrdersAudience, Issuer);
    }

    [Fact]
    public async Task Two_granted_scopes_with_different_audiences_are_refused_at_authorize_before_any_interaction()
    {
        var response = await _client.GetAsync(AuthorizeUrl(App, "openid orders.read reports.read"), Cancellation);

        response.StatusCode.Should().Be(HttpStatusCode.Redirect);
        var location = response.Headers.Location!.OriginalString;
        location.Should().StartWith(Redirect, "the error goes back to the client, not to the login page");
        QueryHelpers.ParseQuery(new Uri(location).Query)["error"].ToString().Should().Be("invalid_scope");
    }

    [Fact]
    public async Task A_scope_no_longer_defined_at_exchange_is_server_error()
    {
        var code = await ObtainCodeAsync(App, "openid orders.read");
        _scopes.Scopes = [.. StandardScopes.All];

        var response = await PostTokenAsync(code, App);

        await ShouldBeErrorAsync(response, "server_error", HttpStatusCode.InternalServerError);
    }

    [Fact]
    public async Task An_audience_malformed_at_exchange_is_server_error()
    {
        var code = await ObtainCodeAsync(App, "openid orders.read");
        _scopes.Scopes = [.. StandardScopes.All, new ScopeDefinition { Name = "orders.read", Audience = "orders" }];

        var response = await PostTokenAsync(code, App);

        await ShouldBeErrorAsync(response, "server_error", HttpStatusCode.InternalServerError);
    }

    [Fact]
    public void An_audience_that_is_not_an_absolute_URI_fails_startup()
    {
        using var factory = new StartupFactory(scopes: [.. StandardScopes.All, new ScopeDefinition { Name = "orders.read", Audience = "orders" }]);

        var act = () => factory.CreateClient();

        ExceptionChain.FindInChain<ZeeKayDaConfigurationException>(act.Should().Throw<Exception>().Which)!
            .AggregatedFailures.Should().Contain(f => f.Code == "scopes.audience.invalid");
    }

    [Fact]
    public void A_client_allowing_a_scope_no_repository_defines_fails_startup()
    {
        using var factory = new StartupFactory(clients => clients.AddPublic("bad", [Redirect], [], ["openid", "undefined"]));

        var act = () => factory.CreateClient();

        ExceptionChain.FindInChain<ZeeKayDaConfigurationException>(act.Should().Throw<Exception>().Which)!
            .AggregatedFailures.Should().Contain(f => f.Code == "client.allowed_scopes.undefined");
    }

    // ── The provider's answers ────────────────────────────────────────────────────────────────

    [Fact]
    public async Task SubjectInvalid_answers_invalid_grant_and_issues_nothing()
    {
        _provider.Script = _ => new ClaimsResolutionResult.SubjectInvalid();
        var code = await ObtainCodeAsync(App, "openid profile");

        var response = await PostTokenAsync(code, App);

        await ShouldBeErrorAsync(response, "invalid_grant");
        var body = await response.Content.ReadAsStringAsync(Cancellation);
        body.Should().NotContain("access_token").And.NotContain("id_token");
    }

    [Fact]
    public async Task A_throwing_provider_answers_server_error_and_no_claim_value_reaches_a_log()
    {
        _provider.Script = _ => throw new InvalidOperationException("Could not load chris@example.com");
        var code = await ObtainCodeAsync(App, "openid profile");

        var response = await PostTokenAsync(code, App);

        await ShouldBeErrorAsync(response, "server_error", HttpStatusCode.InternalServerError);
        _logs.Entries.Should().Contain(entry => entry.Level == LogLevel.Error && entry.Message.Contains(App, StringComparison.Ordinal));
        LogsShouldCarryNoClaimValue();
    }

    [Fact]
    public async Task A_successful_exchange_writes_no_claim_value_to_any_log()
    {
        await ExchangeAsync(clientId: TenantApp, scope: "openid profile email");

        LogsShouldCarryNoClaimValue();
    }

    [Fact]
    public async Task A_providers_own_cancellation_is_its_failure_and_answers_server_error()
    {
        // An HttpClient timeout inside the provider surfaces as TaskCanceledException while the
        // request itself is still live; it must not escape as an unhandled exception.
        _provider.Script = _ => throw new TaskCanceledException("the identity store timed out");
        var code = await ObtainCodeAsync(App, "openid profile");

        var response = await PostTokenAsync(code, App);

        await ShouldBeErrorAsync(response, "server_error", HttpStatusCode.InternalServerError);
    }

    [Fact]
    public async Task A_result_list_that_throws_while_being_read_answers_server_error_and_leaks_nothing()
    {
        // The list is the provider's own code; a message it throws with must reach no log line.
        _provider.Script = _ => new ClaimsResolutionResult.Resolved { Claims = new ThrowingClaimList("row for chris@example.com is corrupt") };
        var code = await ObtainCodeAsync(App, "openid profile");

        var response = await PostTokenAsync(code, App);

        await ShouldBeErrorAsync(response, "server_error", HttpStatusCode.InternalServerError);
        LogsShouldCarryNoClaimValue();
    }

    [Fact]
    public async Task A_provider_whose_construction_fails_answers_server_error_and_leaks_nothing()
    {
        using var factory = new TestWebAppFactory(
            configureBuilder: builder =>
            {
                builder.Services.AddLogging(logging => logging.AddProvider(_logs));
                builder.AddClaimsProvider<UnconstructibleClaimsProvider>();
                builder.AddInMemoryClients(clients => clients.Add(
                    ClientRegistration.CreatePublic(App, [Redirect], [], ["openid", "profile"]) with { RequireConsent = false }));
            },
            mapEndpoints: MapLoginPage);
        using var client = factory.CreateClient(new() { BaseAddress = new Uri(Issuer), AllowAutoRedirect = false, HandleCookies = true });
        var code = await ObtainCodeWithAsync(client, App, "openid profile");

        var response = await PostTokenWithAsync(client, code, App);

        await ShouldBeErrorAsync(response, "server_error", HttpStatusCode.InternalServerError);
        _logs.Entries.Should().NotContain(entry => entry.Message.Contains("connection string", StringComparison.Ordinal));
    }

    [Fact]
    public async Task A_provider_returning_null_answers_server_error()
    {
        _provider.Script = _ => null!;
        var code = await ObtainCodeAsync(App, "openid profile");

        var response = await PostTokenAsync(code, App);

        await ShouldBeErrorAsync(response, "server_error", HttpStatusCode.InternalServerError);
    }

    [Fact]
    public async Task A_provider_that_throws_for_this_subject_only_does_not_affect_the_next_exchange()
    {
        _provider.Script = _ => throw new InvalidOperationException("transient");
        await PostTokenAsync(await ObtainCodeAsync(App, "openid profile"), App);
        _provider.Script = null;

        var tokens = await ExchangeAsync(scope: "openid profile");

        tokens.IdToken.GetProperty("name").GetString().Should().Be("Chris", "the provider is called fresh on every issuance");
    }

    // ── Merging ───────────────────────────────────────────────────────────────────────────────

    [Fact]
    public async Task Repeated_string_records_merge_into_one_array_in_order()
    {
        _provider.Script = _ => Resolved([new("role", "viewer"), new("role", "admin")]);

        var tokens = await ExchangeAsync(scope: "openid orders.read");

        tokens.AccessToken.GetProperty("role").EnumerateArray().Select(role => role.GetString()).Should().Equal("viewer", "admin");
    }

    [Fact]
    public async Task A_repeated_boolean_aborts_issuance_as_server_error()
    {
        _provider.Script = _ => Resolved([new("email_verified", true), new("email_verified", false)]);
        var code = await ObtainCodeAsync(App, "openid email");

        var response = await PostTokenAsync(code, App);

        await ShouldBeErrorAsync(response, "server_error", HttpStatusCode.InternalServerError);
        _logs.Entries.Should().Contain(entry => entry.Level == LogLevel.Error && entry.Message.Contains("'email_verified'", StringComparison.Ordinal));
    }

    [Fact]
    public async Task An_address_lands_as_an_object_with_the_standard_member_names()
    {
        _provider.Script = _ => Resolved([new("address", new AddressClaim { Locality = "Gothenburg", Country = "SE" })]);

        var tokens = await ExchangeAsync(scope: "openid address");

        var address = tokens.IdToken.GetProperty("address");
        address.GetProperty("locality").GetString().Should().Be("Gothenburg");
        address.GetProperty("country").GetString().Should().Be("SE");
        address.TryGetProperty("street_address", out _).Should().BeFalse();
    }

    // ── Startup ───────────────────────────────────────────────────────────────────────────────

    [Fact]
    public void A_host_with_no_claims_provider_fails_startup_naming_the_registration()
    {
        using var factory = new StartupFactory(registerProvider: false);

        var act = () => factory.CreateClient();

        var failure = ExceptionChain.FindInChain<ZeeKayDaConfigurationException>(act.Should().Throw<Exception>().Which)!
            .AggregatedFailures.Should().Contain(f => f.Code == "claims.provider.missing").Subject;
        failure.Message.Should().Contain("AddClaimsProvider");
    }

    // ── Driving the flow ──────────────────────────────────────────────────────────────────────

    private static void MapLoginPage(IEndpointRouteBuilder endpoints) =>
        endpoints.MapPost(LoginPath, async (HttpContext context, ILoginInteraction login) =>
            await login.SignInAsync(
                new ClaimsPrincipal(new ClaimsIdentity([new Claim("sub", Subject)], "test")),
                AuthenticationMethods.Password));

    private static string AuthorizeUrl(string clientId, string scope) =>
        QueryHelpers.AddQueryString("/connect/authorize", new Dictionary<string, string?>
        {
            ["client_id"] = clientId,
            ["redirect_uri"] = Redirect,
            ["response_type"] = "code",
            ["scope"] = scope,
            ["nonce"] = Nonce,
            ["code_challenge"] = Challenge,
            ["code_challenge_method"] = "S256",
        });

    private Task<string> ObtainCodeAsync(string clientId, string scope) => ObtainCodeWithAsync(_client, clientId, scope);

    private static async Task<string> ObtainCodeWithAsync(HttpClient client, string clientId, string scope)
    {
        var response = await client.GetAsync(AuthorizeUrl(clientId, scope), Cancellation);
        response.StatusCode.Should().Be(HttpStatusCode.Redirect);

        if (response.Headers.Location!.OriginalString.StartsWith(LoginPath, StringComparison.Ordinal))
        {
            var location = response.Headers.Location!.OriginalString;
            var interactionId = QueryHelpers.ParseQuery(location[location.IndexOf('?')..])[InteractionHandoff.InteractionIdParameter].ToString();
            using var login = new FormUrlEncodedContent([]);
            response = await client.PostAsync(QueryHelpers.AddQueryString(LoginPath, InteractionHandoff.InteractionIdParameter, interactionId), login, Cancellation);
        }

        return response.ShouldHaveIssuedCodeTo(Redirect);
    }

    private Task<HttpResponseMessage> PostTokenAsync(string code, string clientId) => PostTokenWithAsync(_client, code, clientId);

    private static async Task<HttpResponseMessage> PostTokenWithAsync(HttpClient client, string code, string clientId)
    {
        using var form = new FormUrlEncodedContent(new Dictionary<string, string>
        {
            ["grant_type"] = "authorization_code",
            ["code"] = code,
            ["redirect_uri"] = Redirect,
            ["client_id"] = clientId,
            ["code_verifier"] = Verifier,
        });

        return await client.PostAsync(TokenPath, form, Cancellation);
    }

    private async Task<(JsonElement AccessToken, JsonElement IdToken)> ExchangeAsync(string clientId = App, string scope = "openid profile")
    {
        var response = await PostTokenAsync(await ObtainCodeAsync(clientId, scope), clientId);
        response.StatusCode.Should().Be(HttpStatusCode.OK, await response.Content.ReadAsStringAsync(Cancellation));

        var body = JsonDocument.Parse(await response.Content.ReadAsStringAsync(Cancellation)).RootElement.Clone();
        return (Claims(body.GetProperty("access_token").GetString()!), Claims(body.GetProperty("id_token").GetString()!));
    }

    private static JsonElement Claims(string jwt) =>
        JsonDocument.Parse(Base64Url.DecodeFromChars(jwt.Split('.')[1])).RootElement.Clone();

    private static async Task ShouldBeErrorAsync(HttpResponseMessage response, string error, HttpStatusCode status = HttpStatusCode.BadRequest)
    {
        response.StatusCode.Should().Be(status);
        var body = JsonDocument.Parse(await response.Content.ReadAsStringAsync(Cancellation)).RootElement;
        body.GetProperty("error").GetString().Should().Be(error);
    }

    /// <summary>Nothing the provider returned, or embedded in its exception, reaches a log sink.</summary>
    private void LogsShouldCarryNoClaimValue()
    {
        string[] values = ["Chris", "chris@example.com", "acme", "admin", "C-1"];

        _logs.Entries
            .Where(entry => !entry.Category.StartsWith("Microsoft.AspNetCore.Hosting", StringComparison.Ordinal))
            .Should().NotContain(
                entry => values.Any(value => entry.Message.Contains(value, StringComparison.Ordinal)),
                "resolved claims are personal data and never reach a log");
    }

    private static ClaimsResolutionResult Resolved(IReadOnlyList<ClaimRecord> claims) =>
        new ClaimsResolutionResult.Resolved { Claims = claims };

    // ── Test doubles ──────────────────────────────────────────────────────────────────────────

    /// <summary>Answers from <see cref="Script"/> when set, otherwise the default pool; records every context it is handed.</summary>
    private sealed class ScriptedClaimsProvider : IClaimsProvider
    {
        private readonly List<ClaimsProviderContext> _calls = [];

        public Func<ClaimsProviderContext, ClaimsResolutionResult>? Script { get; set; }

        public IReadOnlyList<ClaimsProviderContext> Calls
        {
            get { lock (_calls) return [.. _calls]; }
        }

        public ValueTask<ClaimsResolutionResult> GetClaimsAsync(ClaimsProviderContext context, CancellationToken cancellationToken = default)
        {
            lock (_calls) _calls.Add(context);

            return ValueTask.FromResult(Script is { } script ? script(context) : Resolved(DefaultPool));
        }
    }

    /// <summary>A provider whose construction fails with a message a host would not want logged.</summary>
    private sealed class UnconstructibleClaimsProvider : IClaimsProvider
    {
        public UnconstructibleClaimsProvider() => throw new InvalidOperationException("Could not open connection string Server=db;Password=hunter2");

        public ValueTask<ClaimsResolutionResult> GetClaimsAsync(ClaimsProviderContext context, CancellationToken cancellationToken = default) =>
            throw new NotSupportedException();
    }

    /// <summary>A result list whose enumeration throws, standing in for a lazy query the provider handed over unread.</summary>
    private sealed class ThrowingClaimList(string message) : IReadOnlyList<ClaimRecord>
    {
        public int Count => 1;

        public ClaimRecord this[int index] => throw new InvalidOperationException(message);

        public IEnumerator<ClaimRecord> GetEnumerator() => throw new InvalidOperationException(message);

        System.Collections.IEnumerator System.Collections.IEnumerable.GetEnumerator() => GetEnumerator();
    }

    /// <summary>A scope repository whose definitions a test can change between requests.</summary>
    private sealed class MutableScopeRepository(IReadOnlyCollection<ScopeDefinition> scopes) : IScopeRepository
    {
        public IReadOnlyCollection<ScopeDefinition> Scopes { get; set; } = scopes;

        public ValueTask<IReadOnlyCollection<ScopeDefinition>> GetScopesAsync(CancellationToken cancellationToken = default) =>
            ValueTask.FromResult(Scopes);
    }

    /// <summary>A host built by hand, for the startup failures the shared factory papers over.</summary>
    private sealed class StartupFactory(
        Action<Clients.IInMemoryClientRegistrationBuilder>? clients = null,
        IEnumerable<ScopeDefinition>? scopes = null,
        bool registerProvider = true) : WebApplicationFactory<StartupFactory>
    {
        protected override IHostBuilder CreateHostBuilder()
            => Host.CreateDefaultBuilder().ConfigureWebHostDefaults(webBuilder => webBuilder.UseTestServer());

        protected override void ConfigureWebHost(IWebHostBuilder builder)
        {
            builder.UseContentRoot(AppContext.BaseDirectory);
            builder.ConfigureServices(services =>
            {
                services.AddRouting();
                var auth = services.AddZeeKayDaAuth(options =>
                {
                    options.Issuer = Issuer;
                    options.TokenEndpoint.AuthMethodsSupported.Add(TokenEndpointAuthMethods.None);
                })
                .AddInMemoryScopes(scopes ?? StandardScopes.All)
                .AddInMemoryClients(clients ?? (c => c.AddPublic(App, [Redirect], [], ["openid"])))
                .AddInMemoryStores(allowOutsideDevelopment: true)
                .AddTestSigningKeys();

                if (registerProvider)
                    auth.AddTestClaimsProvider();
            });

            builder.Configure(app =>
            {
                app.UseRouting();
                app.UseEndpoints(endpoints => endpoints.MapZeeKayDaAuth());
            });
        }
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
