using System.Net;
using System.Security.Claims;
using System.Text.Json;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Routing;
using Microsoft.AspNetCore.WebUtilities;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Microsoft.Extensions.Primitives;
using Microsoft.Extensions.Time.Testing;
using ZeeKayDa.Auth.AspNetCore.Interaction;
using ZeeKayDa.Auth.Authorization;
using ZeeKayDa.Auth.Clients;
using ZeeKayDa.Auth.Stores;

namespace ZeeKayDa.Auth.AspNetCore.Tests.Interaction;

/// <summary>
/// Integration tests for the end of a successful authorization request: the code the client is
/// sent, what the stored entry binds it to, and what the store then does with it.
/// </summary>
/// <remarks>
/// The test host maps a login page and a consent page written as a real host writes them, plus
/// probes that report what the encrypted session and interaction cookies carry. The issued code
/// is redeemed through the host's own <see cref="IAuthorizationCodeStore"/>, which is what the
/// token endpoint will do with it.
/// </remarks>
public sealed class AuthorizationCodeIssuanceTests : IDisposable
{
    private const string RegisteredRedirect = "https://test.example.com/callback";
    private const string Challenge = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM";
    private const string Nonce = "n-0S6_WzA2Mj";
    private const string LoginPath = "/account/login";
    private const string ConsentPath = FlowAssertions.ConsentPath;
    private const string ConsentingClient = "consenting-client";
    private const string TrustedClient = "trusted-client";
    private const string OtherClient = "other-client";

    private static readonly DateTimeOffset Now = new(2026, 9, 5, 12, 0, 0, TimeSpan.Zero);

    private readonly FakeTimeProvider _time = new(Now);
    private readonly CapturingLoggerProvider _logs = new();
    private readonly TestWebAppFactory _factory;
    private readonly HttpClient _client;

    public AuthorizationCodeIssuanceTests()
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

    private TestWebAppFactory NewFactory(
        IClientRepository? repository = null,
        TimeSpan? codeLifetime = null,
        Action<ZeeKayDaAuthBuilder>? configureStores = null) => new(
        configureOptions: options =>
        {
            if (codeLifetime is { } lifetime)
                options.AuthorizationEndpoint.AuthorizationCodeLifetime = lifetime;
        },
        configureBuilder: builder =>
        {
            builder.Services.AddSingleton<TimeProvider>(_time);
            builder.Services.AddLogging(logging => logging.AddProvider(_logs));
            builder.AddInMemoryClients(clients => clients
                .Add(ConsentingRegistration())
                .Add(TrustedRegistration())
                .AddPublic(OtherClient, ["https://other.example.com/callback"], [], ["openid"]));

            // Registered after AddInMemoryClients, so it wins resolution rather than tripping the
            // guard against a repository registered before it.
            if (repository is not null)
                builder.Services.AddSingleton(repository);

            configureStores?.Invoke(builder);
        },
        mapEndpoints: MapHostPages);

    private static ClientRegistration ConsentingRegistration() =>
        ClientRegistration.CreatePublic(ConsentingClient, [RegisteredRedirect], [], ["openid", "profile", "email"]);

    /// <summary>A first-party client the operator chose to exempt from consent.</summary>
    private static ClientRegistration TrustedRegistration()
    {
        var client = ClientRegistration.CreatePublic(TrustedClient, [RegisteredRedirect], [], ["openid", "profile"]);
        return client with { RequireConsent = false };
    }

    private static HttpClient NewClient(TestWebAppFactory factory) => factory.CreateClient(new()
    {
        BaseAddress = new Uri("https://test.example.com"),
        AllowAutoRedirect = false,
        HandleCookies = true,
    });

    /// <summary>The host's pages: sign-in, the consent page, and two probes.</summary>
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

        endpoints.MapGet("/test/session", async (HttpContext context) =>
        {
            var result = await context.AuthenticateAsync(ZeeKayDaCookies.Session);

            return result.Succeeded
                ? Results.Ok(new
                {
                    sub = result.Principal!.FindFirstValue("sub"),
                    sid = result.Principal.FindFirstValue(SsoSessionClaimTypes.SessionId),
                })
                : Results.NotFound();
        });

        endpoints.MapGet("/test/interaction", (HttpContext context, AuthorizationFlow flow) =>
            flow.Read(context) is { } requestContext ? Results.Ok(new { id = requestContext.Id }) : Results.NotFound());
    }

    private static Dictionary<string, string?> ValidQuery(string clientId = ConsentingClient, string scope = "openid profile email") => new()
    {
        ["client_id"] = clientId,
        ["redirect_uri"] = RegisteredRedirect,
        ["response_type"] = "code",
        ["scope"] = scope,
        ["nonce"] = Nonce,
        ["code_challenge"] = Challenge,
        ["code_challenge_method"] = "S256",
    };

    private Task<HttpResponseMessage> AuthorizeAsync(Dictionary<string, string?>? query = null) =>
        AuthorizeAsync(_client, query);

    private static Task<HttpResponseMessage> AuthorizeAsync(HttpClient client, Dictionary<string, string?>? query = null) =>
        client.GetAsync(QueryHelpers.AddQueryString("/connect/authorize", query ?? ValidQuery()), Cancellation);

    /// <summary>The interaction identifier the framework put on a redirect to a host page.</summary>
    private static string InteractionIdFrom(HttpResponseMessage response)
    {
        var location = response.Headers.Location!.OriginalString;
        return QueryHelpers.ParseQuery(location[location.IndexOf('?')..])[InteractionHandoff.InteractionIdParameter]!;
    }

    private static string WithInteractionId(string path, string interactionId) =>
        QueryHelpers.AddQueryString(path, InteractionHandoff.InteractionIdParameter, interactionId);

    private static FormUrlEncodedContent Form(params (string Key, string Value)[] fields) =>
        new(fields.Select(field => KeyValuePair.Create(field.Key, field.Value)));

    private Task<HttpResponseMessage> PostLoginAsync(string interactionId, string sub = "user-1") =>
        PostLoginAsync(_client, interactionId, sub);

    private static async Task<HttpResponseMessage> PostLoginAsync(HttpClient client, string interactionId, string sub = "user-1")
    {
        using var content = Form(("sub", sub));
        return await client.PostAsync(WithInteractionId(LoginPath, interactionId), content, Cancellation);
    }

    private Task<HttpResponseMessage> GrantAsync(string interactionId, params string[] scopes) =>
        GrantAsync(_client, interactionId, scopes);

    private static async Task<HttpResponseMessage> GrantAsync(HttpClient client, string interactionId, params string[] scopes)
    {
        using var content = Form([.. scopes.Select(scope => ("scope", scope))]);
        return await client.PostAsync(WithInteractionId(ConsentPath, interactionId), content, Cancellation);
    }

    /// <summary>Runs authorize → login → consent handoff, returning the interaction identifier the consent page was handed.</summary>
    private async Task<string> ReachConsentAsync(Dictionary<string, string?>? query = null) =>
        await ReachConsentAsync(_client, query);

    private static async Task<string> ReachConsentAsync(HttpClient client, Dictionary<string, string?>? query = null)
    {
        var handoff = await AuthorizeAsync(client, query);
        var signIn = await PostLoginAsync(client, InteractionIdFrom(handoff));
        signIn.ShouldHaveReachedConsent();

        return InteractionIdFrom(signIn);
    }

    /// <summary>Runs the whole flow for the consenting client, granting every scope asked, and returns the code response.</summary>
    private async Task<HttpResponseMessage> CompleteFlowAsync(Dictionary<string, string?>? query = null)
    {
        var interactionId = await ReachConsentAsync(query);
        return await GrantAsync(interactionId, "openid", "profile", "email");
    }

    /// <summary>Redeems the code as the token endpoint will, through the host's own store.</summary>
    private Task<AuthorizationCodeRedemptionResult> RedeemAsync(string code, string clientId = ConsentingClient) =>
        RedeemAsync(_factory, code, clientId);

    private static async Task<AuthorizationCodeRedemptionResult> RedeemAsync(TestWebAppFactory factory, string code, string clientId = ConsentingClient)
    {
        var store = factory.Services.GetRequiredService<IAuthorizationCodeStore>();
        return await store.TryRedeemAsync(code, clientId, familyId: StoreKeyGenerator.Generate(), Cancellation);
    }

    private static async Task<JsonElement> ReadJsonAsync(HttpResponseMessage response)
    {
        var body = await response.Content.ReadAsStringAsync(Cancellation);
        return JsonDocument.Parse(body).RootElement.Clone();
    }

    private async Task<bool> InteractionIsAliveAsync()
    {
        var response = await _client.GetAsync("/test/interaction", Cancellation);
        return response.StatusCode != HttpStatusCode.NotFound;
    }

    private async Task<string> ReadSessionIdAsync()
    {
        var response = await _client.GetAsync("/test/session", Cancellation);
        response.StatusCode.Should().Be(HttpStatusCode.OK, "the session that produced the code is still held");

        return (await ReadJsonAsync(response)).GetProperty("sid").GetString()!;
    }

    /// <summary>The parsed query of a redirect back to the client.</summary>
    private static Dictionary<string, StringValues> RedirectQueryOf(HttpResponseMessage response)
    {
        var location = response.Headers.Location!.OriginalString;
        return QueryHelpers.ParseQuery(location[location.IndexOf('?')..]);
    }

    /// <summary>Where a redirect points — scheme, authority and path, with the query stripped.</summary>
    private static string DestinationOf(HttpResponseMessage response) =>
        new Uri(response.Headers.Location!.OriginalString).GetLeftPart(UriPartial.Path);

    // ── The response to the client ────────────────────────────────────────────────────────────

    [Fact]
    public async Task A_granted_request_is_answered_with_a_code_at_the_registered_redirect_uri()
    {
        var query = ValidQuery();
        query["state"] = "opaque-client-state";

        var response = await CompleteFlowAsync(query);

        var code = response.ShouldHaveIssuedCodeTo(RegisteredRedirect);
        code.Should().MatchRegex("^[A-Za-z0-9_-]{43}$", "a 256-bit CSPRNG handle, Base64Url-encoded");
        var parameters = RedirectQueryOf(response);
        parameters["state"].Should().Equal(["opaque-client-state"]);
        parameters["iss"].Should().Equal(["https://test.example.com"]);
        response.Headers.CacheControl!.NoStore.Should().BeTrue("the response carries the code");
    }

    [Fact]
    public async Task A_request_without_state_is_answered_without_one()
    {
        var response = await CompleteFlowAsync();

        response.ShouldHaveIssuedCodeTo(RegisteredRedirect);
        RedirectQueryOf(response).Should().NotContainKey("state", "state is echoed only when the client sent one");
    }

    [Fact]
    public async Task A_client_that_does_not_require_consent_is_answered_with_a_code_straight_from_sign_in()
    {
        var handoff = await AuthorizeAsync(ValidQuery(TrustedClient, "openid profile"));

        var signIn = await PostLoginAsync(InteractionIdFrom(handoff));

        var code = signIn.ShouldHaveIssuedCodeTo(RegisteredRedirect);
        var redeemed = (await RedeemAsync(code, TrustedClient)).Should().BeOfType<AuthorizationCodeRedemptionResult.Redeemed>().Subject;
        // No consent was asked, so the effective scopes are the granted ones.
        redeemed.Entry.Scope.Should().Equal("openid", "profile");
        redeemed.Entry.SsoSessionId.Should().Be(await ReadSessionIdAsync(),
            "the session was written in the same response as the code, and the code is bound to it");
    }

    [Fact]
    public async Task A_request_an_existing_session_answers_for_is_answered_with_a_code_without_interacting()
    {
        await CompleteFlowAsync();
        var sessionId = await ReadSessionIdAsync();

        var query = ValidQuery(TrustedClient, "openid profile");
        query["prompt"] = "none";
        var response = await AuthorizeAsync(query);

        var code = response.ShouldHaveIssuedCodeTo(RegisteredRedirect, "prompt=none succeeds against a live session for a client that skips consent");
        var redeemed = (await RedeemAsync(code, TrustedClient)).Should().BeOfType<AuthorizationCodeRedemptionResult.Redeemed>().Subject;
        redeemed.Entry.SsoSessionId.Should().Be(sessionId);
    }

    [Fact]
    public async Task Issuance_discards_the_interaction()
    {
        var response = await CompleteFlowAsync();

        response.ShouldHaveIssuedCodeTo(RegisteredRedirect);
        (await InteractionIsAliveAsync()).Should().BeFalse("a request that reached issuance is never resumed");
    }

    [Fact]
    public async Task Issuance_straight_from_sign_in_discards_the_interaction_too()
    {
        // On this path the session cookie and the interaction cookie's deletion land in the same
        // response; a replayed login POST for the same interaction must find nothing to complete.
        var handoff = await AuthorizeAsync(ValidQuery(TrustedClient, "openid profile"));
        var interactionId = InteractionIdFrom(handoff);
        (await PostLoginAsync(interactionId)).ShouldHaveIssuedCodeTo(RegisteredRedirect);

        var replay = async () => await PostLoginAsync(interactionId);

        await replay.Should().ThrowAsync<ZeeKayDaInteractionException>();
        (await InteractionIsAliveAsync()).Should().BeFalse();
    }

    [Fact]
    public async Task A_replayed_consent_post_after_issuance_is_refused_and_issues_nothing()
    {
        // The consent decision is not persisted: it is taken, the code issued and the
        // interaction discarded in one response, so the same POST sent again finds no request
        // to answer for. Replaying the form cannot mint a second code.
        var interactionId = await ReachConsentAsync();
        (await GrantAsync(interactionId, "openid")).ShouldHaveIssuedCodeTo(RegisteredRedirect);

        var replay = async () => await GrantAsync(interactionId, "openid");

        await replay.Should().ThrowAsync<ZeeKayDaInteractionException>();
    }

    // ── What the code is bound to ─────────────────────────────────────────────────────────────

    [Fact]
    public async Task The_issued_code_redeems_to_an_entry_bound_to_the_request_and_the_session()
    {
        var handoff = await AuthorizeAsync();
        var interactionId = InteractionIdFrom(handoff);
        var signIn = await PostLoginAsync(interactionId);
        signIn.ShouldHaveReachedConsent();
        var response = await GrantAsync(interactionId, "openid", "profile", "email");
        var code = response.ShouldHaveIssuedCodeTo(RegisteredRedirect);

        var redeemed = (await RedeemAsync(code)).Should().BeOfType<AuthorizationCodeRedemptionResult.Redeemed>().Subject;

        var entry = redeemed.Entry;
        entry.ClientId.Should().Be(ConsentingClient);
        entry.RedirectUri.Should().Be(RegisteredRedirect);
        entry.Sub.Should().Be("user-1");
        entry.Scope.Should().Equal("openid", "profile", "email");
        entry.Nonce.Should().Be(Nonce);
        entry.CodeChallenge.Should().Be(Challenge);
        entry.CodeChallengeMethod.Should().Be(CodeChallengeMethod.S256);
        entry.AuthTime.Should().Be(Now);
        entry.Amr.Should().Equal(AuthenticationMethods.Password);
        entry.Acr.Should().BeNull();
        entry.SsoSessionId.Should().Be(await ReadSessionIdAsync(), "the session identifier, never a per-code value");
        entry.InteractionId.Should().Be(interactionId);
        entry.IssuedAt.Should().Be(Now);
        entry.ExpiresAt.Should().Be(Now + TimeSpan.FromSeconds(60), "the default AuthorizationCodeLifetime");
    }

    [Fact]
    public async Task Two_completed_flows_produce_different_codes()
    {
        var first = (await CompleteFlowAsync()).ShouldHaveIssuedCodeTo(RegisteredRedirect);
        var second = (await CompleteFlowAsync()).ShouldHaveIssuedCodeTo(RegisteredRedirect);

        second.Should().NotBe(first);
    }

    [Fact]
    public async Task A_grant_naming_scopes_the_request_never_carried_issues_only_what_was_asked()
    {
        // The page's answer can only narrow the request: a scope the client is not allowed, and
        // one the request never carried, are both dropped without comment.
        var interactionId = await ReachConsentAsync(ValidQuery(scope: "openid email"));

        var response = await GrantAsync(interactionId, "openid", "email", "profile", "admin", "offline_access");

        var code = response.ShouldHaveIssuedCodeTo(RegisteredRedirect);
        var redeemed = (await RedeemAsync(code)).Should().BeOfType<AuthorizationCodeRedemptionResult.Redeemed>().Subject;
        redeemed.Entry.Scope.Should().Equal("openid", "email");
    }

    [Fact]
    public async Task A_grant_narrower_than_the_request_issues_the_narrower_set()
    {
        var interactionId = await ReachConsentAsync();

        var response = await GrantAsync(interactionId, "openid", "email");

        var code = response.ShouldHaveIssuedCodeTo(RegisteredRedirect);
        var redeemed = (await RedeemAsync(code)).Should().BeOfType<AuthorizationCodeRedemptionResult.Redeemed>().Subject;
        redeemed.Entry.Scope.Should().Equal("openid", "email");
    }

    [Fact]
    public async Task The_scopes_are_narrowed_by_the_registration_as_it_is_when_the_code_is_issued()
    {
        // The operator removed a scope from the client between the consent handoff and the
        // user's answer. The code carries what the registration allows now, not what it allowed
        // when the request was accepted.
        var repository = new MutableClientRepository(ConsentingRegistration());
        using var factory = NewFactory(repository);
        using var client = NewClient(factory);
        var interactionId = await ReachConsentAsync(client);

        repository.Current = ConsentingRegistration() with { AllowedScopes = new HashSet<string>(StringComparer.Ordinal) { "openid", "profile" } };
        var response = await GrantAsync(client, interactionId, "openid", "profile", "email");

        var code = response.ShouldHaveIssuedCodeTo(RegisteredRedirect);
        var redeemed = (await RedeemAsync(factory, code)).Should().BeOfType<AuthorizationCodeRedemptionResult.Redeemed>().Subject;
        redeemed.Entry.Scope.Should().Equal("openid", "profile");
    }

    [Fact]
    public async Task A_registration_that_no_longer_allows_openid_ends_the_request_locally()
    {
        // The same situation as a registration that dropped its redirect URI: the request was
        // accepted against a registration that no longer vouches for it, so it ends where it
        // stands, and nothing is issued.
        var repository = new MutableClientRepository(ConsentingRegistration());
        using var factory = NewFactory(repository);
        using var client = NewClient(factory);
        var interactionId = await ReachConsentAsync(client);

        repository.Current = ConsentingRegistration() with { AllowedScopes = new HashSet<string>(StringComparer.Ordinal) { "profile", "email" } };
        var response = await GrantAsync(client, interactionId, "openid", "profile", "email");

        response.StatusCode.Should().Be(HttpStatusCode.BadRequest);
        response.Headers.Location.Should().BeNull();
        (await response.Content.ReadAsStringAsync(Cancellation)).Should().Contain("invalid_request");
        var replay = async () => await GrantAsync(client, interactionId, "openid");
        await replay.Should().ThrowAsync<ZeeKayDaInteractionException>("the interaction was discarded");
    }

    // ── What the store does with it ───────────────────────────────────────────────────────────

    [Fact]
    public async Task A_code_is_single_use()
    {
        var code = (await CompleteFlowAsync()).ShouldHaveIssuedCodeTo(RegisteredRedirect);
        (await RedeemAsync(code)).Should().BeOfType<AuthorizationCodeRedemptionResult.Redeemed>();

        var replay = await RedeemAsync(code);

        replay.Should().BeOfType<AuthorizationCodeRedemptionResult.AlreadyRedeemed>()
            .Which.FamilyId.Should().NotBeNullOrEmpty("a replay names the family the first redemption started, so it can be revoked");
    }

    [Fact]
    public async Task A_code_expires_as_configured()
    {
        using var factory = NewFactory(codeLifetime: TimeSpan.FromSeconds(30));
        using var client = NewClient(factory);
        var interactionId = await ReachConsentAsync(client);
        var code = (await GrantAsync(client, interactionId, "openid")).ShouldHaveIssuedCodeTo(RegisteredRedirect);
        var skew = factory.Services.GetRequiredService<IOptions<AuthorizationServerOptions>>().Value.ClockSkewTolerance;

        _time.Advance(TimeSpan.FromSeconds(30) + skew + TimeSpan.FromSeconds(1));

        (await RedeemAsync(factory, code)).Should().BeOfType<AuthorizationCodeRedemptionResult.NotFound>(
            "past its lifetime and the skew grace, the code is unknown");
    }

    [Fact]
    public async Task A_code_inside_its_lifetime_still_redeems()
    {
        using var factory = NewFactory(codeLifetime: TimeSpan.FromSeconds(30));
        using var client = NewClient(factory);
        var interactionId = await ReachConsentAsync(client);
        var code = (await GrantAsync(client, interactionId, "openid")).ShouldHaveIssuedCodeTo(RegisteredRedirect);

        _time.Advance(TimeSpan.FromSeconds(29));

        (await RedeemAsync(factory, code)).Should().BeOfType<AuthorizationCodeRedemptionResult.Redeemed>();
    }

    [Fact]
    public async Task A_code_presented_by_another_client_is_not_redeemed()
    {
        var code = (await CompleteFlowAsync()).ShouldHaveIssuedCodeTo(RegisteredRedirect);

        (await RedeemAsync(code, OtherClient)).Should().BeOfType<AuthorizationCodeRedemptionResult.ClientMismatch>();
        (await RedeemAsync(code)).Should().BeOfType<AuthorizationCodeRedemptionResult.Redeemed>(
            "a mismatch does not consume the code, so the client it was issued to can still redeem it");
    }

    // ── When the store fails ──────────────────────────────────────────────────────────────────

    [Fact]
    public async Task A_store_failure_answers_the_client_with_server_error_and_discards_the_interaction()
    {
        using var factory = NewFactory(configureStores: builder => builder
            .AddAuthorizationCodeStore<FailingBackingStore>()
            .AddInMemoryRefreshTokenStore(allowOutsideDevelopment: true));
        using var client = NewClient(factory);
        var query = ValidQuery();
        query["state"] = "opaque-client-state";
        var interactionId = await ReachConsentAsync(client, query);

        var response = await GrantAsync(client, interactionId, "openid");

        response.StatusCode.Should().Be(HttpStatusCode.Redirect);
        DestinationOf(response).Should().Be(RegisteredRedirect);
        var parameters = RedirectQueryOf(response);
        parameters["error"].Should().Equal(["server_error"]);
        parameters["state"].Should().Equal(["opaque-client-state"]);
        parameters["iss"].Should().Equal(["https://test.example.com"]);
        parameters.Should().NotContainKey("code", "nothing was stored, so nothing is handed out");
        _logs.Entries.Should().Contain(entry => entry.Level == LogLevel.Error && entry.Message.Contains(ConsentingClient, StringComparison.Ordinal));
        var replay = async () => await GrantAsync(client, interactionId, "openid");
        await replay.Should().ThrowAsync<ZeeKayDaInteractionException>("a request that failed at issuance is not resumed");
    }

    // ── Preconditions the callers establish ───────────────────────────────────────────────────

    [Fact]
    public async Task Issuance_for_a_context_that_was_never_authenticated_is_a_caller_error()
    {
        // No path through the flow reaches issuance without a session on the context; a future
        // one that did would fail here rather than issue a code bound to nobody.
        var issuer = _factory.Services.GetRequiredService<AuthorizationCodeIssuer>();
        var context = new DefaultHttpContext { RequestServices = _factory.Services };

        var issue = async () => await issuer.IssueAsync(context, UnauthenticatedContext(), TrustedRegistration());

        await issue.Should().ThrowAsync<InvalidOperationException>().WithMessage("*not been authenticated*");
    }

    [Fact]
    public async Task Issuance_for_a_consent_requiring_client_without_a_decision_is_a_caller_error()
    {
        // The dispatch sends a consent-requiring client to the page and the page records the
        // decision; issuance refuses to assume one.
        var issuer = _factory.Services.GetRequiredService<AuthorizationCodeIssuer>();
        var context = new DefaultHttpContext { RequestServices = _factory.Services };
        var authenticated = UnauthenticatedContext() with { SsoSessionId = "session-1", Subject = "user-1", AuthTime = Now };

        var issue = async () => await issuer.IssueAsync(context, authenticated, ConsentingRegistration());

        await issue.Should().ThrowAsync<InvalidOperationException>().WithMessage("*consent decision*");
    }

    private static AuthorizationRequestContext UnauthenticatedContext() => new()
    {
        Id = StoreKeyGenerator.Generate(),
        ClientId = ConsentingClient,
        RedirectUri = RegisteredRedirect,
        Scopes = ["openid", "profile"],
        State = null,
        Nonce = Nonce,
        CodeChallenge = Challenge,
        CodeChallengeMethod = CodeChallengeMethod.S256,
        Prompts = new HashSet<PromptValue>(),
        MaxAge = null,
        IssuedAt = Now,
        ExpiresAt = Now + TimeSpan.FromMinutes(10),
    };

    /// <summary>A backing store whose every write fails, as an unreachable cache would.</summary>
    private sealed class FailingBackingStore : IAuthorizationCodeBackingStore
    {
        public ValueTask<bool> TryInsertAsync(StoreKey key, ReadOnlyMemory<byte> value, DateTimeOffset expiresAt, CancellationToken cancellationToken) =>
            throw new IOException("The cache is unreachable.");

        public ValueTask<ReadOnlyMemory<byte>?> GetAsync(StoreKey key, CancellationToken cancellationToken) =>
            new((ReadOnlyMemory<byte>?)null);

        public ValueTask RemoveAsync(StoreKey key, CancellationToken cancellationToken) => ValueTask.CompletedTask;
    }

    /// <summary>A repository holding one registration an operator can change mid-flow.</summary>
    private sealed class MutableClientRepository(IClientRegistration initial) : IClientRepository
    {
        public IClientRegistration? Current { get; set; } = initial;

        public ValueTask<IClientRegistration?> FindByClientIdAsync(string clientId, CancellationToken cancellationToken = default) =>
            new(Current is { } current && string.Equals(current.ClientId, clientId, StringComparison.Ordinal) ? current : null);
    }

    /// <summary>Captures every log entry the host writes, after the framework's redaction.</summary>
    private sealed class CapturingLoggerProvider : ILoggerProvider
    {
        private readonly List<(LogLevel Level, string Message)> _entries = [];

        public IReadOnlyList<(LogLevel Level, string Message)> Entries
        {
            get { lock (_entries) return [.. _entries]; }
        }

        public ILogger CreateLogger(string categoryName) => new Logger(this);

        public void Dispose()
        {
        }

        private void Add(LogLevel level, string message)
        {
            lock (_entries) _entries.Add((level, message));
        }

        private sealed class Logger(CapturingLoggerProvider owner) : ILogger
        {
            public IDisposable? BeginScope<TState>(TState state) where TState : notnull => null;

            public bool IsEnabled(LogLevel logLevel) => true;

            public void Log<TState>(LogLevel logLevel, EventId eventId, TState state, Exception? exception, Func<TState, Exception?, string> formatter) =>
                owner.Add(logLevel, formatter(state, exception));
        }
    }
}
