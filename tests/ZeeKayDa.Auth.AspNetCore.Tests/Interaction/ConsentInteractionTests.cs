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
using Microsoft.Extensions.Primitives;
using Microsoft.Extensions.Time.Testing;
using ZeeKayDa.Auth.AspNetCore.Interaction;
using ZeeKayDa.Auth.Authorization;
using ZeeKayDa.Auth.Clients;

namespace ZeeKayDa.Auth.AspNetCore.Tests.Interaction;

/// <summary>
/// Integration tests for the handoff to the host's consent page and back: when the framework
/// asks, what it asks, and the bindings that decide who may answer.
/// </summary>
/// <remarks>
/// The test host maps a consent page written exactly as a real one would be — a GET that reads
/// <see cref="IConsentInteraction.GetRequestAsync"/> and a POST that ends in
/// <see cref="IConsentInteraction.GrantAsync"/> or <see cref="IConsentInteraction.DenyAsync"/> —
/// plus probes that report what the encrypted session and interaction cookies carry, since
/// nothing else can observe them.
/// </remarks>
public sealed class ConsentInteractionTests : IDisposable
{
    private const string RegisteredRedirect = "https://test.example.com/callback";
    private const string Challenge = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM";
    private const string LoginPath = "/account/login";
    private const string ConsentPath = FlowAssertions.ConsentPath;
    private const string SignOutPath = "/account/sign-out";
    private const string GrantByLinkPath = "/account/consent/grant-by-link";
    private const string DenyByLinkPath = "/account/consent/deny-by-link";
    private const string GrantThenReturnPath = "/account/consent/grant-then-return";
    private const string DenyThenReturnPath = "/account/consent/deny-then-return";
    private const string HijackTarget = "https://attacker.example.net/collect";
    private const string ConsentingClient = "consenting-client";
    private const string TrustedClient = "trusted-client";

    private static readonly DateTimeOffset Now = new(2026, 9, 5, 12, 0, 0, TimeSpan.Zero);

    private readonly FakeTimeProvider _time = new(Now);
    private readonly CapturingLoggerProvider _logs = new();
    private readonly TestWebAppFactory _factory;
    private readonly HttpClient _client;

    public ConsentInteractionTests()
    {
        _factory = NewFactory(ConsentPath);
        _client = NewClient(_factory);
    }

    public void Dispose()
    {
        _client.Dispose();
        _factory.Dispose();
    }

    private static CancellationToken Cancellation => TestContext.Current.CancellationToken;

    private TestWebAppFactory NewFactory(string? consentPath, IClientRepository? repository = null) => new(
        configureOptions: options => options.AuthorizationEndpoint.Interaction.ConsentPath = consentPath,
        configureBuilder: builder =>
        {
            builder.Services.AddSingleton<TimeProvider>(_time);
            builder.Services.AddLogging(logging => logging.AddProvider(_logs));
            builder.AddInMemoryClients(clients => clients
                .Add(ConsentingRegistration())
                .Add(TrustedRegistration()));

            // Registered after AddInMemoryClients, so it wins resolution rather than tripping the
            // guard against a repository registered before it.
            if (repository is not null)
                builder.Services.AddSingleton(repository);
        },
        mapEndpoints: MapHostPages);

    private static ClientRegistration ConsentingRegistration()
    {
        var client = ClientRegistration.CreatePublic(ConsentingClient, [RegisteredRedirect], [], ["openid", "profile", "email"]);
        return client with { DisplayName = "Example App" };
    }

    /// <summary>A first-party client the operator chose to exempt from consent.</summary>
    private static ClientRegistration TrustedRegistration()
    {
        var client = ClientRegistration.CreatePublic(TrustedClient, [RegisteredRedirect], [], ["openid", "profile"]);
        return client with { RequireConsent = false };
    }

    private static HttpClient NewClient(TestWebAppFactory factory, bool handleCookies = true) => factory.CreateClient(new()
    {
        BaseAddress = new Uri("https://test.example.com"),
        AllowAutoRedirect = false,
        HandleCookies = handleCookies,
    });

    /// <summary>The host's pages: sign-in, the consent page, a sign-out, and two probes.</summary>
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

        // The consent page, exactly as the issue's sample host writes it: the GET renders what
        // the framework says to ask, the POST hands back the boxes the user ticked.
        endpoints.MapGet(ConsentPath, async (HttpContext context, IConsentInteraction consent) =>
        {
            // A host with a content security policy of its own sets it as it always did.
            context.Response.Headers.Append("Content-Security-Policy", "default-src 'self'");

            var request = await consent.GetRequestAsync(context.RequestAborted);

            return Results.Ok(new
            {
                clientId = request.Client.ClientId,
                displayName = request.Client.DisplayName,
                scopes = request.Scopes,
                subject = request.Subject,
            });
        });

        endpoints.MapPost(ConsentPath, async (HttpContext context, IConsentInteraction consent) =>
        {
            var form = await context.Request.ReadFormAsync(context.RequestAborted);

            if (form["action"].FirstOrDefault() == "deny")
                await consent.DenyAsync();
            else
                await consent.GrantAsync(form["scope"].Select(scope => scope ?? string.Empty));
        });

        // Pages wired the way the XML docs say not to: a decision taken from the request that
        // renders the page, which is the request the framework itself arrives with.
        endpoints.MapGet(GrantByLinkPath, (IConsentInteraction consent) => consent.GrantAsync(["openid"]));
        endpoints.MapGet(DenyByLinkPath, (IConsentInteraction consent) => consent.DenyAsync());

        // Pages that do the thing the XML docs tell hosts not to do: call a terminal method and
        // then return a result of their own.
        endpoints.MapPost(GrantThenReturnPath, async (IConsentInteraction consent) =>
        {
            await consent.GrantAsync(["openid"]);
            return Results.Redirect(HijackTarget);
        });

        endpoints.MapPost(DenyThenReturnPath, async (IConsentInteraction consent) =>
        {
            await consent.DenyAsync();
            return Results.Redirect(HijackTarget);
        });

        // A host's own sign-out: ends the SSO session and nothing else.
        endpoints.MapPost(SignOutPath, (HttpContext context) => context.SignOutAsync(ZeeKayDaCookies.Session));

        endpoints.MapGet("/test/session", async (HttpContext context) =>
        {
            var result = await context.AuthenticateAsync(ZeeKayDaCookies.Session);

            return result.Succeeded
                ? Results.Ok(new { sub = result.Principal!.FindFirstValue("sub") })
                : Results.NotFound();
        });

        endpoints.MapGet("/test/interaction", (HttpContext context, AuthorizationFlow flow) =>
            flow.Read(context) is { } requestContext
                ? Results.Ok(new { grantedScopes = requestContext.GrantedScopes, consentedAt = requestContext.ConsentedAt })
                : Results.NotFound());
    }

    private static Dictionary<string, string?> ValidQuery(string clientId = ConsentingClient, string scope = "openid profile email") => new()
    {
        ["client_id"] = clientId,
        ["redirect_uri"] = RegisteredRedirect,
        ["response_type"] = "code",
        ["scope"] = scope,
        ["nonce"] = "n-0S6_WzA2Mj",
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

    private static string WithInteractionId(string path, string? interactionId) =>
        interactionId is null
            ? path
            : QueryHelpers.AddQueryString(path, InteractionHandoff.InteractionIdParameter, interactionId);

    private static FormUrlEncodedContent Form(params (string Key, string Value)[] fields) =>
        new(fields.Select(field => KeyValuePair.Create(field.Key, field.Value)));

    private Task<HttpResponseMessage> PostLoginAsync(string? interactionId, string sub = "user-1") =>
        PostLoginAsync(_client, interactionId, sub);

    private static async Task<HttpResponseMessage> PostLoginAsync(HttpClient client, string? interactionId, string sub = "user-1")
    {
        using var content = Form(("sub", sub));
        return await client.PostAsync(WithInteractionId(LoginPath, interactionId), content, Cancellation);
    }

    /// <summary>Runs authorize → login → consent handoff, returning the sign-in response that made the handoff.</summary>
    private async Task<HttpResponseMessage> ReachConsentAsync(Dictionary<string, string?>? query = null, string sub = "user-1")
    {
        var handoff = await AuthorizeAsync(query);
        var signIn = await PostLoginAsync(InteractionIdFrom(handoff), sub);
        signIn.ShouldHaveReachedConsent();

        return signIn;
    }

    private Task<HttpResponseMessage> GetConsentPageAsync(string? interactionId) =>
        _client.GetAsync(WithInteractionId(ConsentPath, interactionId), Cancellation);

    private async Task<JsonElement> ReadConsentPageAsync(string interactionId)
    {
        var response = await GetConsentPageAsync(interactionId);
        response.StatusCode.Should().Be(HttpStatusCode.OK);

        return await ReadJsonAsync(response);
    }

    private async Task<HttpResponseMessage> PostConsentAsync(string? interactionId, params (string Key, string Value)[] fields)
    {
        using var content = Form(fields);
        return await _client.PostAsync(WithInteractionId(ConsentPath, interactionId), content, Cancellation);
    }

    private Task<HttpResponseMessage> GrantAsync(string? interactionId, params string[] scopes) =>
        PostConsentAsync(interactionId, [.. scopes.Select(scope => ("scope", scope))]);

    private Task<HttpResponseMessage> DenyAsync(string? interactionId) =>
        PostConsentAsync(interactionId, ("action", "deny"));

    private static async Task<JsonElement> ReadJsonAsync(HttpResponseMessage response)
    {
        var body = await response.Content.ReadAsStringAsync(Cancellation);
        return JsonDocument.Parse(body).RootElement.Clone();
    }

    private async Task<JsonElement?> ReadInteractionAsync()
    {
        var response = await _client.GetAsync("/test/interaction", Cancellation);
        return response.StatusCode == HttpStatusCode.NotFound ? null : await ReadJsonAsync(response);
    }

    private async Task<string?> ReadSessionSubjectAsync()
    {
        var response = await _client.GetAsync("/test/session", Cancellation);
        return response.StatusCode == HttpStatusCode.NotFound
            ? null
            : (await ReadJsonAsync(response)).GetProperty("sub").GetString();
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

    /// <summary>
    /// The <c>name=value</c> pairs a response set for cookies whose name starts with
    /// <paramref name="prefix"/>, deletions excluded — the interaction cookie may be chunked.
    /// </summary>
    private static string[] CookiesFrom(HttpResponseMessage response, string prefix) =>
        [.. response.Headers.GetValues("Set-Cookie")
            .Select(header => header[..header.IndexOf(';')])
            .Where(pair => pair.StartsWith(prefix, StringComparison.Ordinal) && !pair.EndsWith('='))];

    // ── The handoff ───────────────────────────────────────────────────────────────────────────

    [Fact]
    public async Task After_sign_in_the_user_is_sent_to_the_consent_page_carrying_the_same_interaction_id()
    {
        var handoff = await AuthorizeAsync();
        var interactionId = InteractionIdFrom(handoff);

        var signIn = await PostLoginAsync(interactionId);

        signIn.ShouldHaveReachedConsent();
        InteractionIdFrom(signIn).Should().Be(interactionId);
    }

    [Fact]
    public async Task A_request_an_existing_session_answers_for_goes_straight_to_the_consent_page()
    {
        await ReachConsentAsync();

        var response = await AuthorizeAsync();

        response.ShouldHaveReachedConsent("there is no sign-in to do, and no remembered grant to skip the page on");
    }

    [Fact]
    public async Task A_client_that_does_not_require_consent_skips_the_page()
    {
        var handoff = await AuthorizeAsync(ValidQuery(TrustedClient, "openid profile"));

        var signIn = await PostLoginAsync(InteractionIdFrom(handoff));

        signIn.ShouldHaveIssuedCodeTo(RegisteredRedirect, "the request goes straight to code issuance");
    }

    [Fact]
    public async Task A_host_with_no_consent_page_answers_the_client_with_server_error_and_logs_the_gap()
    {
        using var factory = NewFactory(consentPath: null);
        using var client = NewClient(factory);
        var handoff = await AuthorizeAsync(client);

        var signIn = await PostLoginAsync(client, InteractionIdFrom(handoff));

        signIn.StatusCode.Should().Be(HttpStatusCode.Redirect);
        DestinationOf(signIn).Should().Be(RegisteredRedirect);
        RedirectQueryOf(signIn)["error"].Should().Equal(["server_error"]);
        _logs.Entries.Should().Contain(entry =>
            entry.Level == LogLevel.Error && entry.Message.Contains("ConsentPath", StringComparison.Ordinal),
            "a developer finds a configuration gap in the log, not by reading the client's error page");
    }

    [Fact]
    public async Task A_host_with_no_consent_page_still_serves_a_client_that_does_not_require_consent()
    {
        // Whether the page is needed depends on the clients, which is why there is no startup
        // check for it: a host whose clients all skip consent is correctly configured without one.
        using var factory = NewFactory(consentPath: null);
        using var client = NewClient(factory);
        var handoff = await AuthorizeAsync(client, ValidQuery(TrustedClient, "openid profile"));

        var signIn = await PostLoginAsync(client, InteractionIdFrom(handoff));

        signIn.ShouldHaveIssuedCodeTo(RegisteredRedirect);
    }

    [Fact]
    public async Task A_client_removed_after_the_request_was_accepted_renders_locally()
    {
        // The redirect URI was authenticated against a registration that no longer answers, so
        // the request ends at the local error page rather than being sent there.
        var repository = new MutableClientRepository(ConsentingRegistration());
        using var factory = NewFactory(ConsentPath, repository);
        using var client = NewClient(factory);
        var handoff = await AuthorizeAsync(client);

        repository.Current = null;
        var signIn = await PostLoginAsync(client, InteractionIdFrom(handoff));

        signIn.StatusCode.Should().Be(HttpStatusCode.BadRequest);
        signIn.Headers.Location.Should().BeNull();
        (await signIn.Content.ReadAsStringAsync(Cancellation)).Should().Contain("invalid_request");
    }

    [Fact]
    public async Task A_request_whose_redirect_uri_was_removed_from_the_registration_renders_locally()
    {
        // The operator removed the URI the request was accepted with while keeping the client.
        // Nothing — an error included — is sent to a URI the registration no longer vouches for.
        var repository = new MutableClientRepository(ConsentingRegistration());
        using var factory = NewFactory(ConsentPath, repository);
        using var client = NewClient(factory);
        var handoff = await AuthorizeAsync(client);

        repository.Current = WithOtherRedirectUri(ConsentingRegistration());
        var signIn = await PostLoginAsync(client, InteractionIdFrom(handoff));

        signIn.StatusCode.Should().Be(HttpStatusCode.BadRequest);
        signIn.Headers.Location.Should().BeNull();
    }

    private static ClientRegistration WithOtherRedirectUri(ClientRegistration registration) =>
        registration with
        {
            RedirectUris = new HashSet<string>(StringComparer.Ordinal) { "https://test.example.com/elsewhere" },
        };

    // ── What the page is told to ask ──────────────────────────────────────────────────────────

    [Fact]
    public async Task GetRequestAsync_reports_the_client_the_effective_scopes_and_the_subject()
    {
        // "admin" is not among the client's allowed scopes, so it is narrowed away before the
        // page ever sees the request; the rest arrive in request order.
        var signIn = await ReachConsentAsync(ValidQuery(scope: "openid admin email profile"), sub: "alice");

        var page = await ReadConsentPageAsync(InteractionIdFrom(signIn));

        page.GetProperty("clientId").GetString().Should().Be(ConsentingClient);
        page.GetProperty("displayName").GetString().Should().Be("Example App");
        page.GetProperty("scopes").EnumerateArray().Select(scope => scope.GetString())
            .Should().Equal("openid", "email", "profile");
        page.GetProperty("subject").GetString().Should().Be("alice");
    }

    [Fact]
    public async Task GetRequestAsync_reports_no_display_name_for_a_registration_without_one()
    {
        var signIn = await ReachConsentAsync(ValidQuery("test-client", "openid"));

        var page = await ReadConsentPageAsync(InteractionIdFrom(signIn));

        page.GetProperty("clientId").GetString().Should().Be("test-client");
        page.GetProperty("displayName").ValueKind.Should().Be(JsonValueKind.Null,
            "the page falls back to the client id itself; the framework invents nothing");
    }

    [Fact]
    public async Task Every_consent_operation_for_a_client_removed_after_the_handoff_is_refused()
    {
        // The registration is read again at every consent call. A client removed since the
        // handoff has no page worth rendering and no redirect URI anyone vouches for any more, so
        // nothing is rendered, granted, or sent there.
        var repository = new MutableClientRepository(ConsentingRegistration());
        using var factory = NewFactory(ConsentPath, repository);
        using var client = NewClient(factory);
        var handoff = await AuthorizeAsync(client);
        var signIn = await PostLoginAsync(client, InteractionIdFrom(handoff));
        signIn.ShouldHaveReachedConsent();

        repository.Current = null;

        await EveryConsentOperationIsRefusedAsync(client, InteractionIdFrom(signIn));
    }

    [Fact]
    public async Task Every_consent_operation_for_a_client_that_dropped_the_redirect_uri_is_refused()
    {
        // The client still exists, but the URI the request was accepted with is no longer its. A
        // deny sent there would hand the authorization response to whoever holds it now.
        var repository = new MutableClientRepository(ConsentingRegistration());
        using var factory = NewFactory(ConsentPath, repository);
        using var client = NewClient(factory);
        var handoff = await AuthorizeAsync(client);
        var signIn = await PostLoginAsync(client, InteractionIdFrom(handoff));
        signIn.ShouldHaveReachedConsent();

        repository.Current = WithOtherRedirectUri(ConsentingRegistration());

        await EveryConsentOperationIsRefusedAsync(client, InteractionIdFrom(signIn));
    }

    /// <summary>
    /// The read, the grant and the deny all throw, nothing is redirected anywhere, and the
    /// interaction is left exactly where it was.
    /// </summary>
    private static async Task EveryConsentOperationIsRefusedAsync(HttpClient client, string interactionId)
    {
        var url = WithInteractionId(ConsentPath, interactionId);
        using var grantForm = Form(("scope", "openid"));
        using var denyForm = Form(("action", "deny"));

        var read = async () => await client.GetAsync(url, Cancellation);
        await read.Should().ThrowAsync<ZeeKayDaInteractionException>();
        var grant = async () => await client.PostAsync(url, grantForm, Cancellation);
        await grant.Should().ThrowAsync<ZeeKayDaInteractionException>();
        var deny = async () => await client.PostAsync(url, denyForm, Cancellation);
        await deny.Should().ThrowAsync<ZeeKayDaInteractionException>();

        var probe = await client.GetAsync("/test/interaction", Cancellation);
        probe.StatusCode.Should().Be(HttpStatusCode.OK, "a refused call leaves the interaction where it was");
    }

    [Fact]
    public async Task GetRequestAsync_makes_the_rendered_page_unframeable_and_uncacheable()
    {
        // The page takes a one-click decision, so an attacker who can frame it can steer that
        // click. No consent page renders without this call, which is what makes the stamp a
        // guarantee — alongside a policy the host set itself, not instead of it.
        var signIn = await ReachConsentAsync();

        var response = await GetConsentPageAsync(InteractionIdFrom(signIn));

        response.StatusCode.Should().Be(HttpStatusCode.OK);
        response.Headers.GetValues("Content-Security-Policy")
            .Should().BeEquivalentTo(["default-src 'self'", "frame-ancestors 'none'"]);
        response.Headers.GetValues("X-Frame-Options").Should().Equal("DENY");
        response.Headers.CacheControl!.NoStore.Should().BeTrue();
    }

    [Fact]
    public async Task GetRequestAsync_without_an_interaction_id_is_refused()
    {
        await ReachConsentAsync();

        var read = async () => await GetConsentPageAsync(interactionId: null);

        await read.Should().ThrowAsync<ZeeKayDaInteractionException>();
    }

    [Fact]
    public async Task GetRequestAsync_before_the_user_has_signed_in_is_refused()
    {
        // The consent page reached with a valid interaction id but no sign-in behind it: there
        // is nobody to ask yet, so there is nothing to render.
        var handoff = await AuthorizeAsync();

        var read = async () => await GetConsentPageAsync(InteractionIdFrom(handoff));

        await read.Should().ThrowAsync<ZeeKayDaInteractionException>();
    }

    // ── Granting ──────────────────────────────────────────────────────────────────────────────

    [Fact]
    public async Task GrantAsync_ends_the_request_with_a_code_and_discards_the_interaction()
    {
        // What the code carries is AuthorizationCodeIssuanceTests' subject; here, that a grant
        // is the end of the interaction rather than a decision left on it for later.
        var signIn = await ReachConsentAsync();

        var grant = await GrantAsync(InteractionIdFrom(signIn), "openid", "profile");

        grant.ShouldHaveIssuedCodeTo(RegisteredRedirect);
        (await ReadInteractionAsync()).Should().BeNull("the decision is taken and the code issued in the one response");
    }

    [Fact]
    public async Task A_second_sign_in_after_a_grant_finds_no_interaction_to_complete()
    {
        // The login page stays answerable after the consent handoff, so a second user could sign
        // in on the same interaction. Once a grant has ended it, there is nothing for them to
        // complete, and the first user's decision cannot ride along into theirs.
        var signIn = await ReachConsentAsync(sub: "user-1");
        var interactionId = InteractionIdFrom(signIn);
        (await GrantAsync(interactionId, "openid")).ShouldHaveIssuedCodeTo(RegisteredRedirect);

        var reSignIn = async () => await PostLoginAsync(interactionId, sub: "user-2");

        await reSignIn.Should().ThrowAsync<ZeeKayDaInteractionException>();
    }

    [Fact]
    public async Task GrantAsync_without_openid_answers_the_client_with_access_denied()
    {
        var query = ValidQuery();
        query["state"] = "opaque-client-state";
        var signIn = await ReachConsentAsync(query);

        var grant = await GrantAsync(InteractionIdFrom(signIn), "profile", "email");

        grant.StatusCode.Should().Be(HttpStatusCode.Redirect);
        DestinationOf(grant).Should().Be(RegisteredRedirect);
        var parameters = RedirectQueryOf(grant);
        parameters["error"].Should().Equal(["access_denied"]);
        parameters["error_description"].ToString().Should().Contain("identified");
        parameters["state"].Should().Equal(["opaque-client-state"]);
        parameters["iss"].Should().Equal(["https://test.example.com"]);
        (await ReadInteractionAsync()).Should().BeNull("a refused request is not resumed later");
    }

    [Fact]
    public async Task GrantAsync_with_a_blank_scope_entry_is_refused_as_an_argument_error()
    {
        var signIn = await ReachConsentAsync();

        var grant = async () => await GrantAsync(InteractionIdFrom(signIn), "openid", "");

        await grant.Should().ThrowAsync<ArgumentException>();
    }

    [Fact]
    public async Task GrantAsync_without_an_interaction_id_is_refused()
    {
        await ReachConsentAsync();

        var grant = async () => await GrantAsync(interactionId: null, "openid");

        await grant.Should().ThrowAsync<ZeeKayDaInteractionException>();
    }

    [Fact]
    public async Task GrantAsync_naming_an_interaction_the_browser_is_not_carrying_is_refused()
    {
        // Two tabs: the second authorization request replaced the first's context. Completing
        // the first would record consent for a request the browser no longer holds.
        var firstTab = await ReachConsentAsync();
        await AuthorizeAsync();

        var grant = async () => await GrantAsync(InteractionIdFrom(firstTab), "openid");

        await grant.Should().ThrowAsync<ZeeKayDaInteractionException>();
    }

    [Fact]
    public async Task GrantAsync_after_the_interaction_has_expired_is_refused()
    {
        var signIn = await ReachConsentAsync();
        var interactionId = InteractionIdFrom(signIn);

        _time.Advance(TimeSpan.FromMinutes(31));

        var grant = async () => await GrantAsync(interactionId, "openid");

        await grant.Should().ThrowAsync<ZeeKayDaInteractionException>();
    }

    [Fact]
    public async Task GrantAsync_after_the_user_signed_out_is_refused()
    {
        var signIn = await ReachConsentAsync();
        using var content = Form();
        await _client.PostAsync(SignOutPath, content, Cancellation);

        var grant = async () => await GrantAsync(InteractionIdFrom(signIn), "openid");

        await grant.Should().ThrowAsync<ZeeKayDaInteractionException>(
            "consent is recorded by the user it was asked of, and nobody is signed in any more");
    }

    [Fact]
    public async Task GrantAsync_by_a_session_other_than_the_one_that_signed_in_is_refused()
    {
        // The interaction context names the session that authenticated it. A browser presenting
        // that context with a different user's session cookie — the shape of a session swapped
        // underneath a half-answered consent page — must not be able to answer for the first.
        var firstSignIn = await ReachConsentAsync(sub: "user-1");
        var firstSession = CookiesFrom(firstSignIn, ZeeKayDaCookies.Session).Single();

        var query = ValidQuery();
        query["prompt"] = "login";
        var secondHandoff = await AuthorizeAsync(query);
        var secondSignIn = await PostLoginAsync(InteractionIdFrom(secondHandoff), sub: "user-2");
        secondSignIn.ShouldHaveReachedConsent();
        var secondInteraction = CookiesFrom(secondSignIn, ZeeKayDaCookies.Interaction);
        var secondSession = CookiesFrom(secondSignIn, ZeeKayDaCookies.Session).Single();
        var url = WithInteractionId(ConsentPath, InteractionIdFrom(secondSignIn));

        using var raw = NewClient(_factory, handleCookies: false);

        var grant = async () => await raw.SendAsync(GrantRequest(url, [.. secondInteraction, firstSession]), Cancellation);
        await grant.Should().ThrowAsync<ZeeKayDaInteractionException>();

        // The control: the same request under the session that did sign in is accepted, so the
        // refusal above is the binding and not the hand-built cookie header.
        var control = await raw.SendAsync(GrantRequest(url, [.. secondInteraction, secondSession]), Cancellation);
        control.ShouldHaveIssuedCodeTo(RegisteredRedirect);
    }

    private static HttpRequestMessage GrantRequest(string url, IEnumerable<string> cookies)
    {
        var request = new HttpRequestMessage(HttpMethod.Post, url) { Content = Form(("scope", "openid")) };
        request.Headers.Add("Cookie", string.Join("; ", cookies));

        return request;
    }

    // ── Denying ───────────────────────────────────────────────────────────────────────────────

    [Fact]
    public async Task DenyAsync_answers_the_client_with_access_denied_naming_the_consent_page()
    {
        var query = ValidQuery();
        query["state"] = "opaque-client-state";
        var signIn = await ReachConsentAsync(query);

        var deny = await DenyAsync(InteractionIdFrom(signIn));

        deny.StatusCode.Should().Be(HttpStatusCode.Redirect);
        DestinationOf(deny).Should().Be(RegisteredRedirect);
        var parameters = RedirectQueryOf(deny);
        parameters["error"].Should().Equal(["access_denied"]);
        parameters["error_description"].ToString().Should().Contain("consent page",
            "the description names the stage so a client can tell a declined consent from a cancelled sign-in");
        parameters["state"].Should().Equal(["opaque-client-state"]);
        parameters["iss"].Should().Equal(["https://test.example.com"]);
    }

    [Fact]
    public async Task DenyAsync_leaves_the_session_alone_and_discards_the_interaction()
    {
        var signIn = await ReachConsentAsync(sub: "alice");
        var interactionId = InteractionIdFrom(signIn);

        await DenyAsync(interactionId);

        (await ReadSessionSubjectAsync()).Should().Be("alice", "declining one client does not sign the user out");
        (await ReadInteractionAsync()).Should().BeNull();
        var grant = async () => await GrantAsync(interactionId, "openid");
        await grant.Should().ThrowAsync<ZeeKayDaInteractionException>("a declined request cannot be resumed");
    }

    [Fact]
    public async Task DenyAsync_without_an_interaction_id_is_refused()
    {
        await ReachConsentAsync();

        var deny = async () => await DenyAsync(interactionId: null);

        await deny.Should().ThrowAsync<ZeeKayDaInteractionException>();
    }

    [Fact]
    public async Task DenyAsync_before_the_user_has_signed_in_is_refused()
    {
        // A deny aimed at an interaction nobody has signed in for: the sign-in page's cancel is
        // the tool for that, and it is bound to the same identifier.
        var handoff = await AuthorizeAsync();

        var deny = async () => await DenyAsync(InteractionIdFrom(handoff));

        await deny.Should().ThrowAsync<ZeeKayDaInteractionException>();
    }

    // ── A decision comes only from a form post ────────────────────────────────────────────────

    [Theory]
    [InlineData(GrantByLinkPath)]
    [InlineData(DenyByLinkPath)]
    public async Task A_decision_taken_from_a_GET_is_refused_and_changes_nothing(string path)
    {
        // The framework redirects to the consent page with a GET. A page that granted in its
        // render handler would consent to every request the moment the user arrived, with no
        // action of theirs — the immediate seeding attack, reopened by a wiring mistake. The
        // refusal happens before anything is read, so the interaction is still there to answer.
        var signIn = await ReachConsentAsync();
        var interactionId = InteractionIdFrom(signIn);

        var byLink = async () => await _client.GetAsync(WithInteractionId(path, interactionId), Cancellation);

        await byLink.Should().ThrowAsync<InvalidOperationException>()
            .WithMessage("*POST*");
        (await ReadInteractionAsync()).Should().NotBeNull("a refused decision leaves the request alive");
        (await GrantAsync(interactionId, "openid")).ShouldHaveIssuedCodeTo(RegisteredRedirect, "the form post still completes it");
    }

    [Theory]
    [InlineData(GrantByLinkPath)]
    [InlineData(DenyByLinkPath)]
    public async Task A_decision_taken_from_a_GET_is_refused_before_any_interaction_state_is_read(string path)
    {
        // No zkd_i and no interaction at all: had the service resolved the interaction first, the
        // refusal would be the interaction one. Seeing the POST refusal instead proves the method
        // check runs before anything is read.
        var byLink = async () => await _client.GetAsync(path, Cancellation);

        await byLink.Should().ThrowAsync<InvalidOperationException>()
            .WithMessage("*POST*");
    }

    // ── A terminal method really is the last word ─────────────────────────────────────────────

    [Theory]
    [InlineData(GrantThenReturnPath)]
    [InlineData(DenyThenReturnPath)]
    public async Task A_result_returned_after_a_terminal_call_cannot_replace_the_response(string path)
    {
        var signIn = await ReachConsentAsync();

        using var content = Form();
        var post = async () => await _client.PostAsync(
            WithInteractionId(path, InteractionIdFrom(signIn)), content, Cancellation);

        var thrown = (await post.Should().ThrowAsync<Exception>()).Which;

        Causes(thrown).OfType<InvalidOperationException>()
            .Should().Contain(ex => ex.Message.Contains("already started", StringComparison.Ordinal),
                "committing the response is what stops the host's own result from landing");
    }

    /// <summary>An exception and everything it wraps, innermost included.</summary>
    private static IEnumerable<Exception> Causes(Exception exception)
    {
        for (var current = exception; current is not null; current = current.InnerException)
            yield return current;
    }

    // ── prompt=none ───────────────────────────────────────────────────────────────────────────

    [Fact]
    public async Task prompt_none_with_a_session_but_no_remembered_consent_is_refused_with_consent_required()
    {
        // prompt=none promises to show the user nothing, and the only thing that could stand in
        // for the consent page is a remembered grant — which nothing records yet.
        await ReachConsentAsync();

        var query = ValidQuery();
        query["prompt"] = "none";
        var response = await AuthorizeAsync(query);

        response.StatusCode.Should().Be(HttpStatusCode.Redirect);
        DestinationOf(response).Should().Be(RegisteredRedirect);
        RedirectQueryOf(response)["error"].Should().Equal(["consent_required"]);
        (await ReadInteractionAsync()).Should().BeNull("a refused request is not left behind for a later sign-in");
    }

    [Fact]
    public async Task prompt_consent_sends_even_an_opt_out_client_to_the_consent_page()
    {
        // The server should prompt when asked to (OIDC Core §3.1.2.1), whatever the registration
        // says about the ordinary case.
        var query = ValidQuery(TrustedClient, "openid profile");
        query["prompt"] = "consent";
        var handoff = await AuthorizeAsync(query);

        var signIn = await PostLoginAsync(InteractionIdFrom(handoff));

        signIn.ShouldHaveReachedConsent();
        var page = await ReadConsentPageAsync(InteractionIdFrom(signIn));
        page.GetProperty("clientId").GetString().Should().Be(TrustedClient);
    }

    [Fact]
    public async Task prompt_consent_for_an_opt_out_client_on_a_host_with_no_consent_page_answers_consent_required()
    {
        // A host whose clients all opt out is correctly configured without a page; a client that
        // asks for one anyway is told it cannot be obtained, and nothing is logged as a gap.
        using var factory = NewFactory(consentPath: null);
        using var client = NewClient(factory);
        var query = ValidQuery(TrustedClient, "openid profile");
        query["prompt"] = "consent";
        var handoff = await AuthorizeAsync(client, query);

        var signIn = await PostLoginAsync(client, InteractionIdFrom(handoff));

        signIn.StatusCode.Should().Be(HttpStatusCode.Redirect);
        DestinationOf(signIn).Should().Be(RegisteredRedirect);
        RedirectQueryOf(signIn)["error"].Should().Equal(["consent_required"]);
        _logs.Entries.Should().NotContain(entry => entry.Level == LogLevel.Error);
    }

    [Fact]
    public async Task prompt_none_for_a_client_that_does_not_require_consent_continues_without_interacting()
    {
        await ReachConsentAsync();

        var query = ValidQuery(TrustedClient, "openid profile");
        query["prompt"] = "none";

        (await AuthorizeAsync(query)).ShouldHaveIssuedCodeTo(RegisteredRedirect);
    }

    /// <summary>A repository holding one registration an operator can change or remove mid-flow.</summary>
    private sealed class MutableClientRepository(IClientRegistration initial) : IClientRepository
    {
        /// <summary>The registration as it is now; <see langword="null"/> once removed.</summary>
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
