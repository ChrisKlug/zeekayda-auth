using System.Net;
using System.Security.Claims;
using System.Text.Json;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Routing;
using Microsoft.AspNetCore.WebUtilities;
using Microsoft.Extensions.DependencyInjection;
using ZeeKayDa.Auth.AspNetCore.Interaction;
using ZeeKayDa.Auth.AspNetCore.Tests.Interaction;
using ZeeKayDa.Auth.Authorization;

namespace ZeeKayDa.Auth.AspNetCore.Tests.Endpoints;

/// <summary>
/// The parts of RP-initiated logout that still need a real host: whether the endpoint is served at
/// all, a real minted <c>id_token_hint</c> (a hand-built one would test the test rather than the
/// framework), a real authorization request in flight, and a host-authored logout page reached
/// through actual routing. The handler's own behaviour when there is no session to end, and
/// everything the framework's own confirmation page does — now that <c>ConfirmAsync</c> is
/// internal — are covered host-free in <see cref="EndSessionEndpointTests"/>.
/// </summary>
/// <remarks>
/// The test host maps a logout page written as a real one would be — a GET that reads
/// <see cref="ILogoutInteraction.GetRequestAsync"/> and a POST that ends in
/// <see cref="ILogoutInteraction.SignOutAsync"/> — for the tests that configure one, and a probe
/// that reports whether the encrypted session cookie still authenticates. Two hosts serve the
/// class: <see cref="EndSessionHostFixture"/> asks through the framework's own confirmation page,
/// and <see cref="EndSessionLogoutPageHostFixture"/> through the host's logout page.
/// </remarks>
public sealed class EndSessionEndpointHostTests
    : IClassFixture<EndSessionHostFixture>,
      IClassFixture<EndSessionLogoutPageHostFixture>,
      IClassFixture<FallbackPolicyHostFixture>
{
    internal const string LogoutPath = "/account/logout";
    internal const string SignedOutPath = "/account/signed-out";

    private const string EndSessionPath = "/connect/endsession";
    private const string ConfirmPath = "/connect/endsession/confirm";
    private const string TokenPath = "/connect/token";
    private const string LoginPath = "/account/login";
    private const string SignOutByLinkPath = "/account/logout/by-link";
    private const string SessionProbePath = "/test/session";
    private const string Redirect = "https://test.example.com/callback";
    private const string App = "app";
    private const string AppName = "Tom & Jerry <App>";
    private const string TrustedApp = "trusted-app";
    private const string OtherApp = "other-app";
    private const string AppSignedOut = "https://app.example.com/signed-out";
    private const string TrustedSignedOut = "https://trusted.example.com/signed-out";
    private const string OtherSignedOut = "https://other.example.com/signed-out";
    private const string State = "af0ifjsldkj";
    private const string Nonce = "n-0S6_WzA2Mj";

    // RFC 7636 Appendix B.
    private const string Verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
    private const string Challenge = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM";

    private readonly EndSessionHostFixture _host;
    private readonly EndSessionLogoutPageHostFixture _withLogoutPage;
    private readonly FallbackPolicyHostFixture _fallback;
    private readonly HttpClient _client;

    public EndSessionEndpointHostTests(
        EndSessionHostFixture host,
        EndSessionLogoutPageHostFixture withLogoutPage,
        FallbackPolicyHostFixture fallback)
    {
        _host = host;
        _withLogoutPage = withLogoutPage;
        _fallback = fallback;
        _host.Reset();
        _withLogoutPage.Reset();
        _client = _host.NewFlowClient();
    }

    private static CancellationToken Cancellation => TestContext.Current.CancellationToken;

    // ── No session: nothing to ask ────────────────────────────────────────────────────────────────

    [Fact]
    public async Task The_endpoint_is_not_served_on_a_host_without_the_code_grant()
    {
        using var factory = new TestWebAppFactory(options => options.GrantTypesSupported = [GrantType.ClientCredentials]);
        using var client = factory.CreateClient(new() { BaseAddress = new Uri("https://test.example.com") });

        var response = await client.GetAsync(EndSessionPath, Cancellation);

        response.StatusCode.Should().Be(HttpStatusCode.NotFound);
    }

    [Fact]
    public async Task The_endpoint_and_its_confirmation_page_are_answered_under_a_host_wide_fallback_authorization_policy()
    {
        // AllowAnonymous on both routes, proven against a host that 401s anything without it. The
        // SSO session is not the host's scheme, so the host's policy must not decide who may sign out.
        var canary = await _fallback.Client.GetAsync("/host-route", Cancellation);
        canary.StatusCode.Should().Be(HttpStatusCode.Unauthorized,
            because: "the canary must prove the fallback policy is actually in force on this host");

        var endSession = await _fallback.Client.GetAsync(EndSessionPath, Cancellation);
        var confirm = await _fallback.Client.GetAsync(ConfirmPath, Cancellation);

        endSession.StatusCode.Should().Be(HttpStatusCode.OK,
            because: "with no session to end, the framework's signed-out page is served");
        confirm.StatusCode.Should().Be(HttpStatusCode.BadRequest,
            because: "with no sign-out to confirm, the handler's own refusal comes back rather than the host's 401");
    }

    // ── With a session: the question ──────────────────────────────────────────────────────────────

    [Fact]
    public async Task A_confirmation_submitted_twice_to_a_host_page_ends_on_the_hosts_signed_out_page()
    {
        var client = _withLogoutPage.NewFlowClient();
        await SignInAsync(client);
        var asked = await EndSessionAsync(client, new());
        await PostEmptyFormAsync(client, Location(asked));

        var again = await PostEmptyFormAsync(client, Location(asked));

        again.StatusCode.Should().Be(HttpStatusCode.Redirect);
        again.Headers.Location!.OriginalString.Should().Be(SignedOutPath);
    }

    [Fact]
    public async Task Signing_out_ends_the_authorization_requests_the_browser_has_in_flight()
    {
        await SignInAsync(_client);

        // The default test client requires consent, so this request is still in flight: its
        // binding cookie names an interaction nothing has completed.
        var pending = await _client.GetAsync(AuthorizeUrl("test-client"), Cancellation);
        var interactionId = InteractionIdFrom(pending);

        var asked = await EndSessionAsync(new());
        var confirmed = await PostEmptyFormAsync(_client, Location(asked));

        SetCookieFor(confirmed, InteractionBindingCookie.NamePrefix + interactionId)
            .ToLowerInvariant().Should().Contain("expires=thu, 01 jan 1970");
    }

    [Fact]
    public async Task Without_a_session_an_authorization_request_in_flight_survives()
    {
        // Nobody is signed in, so there is nothing to end — and a browser part-way through a
        // sign-in keeps the interaction it is part-way through.
        var pending = await _client.GetAsync(AuthorizeUrl(App), Cancellation);
        var interactionId = InteractionIdFrom(pending);

        var response = await EndSessionAsync(new());

        response.StatusCode.Should().Be(HttpStatusCode.OK);
        response.Headers.Contains("Set-Cookie").Should().BeFalse();
        (await PostLoginAsync(_client, interactionId, "user-1")).ShouldHaveIssuedCodeTo(Redirect);
    }

    // ── id_token_hint ─────────────────────────────────────────────────────────────────────────────

    [Fact]
    public async Task A_valid_hint_from_a_client_that_skips_the_question_signs_out_at_once()
    {
        var idToken = await SignInForIdTokenAsync(_client, TrustedApp);

        var response = await EndSessionAsync(new()
        {
            ["id_token_hint"] = idToken,
            ["post_logout_redirect_uri"] = TrustedSignedOut,
            ["state"] = State,
        });

        Location(response).Should().Be($"{TrustedSignedOut}?state={State}");
        (await HasSessionAsync(_client)).Should().BeFalse();
    }

    [Fact]
    public async Task A_valid_hint_from_a_client_that_did_not_opt_out_is_still_asked_and_names_the_client()
    {
        var idToken = await SignInForIdTokenAsync(_client, App);

        var asked = await EndSessionAsync(new()
        {
            ["id_token_hint"] = idToken,
            ["post_logout_redirect_uri"] = AppSignedOut,
            ["state"] = State,
        });
        Location(asked).Should().StartWith(ConfirmPath);

        var confirmed = await PostEmptyFormAsync(_client, Location(asked));
        Location(confirmed).Should().Be($"{AppSignedOut}?state={State}", "the hint named the client the redirect URI was checked against");
    }

    [Fact]
    public async Task A_valid_hint_for_someone_other_than_the_signed_in_user_is_still_asked()
    {
        var idToken = await SignInForIdTokenAsync(_client, TrustedApp, subject: "user-1");
        var otherBrowser = _host.NewFlowClient();
        await SignInAsync(otherBrowser, TrustedApp, subject: "user-2");

        var asked = await EndSessionAsync(otherBrowser, new() { ["id_token_hint"] = idToken });

        Location(asked).Should().StartWith(ConfirmPath);
        (await HasSessionAsync(otherBrowser)).Should().BeTrue();
    }

    [Fact]
    public async Task A_hint_that_does_not_validate_is_ignored_rather_than_trusted()
    {
        await SignInAsync(_client, TrustedApp);

        var asked = await EndSessionAsync(new()
        {
            ["id_token_hint"] = "not.an.id-token",
            ["client_id"] = TrustedApp,
        });

        Location(asked).Should().StartWith(ConfirmPath, "only a valid hint lets a client skip the question");
    }

    [Fact]
    public async Task A_hint_issued_to_another_client_than_the_one_named_is_ignored()
    {
        var idToken = await SignInForIdTokenAsync(_client, TrustedApp);

        var asked = await EndSessionAsync(new()
        {
            ["id_token_hint"] = idToken,
            ["client_id"] = App,
            ["post_logout_redirect_uri"] = TrustedSignedOut,
        });

        // With the hint refused, the request is App's: asked, and the trusted app's redirect URI
        // is not one App registered.
        Location(asked).Should().StartWith(ConfirmPath);
        var confirmed = await PostEmptyFormAsync(_client, Location(asked));
        confirmed.StatusCode.Should().Be(HttpStatusCode.OK);
        confirmed.Headers.Location.Should().BeNull();
    }

    // ── The host's logout page ────────────────────────────────────────────────────────────────────

    [Fact]
    public async Task A_host_logout_page_reads_the_client_and_completes_the_sign_out()
    {
        var client = _withLogoutPage.NewFlowClient();
        await SignInAsync(client);

        var asked = await EndSessionAsync(client, new()
        {
            ["client_id"] = App,
            ["post_logout_redirect_uri"] = AppSignedOut,
            ["state"] = State,
        });
        Location(asked).Should().StartWith($"{LogoutPath}?{InteractionHandoff.InteractionIdParameter}=");

        var page = await client.GetAsync(Location(asked), Cancellation);
        using (var body = JsonDocument.Parse(await page.Content.ReadAsStringAsync(Cancellation)))
        {
            body.RootElement.GetProperty("clientId").GetString().Should().Be(App);
            body.RootElement.GetProperty("displayName").GetString().Should().Be(AppName);
            body.RootElement.GetProperty("subject").GetString().Should().Be("user-1");
        }

        page.Headers.GetValues("X-Frame-Options").Should().Contain("DENY");

        var confirmed = await PostEmptyFormAsync(client, Location(asked));
        Location(confirmed).Should().Be($"{AppSignedOut}?state={State}");
        (await HasSessionAsync(client)).Should().BeFalse();
    }

    [Fact]
    public async Task A_host_logout_page_reached_for_a_sign_out_naming_no_client_is_given_none()
    {
        var client = _withLogoutPage.NewFlowClient();
        await SignInAsync(client);
        var asked = await EndSessionAsync(client, new());

        var page = await client.GetAsync(Location(asked), Cancellation);

        using var body = JsonDocument.Parse(await page.Content.ReadAsStringAsync(Cancellation));
        body.RootElement.GetProperty("clientId").ValueKind.Should().Be(JsonValueKind.Null);

        // The user is still named: a sign-out nobody's client started still signs a known user out,
        // and the page has no other way to say whose session it is ending.
        body.RootElement.GetProperty("subject").GetString().Should().Be("user-1");
    }

    [Fact]
    public async Task A_host_logout_page_is_told_which_user_is_being_signed_out()
    {
        var client = _withLogoutPage.NewFlowClient();
        await SignInAsync(client, subject: "user-7");
        var asked = await EndSessionAsync(client, new() { ["client_id"] = App });

        var page = await client.GetAsync(Location(asked), Cancellation);

        // The subject of the session the sign-out was started for, stamped when the user was asked.
        // SignOutAsync refuses unless the browser still holds that same session, so the page can
        // never name one user and sign out another.
        using var body = JsonDocument.Parse(await page.Content.ReadAsStringAsync(Cancellation));
        body.RootElement.GetProperty("subject").GetString().Should().Be("user-7");
    }

    [Fact]
    public async Task A_logout_page_reloaded_after_someone_else_signed_in_discloses_no_subject()
    {
        // The sign-out carries the subject it was started for. A confirmation left open across a
        // fresh sign-in must not hand the new user the previous one's identifier — the binding
        // cookie survives a sign-in, so nothing but the session check refuses this.
        var client = _withLogoutPage.NewFlowClient();
        await SignInAsync(client, subject: "user-7");
        var asked = await EndSessionAsync(client, new() { ["client_id"] = App });

        await SignInAsync(client, App, subject: "user-8", prompt: "login");
        var reload = async () => await client.GetAsync(Location(asked), Cancellation);

        (await reload.Should().ThrowAsync<ZeeKayDaInteractionException>())
            .WithMessage("*not the one this browser holds now*");
    }

    [Fact]
    public async Task A_host_with_its_own_logout_page_serves_no_framework_confirmation_route()
    {
        var client = _withLogoutPage.NewFlowClient();

        var response = await client.GetAsync(ConfirmPath, Cancellation);

        response.StatusCode.Should().Be(HttpStatusCode.NotFound);
    }

    [Fact]
    public async Task SignOutAsync_from_a_GET_is_refused_and_signs_nobody_out()
    {
        // The framework reaches the logout page with a GET. A page that signed out in its render
        // handler would end the session the moment the user arrived, which is what the question
        // exists to prevent.
        var client = _withLogoutPage.NewFlowClient();
        await SignInAsync(client);
        var asked = await EndSessionAsync(client, new());

        var byLink = async () => await client.GetAsync(
            QueryHelpers.AddQueryString(SignOutByLinkPath, InteractionHandoff.InteractionIdParameter, InteractionIdFrom(asked)),
            Cancellation);

        await byLink.Should().ThrowAsync<InvalidOperationException>();
        (await HasSessionAsync(client)).Should().BeTrue();
    }

    [Fact]
    public async Task GetRequestAsync_without_a_sign_out_to_confirm_throws()
    {
        var client = _withLogoutPage.NewFlowClient();

        var read = async () => await client.GetAsync(LogoutPath, Cancellation);

        await read.Should().ThrowAsync<ZeeKayDaInteractionException>();
    }

    // ── Host and helpers ──────────────────────────────────────────────────────────────────────────

    /// <summary>
    /// The clients these tests sign in to: one that asks before signing out, one that opted out of
    /// the question, and one more whose redirect URI the others must not be able to use.
    /// </summary>
    internal static void AddClients(ZeeKayDaAuthBuilder builder) =>
        builder.AddInMemoryClients(clients => clients
            .AddPublic(App, [Redirect], [AppSignedOut], ["openid"], client =>
            {
                client.RequireConsent = false;
                client.DisplayName = AppName;
            })
            .AddPublic(TrustedApp, [Redirect], [TrustedSignedOut], ["openid"], client =>
            {
                client.RequireConsent = false;
                client.SkipLogoutConfirmation = true;
            })
            .AddPublic(OtherApp, [Redirect], [OtherSignedOut], ["openid"], client => client.RequireConsent = false));

    /// <summary>The host's pages: sign-in, a logout page, a miswired logout link, and a session probe.</summary>
    internal static void MapHostPages(IEndpointRouteBuilder endpoints)
    {
        endpoints.MapPost(LoginPath, async (HttpContext context, ILoginInteraction login) =>
        {
            var form = await context.Request.ReadFormAsync(context.RequestAborted);
            var subject = form["sub"].FirstOrDefault() ?? "user-1";

            await login.SignInAsync(
                new ClaimsPrincipal(new ClaimsIdentity([new Claim("sub", subject)], "test")),
                AuthenticationMethods.Password);
        });

        endpoints.MapGet(LogoutPath, async (HttpContext context, ILogoutInteraction logout) =>
        {
            var request = await logout.GetRequestAsync(context.RequestAborted);

            return Results.Ok(new
            {
                clientId = request.Client?.ClientId,
                displayName = request.Client?.DisplayName,
                subject = request.Subject,
            });
        });

        endpoints.MapPost(LogoutPath, (ILogoutInteraction logout) => logout.SignOutAsync());
        endpoints.MapGet(SignOutByLinkPath, (ILogoutInteraction logout) => logout.SignOutAsync());

        endpoints.MapGet(SessionProbePath, async (HttpContext context) =>
        {
            var result = await context.AuthenticateAsync(ZeeKayDaCookies.Session);

            return result.Succeeded ? Results.Ok() : Results.NotFound();
        });
    }

    private static string AuthorizeUrl(string clientId, string? prompt = null) =>
        QueryHelpers.AddQueryString("/connect/authorize", new Dictionary<string, string?>
        {
            ["client_id"] = clientId,
            ["redirect_uri"] = Redirect,
            ["response_type"] = "code",
            ["scope"] = "openid",
            ["nonce"] = Nonce,
            ["code_challenge"] = Challenge,
            ["code_challenge_method"] = "S256",
            ["prompt"] = prompt,
        });

    /// <summary>
    /// Signs the browser in through an authorization request for <paramref name="clientId"/>.
    /// <paramref name="prompt"/> of <c>login</c> re-authenticates over a session the browser holds.
    /// </summary>
    private static async Task<HttpResponseMessage> SignInAsync(
        HttpClient client,
        string clientId = App,
        string subject = "user-1",
        string? prompt = null)
    {
        var authorize = await client.GetAsync(AuthorizeUrl(clientId, prompt), Cancellation);
        authorize.StatusCode.Should().Be(HttpStatusCode.Redirect);

        using var form = new FormUrlEncodedContent(new Dictionary<string, string> { ["sub"] = subject });
        return await client.PostAsync(Location(authorize), form, Cancellation);
    }

    /// <summary>Completes the login page for an interaction the browser already started.</summary>
    private static async Task<HttpResponseMessage> PostLoginAsync(HttpClient client, string interactionId, string subject)
    {
        using var form = new FormUrlEncodedContent(new Dictionary<string, string> { ["sub"] = subject });

        return await client.PostAsync(
            QueryHelpers.AddQueryString(LoginPath, InteractionHandoff.InteractionIdParameter, interactionId),
            form,
            Cancellation);
    }

    /// <summary>Signs the browser in and redeems the code, for an ID token to send as a hint.</summary>
    private static async Task<string> SignInForIdTokenAsync(HttpClient client, string clientId, string subject = "user-1")
    {
        var code = (await SignInAsync(client, clientId, subject)).ShouldHaveIssuedCodeTo(Redirect);

        using var form = new FormUrlEncodedContent(new Dictionary<string, string>
        {
            ["grant_type"] = "authorization_code",
            ["code"] = code,
            ["redirect_uri"] = Redirect,
            ["client_id"] = clientId,
            ["code_verifier"] = Verifier,
        });
        var response = await client.PostAsync(TokenPath, form, Cancellation);
        var body = await response.Content.ReadAsStringAsync(Cancellation);
        response.StatusCode.Should().Be(HttpStatusCode.OK, body);

        using var document = JsonDocument.Parse(body);
        return document.RootElement.GetProperty("id_token").GetString()!;
    }

    private Task<HttpResponseMessage> EndSessionAsync(Dictionary<string, string?> parameters) =>
        EndSessionAsync(_client, parameters);

    private static Task<HttpResponseMessage> EndSessionAsync(HttpClient client, Dictionary<string, string?> parameters) =>
        client.GetAsync(QueryHelpers.AddQueryString(EndSessionPath, parameters), Cancellation);

    private static async Task<HttpResponseMessage> PostEmptyFormAsync(HttpClient client, string url)
    {
        using var content = new FormUrlEncodedContent([]);
        return await client.PostAsync(url, content, Cancellation);
    }

    private static async Task<bool> HasSessionAsync(HttpClient client) =>
        (await client.GetAsync(SessionProbePath, Cancellation)).StatusCode == HttpStatusCode.OK;

    private static string Location(HttpResponseMessage response) => response.Headers.Location!.OriginalString;

    private static string InteractionIdFrom(HttpResponseMessage response)
    {
        var location = Location(response);
        return QueryHelpers.ParseQuery(location[location.IndexOf('?')..])[InteractionHandoff.InteractionIdParameter]!;
    }

    private static string SetCookieFor(HttpResponseMessage response, string name) => response.Headers
        .GetValues("Set-Cookie")
        .Single(value => value.StartsWith(name + "=", StringComparison.Ordinal));
}
