using System.Buffers.Text;
using System.Net;
using System.Security.Claims;
using System.Text.Json;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Routing;
using Microsoft.AspNetCore.WebUtilities;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Primitives;
using ZeeKayDa.Auth.AspNetCore.Interaction;
using ZeeKayDa.Auth.AspNetCore.Tests.Interaction;
using ZeeKayDa.Auth.Authorization;

namespace ZeeKayDa.Auth.AspNetCore.Tests.Endpoints;

/// <summary>
/// An <c>id_token_hint</c> at the authorization endpoint names the only user who may answer the
/// request (OIDC Core §3.1.2.2): a browser whose session belongs to someone else gets no code for
/// them, silently or after signing in. Every hint here is a real ID token the host minted.
/// </summary>
/// <remarks>
/// The ways a hint can fail to be this server's — another issuer, an unknown key, an expired one
/// accepted — are covered with hand-signed tokens in the request validator's own tests.
/// </remarks>
public sealed class AuthorizationEndpointIdTokenHintTests : IClassFixture<IdTokenHintHostFixture>
{
    private const string LoginPath = "/account/login";
    private const string SessionProbePath = "/test/session";
    private const string TokenPath = "/connect/token";
    private const string Redirect = "https://test.example.com/callback";
    private const string App = "app";
    private const string OtherApp = "other-app";
    private const string Nonce = "n-0S6_WzA2Mj";
    private const string Alice = "alice";
    private const string Bob = "bob";

    // RFC 7636 Appendix B.
    private const string Verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
    private const string Challenge = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM";

    private readonly HttpClient _client;

    public AuthorizationEndpointIdTokenHintTests(IdTokenHintHostFixture host)
    {
        host.Reset();
        _client = host.NewFlowClient();
    }

    private static CancellationToken Cancellation => TestContext.Current.CancellationToken;

    internal static void AddClients(ZeeKayDaAuthBuilder builder) =>
        builder.AddInMemoryClients(clients => clients
            .AddPublic(App, client =>
            {
                client.RedirectUris.Add(Redirect);
                client.AllowedScopes.Add("openid");
                client.RequireConsent = false;
            })
            .AddPublic(OtherApp, client =>
            {
                client.RedirectUris.Add(Redirect);
                client.AllowedScopes.Add("openid");
                client.RequireConsent = false;
            }));

    /// <summary>The host's pages: a login form signing in whichever subject it is posted, and a session probe.</summary>
    internal static void MapHostPages(IEndpointRouteBuilder endpoints)
    {
        endpoints.MapGet(LoginPath, async (HttpContext context, LoginInteraction login) =>
        {
            var request = await login.GetRequestAsync(context.RequestAborted);

            return Results.Ok(new { requiredSubject = request.RequiredSubject });
        });

        endpoints.MapPost(LoginPath, async (HttpContext context, LoginInteraction login) =>
        {
            var form = await context.Request.ReadFormAsync(context.RequestAborted);

            await login.SignInAsync(form["sub"].Single()!, AuthenticationMethods.Password);
        });

        endpoints.MapGet(SessionProbePath, async (HttpContext context) =>
        {
            var result = await context.AuthenticateAsync(ZeeKayDaCookies.Session);

            return result.Succeeded
                ? Results.Ok(new
                {
                    sid = result.Principal!.FindFirstValue(SsoSessionClaimTypes.SessionId),
                    sub = result.Principal.FindFirstValue("sub"),
                })
                : Results.NotFound();
        });
    }

    // ── prompt=none ───────────────────────────────────────────────────────────────────────────────

    [Fact]
    public async Task Prompt_none_with_another_users_hint_while_a_session_is_held_is_refused_with_login_required()
    {
        var alicesHint = await IdTokenForAsync(Alice);
        await SignInAsync(Bob);

        var response = await AuthorizeAsync(prompt: "none", idTokenHint: alicesHint);

        var query = ErrorAtClient(response);
        query["error"].ToString().Should().Be(AuthorizeRequestErrors.LoginRequired);
        query.Should().NotContainKey("code");
    }

    [Fact]
    public async Task Prompt_none_with_the_session_users_hint_issues_a_code()
    {
        var alicesHint = await IdTokenForAsync(Alice);

        var response = await AuthorizeAsync(prompt: "none", idTokenHint: alicesHint);

        response.ShouldHaveIssuedCodeTo(Redirect);
    }

    // ── An interactive request ────────────────────────────────────────────────────────────────────

    [Fact]
    public async Task An_interactive_request_with_another_users_hint_reaches_the_login_page()
    {
        var alicesHint = await IdTokenForAsync(Alice);
        await SignInAsync(Bob);

        var response = await AuthorizeAsync(idTokenHint: alicesHint);

        response.StatusCode.Should().Be(HttpStatusCode.Redirect);
        Location(response).Should().StartWith($"{LoginPath}?{InteractionHandoff.InteractionIdParameter}=");
    }

    [Fact]
    public async Task The_login_page_is_told_the_subject_the_hint_names()
    {
        var alicesHint = await IdTokenForAsync(Alice);
        await SignInAsync(Bob);
        var handoff = await AuthorizeAsync(idTokenHint: alicesHint);

        var page = await _client.GetAsync(Location(handoff), Cancellation);

        var body = JsonDocument.Parse(await page.Content.ReadAsStringAsync(Cancellation)).RootElement;
        body.GetProperty("requiredSubject").GetString().Should().Be(Alice);
    }

    [Fact]
    public async Task The_login_page_is_told_no_required_subject_without_a_hint()
    {
        var handoff = await AuthorizeAsync();

        var page = await _client.GetAsync(Location(handoff), Cancellation);

        var body = JsonDocument.Parse(await page.Content.ReadAsStringAsync(Cancellation)).RootElement;
        body.GetProperty("requiredSubject").ValueKind.Should().Be(JsonValueKind.Null);
    }

    [Fact]
    public async Task Signing_in_as_another_user_than_the_hint_names_is_refused_with_login_required_and_leaves_the_session_unchanged()
    {
        var alicesHint = await IdTokenForAsync(Alice);
        await SignInAsync(Bob);
        var sessionBefore = await ReadSessionAsync();
        var login = await AuthorizeAsync(idTokenHint: alicesHint);

        var response = await PostLoginAsync(Location(login), "carol");

        ErrorAtClient(response)["error"].ToString().Should().Be(AuthorizeRequestErrors.LoginRequired);
        (await ReadSessionAsync()).Should().Be(sessionBefore);
    }

    [Fact]
    public async Task Signing_in_as_the_hinted_user_issues_a_code_for_that_user()
    {
        var alicesHint = await IdTokenForAsync(Alice);
        await SignInAsync(Bob);
        var login = await AuthorizeAsync(idTokenHint: alicesHint);

        var response = await PostLoginAsync(Location(login), Alice);

        var idToken = await RedeemAsync(response.ShouldHaveIssuedCodeTo(Redirect));
        SubjectOf(idToken).Should().Be(Alice);
    }

    // ── A hint that is not the client's ───────────────────────────────────────────────────────────

    [Fact]
    public async Task A_hint_issued_to_another_client_is_answered_invalid_request_at_the_client()
    {
        var otherAppsHint = await IdTokenForAsync(Alice, OtherApp);

        var response = await AuthorizeAsync(prompt: "none", idTokenHint: otherAppsHint);

        ErrorAtClient(response)["error"].ToString().Should().Be(AuthorizeRequestErrors.InvalidRequest);
    }

    // ── Helpers ───────────────────────────────────────────────────────────────────────────────────

    private Task<HttpResponseMessage> AuthorizeAsync(string clientId = App, string? prompt = null, string? idTokenHint = null) =>
        _client.GetAsync(
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
                ["id_token_hint"] = idTokenHint,
            }),
            Cancellation);

    /// <summary>Signs <paramref name="subject"/> in over whatever session the browser holds; returns the code response.</summary>
    private async Task<HttpResponseMessage> SignInAsync(string subject, string clientId = App)
    {
        var login = await AuthorizeAsync(clientId, prompt: "login");
        login.StatusCode.Should().Be(HttpStatusCode.Redirect);

        return await PostLoginAsync(Location(login), subject);
    }

    private async Task<HttpResponseMessage> PostLoginAsync(string loginUrl, string subject)
    {
        using var form = new FormUrlEncodedContent(new Dictionary<string, string> { ["sub"] = subject });
        return await _client.PostAsync(loginUrl, form, Cancellation);
    }

    /// <summary>Signs <paramref name="subject"/> in for <paramref name="clientId"/> and redeems the code, for an ID token to send as a hint.</summary>
    private async Task<string> IdTokenForAsync(string subject, string clientId = App) =>
        await RedeemAsync((await SignInAsync(subject, clientId)).ShouldHaveIssuedCodeTo(Redirect), clientId);

    private async Task<string> RedeemAsync(string code, string clientId = App)
    {
        using var form = new FormUrlEncodedContent(new Dictionary<string, string>
        {
            ["grant_type"] = "authorization_code",
            ["code"] = code,
            ["redirect_uri"] = Redirect,
            ["client_id"] = clientId,
            ["code_verifier"] = Verifier,
        });
        var response = await _client.PostAsync(TokenPath, form, Cancellation);
        var body = await response.Content.ReadAsStringAsync(Cancellation);
        response.StatusCode.Should().Be(HttpStatusCode.OK, body);

        using var document = JsonDocument.Parse(body);
        return document.RootElement.GetProperty("id_token").GetString()!;
    }

    private async Task<string> ReadSessionAsync()
    {
        var response = await _client.GetAsync(SessionProbePath, Cancellation);
        response.StatusCode.Should().Be(HttpStatusCode.OK);

        return await response.Content.ReadAsStringAsync(Cancellation);
    }

    private static string SubjectOf(string idToken)
    {
        using var payload = JsonDocument.Parse(Base64Url.DecodeFromChars(idToken.Split('.')[1]));
        return payload.RootElement.GetProperty("sub").GetString()!;
    }

    /// <summary>The query of a redirect to the client's registered redirect URI.</summary>
    private static Dictionary<string, StringValues> ErrorAtClient(HttpResponseMessage response)
    {
        response.StatusCode.Should().Be(HttpStatusCode.Redirect);
        var location = Location(response);
        location.Should().StartWith(Redirect + "?");

        return QueryHelpers.ParseQuery(location[location.IndexOf('?')..]);
    }

    private static string Location(HttpResponseMessage response) => response.Headers.Location!.OriginalString;
}
