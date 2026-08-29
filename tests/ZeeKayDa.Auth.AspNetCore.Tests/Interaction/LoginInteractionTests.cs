using System.Net;
using System.Security.Claims;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Routing;
using Microsoft.AspNetCore.WebUtilities;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Time.Testing;
using ZeeKayDa.Auth.AspNetCore.Interaction;

namespace ZeeKayDa.Auth.AspNetCore.Tests.Interaction;

/// <summary>
/// Integration tests for the handoff to the host's login page and back (#85, local leg): the
/// <c>zkd_i</c> binding that decides which interaction a sign-in may complete, and the SSO session
/// minted when it does.
/// </summary>
/// <remarks>
/// The test host maps a login page whose handler calls <see cref="ILoginInteraction.SignInAsync"/>
/// exactly as a real one would, and a <c>/test/session</c> probe that reports the session claims
/// the framework wrote — the session cookie is encrypted, so its contents are otherwise only
/// observable through a handler.
/// </remarks>
public sealed class LoginInteractionTests : IDisposable
{
    private const string RegisteredRedirect = "https://test.example.com/callback";
    private const string Challenge = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM";
    private const string LoginPath = "/account/login";

    private static readonly DateTimeOffset Now = new(2026, 8, 29, 12, 0, 0, TimeSpan.Zero);

    private readonly FakeTimeProvider _time = new(Now);
    private readonly TestWebAppFactory _factory;
    private readonly HttpClient _client;

    public LoginInteractionTests()
    {
        _factory = new TestWebAppFactory(
            configureBuilder: builder => builder.Services.AddSingleton<TimeProvider>(_time),
            mapEndpoints: MapHostPages);

        _client = _factory.CreateClient(new()
        {
            BaseAddress = new Uri("https://test.example.com"),
            AllowAutoRedirect = false,
            HandleCookies = true,
        });
    }

    public void Dispose()
    {
        _client.Dispose();
        _factory.Dispose();
    }

    /// <summary>
    /// The host's own pages: a login form that signs a fixed user in, and a probe reporting what
    /// the session cookie carries.
    /// </summary>
    private static void MapHostPages(IEndpointRouteBuilder endpoints)
    {
        endpoints.MapPost(LoginPath, async (HttpContext context, ILoginInteraction login) =>
        {
            var form = await context.Request.ReadFormAsync(context.RequestAborted);
            var subject = form["sub"].FirstOrDefault() ?? "user-1";

            var claims = new List<Claim> { new("sub", subject), new("name", "Test User") };

            // A host that copies claims from somewhere else could carry a framework-reserved one
            // in with them. The test passes it deliberately.
            if (form["forge_sid"].FirstOrDefault() is { Length: > 0 } forged)
                claims.Add(new Claim(SsoSessionClaimTypes.SessionId, forged));

            await login.SignInAsync(
                new ClaimsPrincipal(new ClaimsIdentity(claims, "test")),
                amr: "pwd");
        });

        // Nothing should ever challenge the framework's session scheme: the authorization endpoint
        // owns that decision and needs the interaction context written first.
        endpoints.MapGet("/test/challenge-session", async (HttpContext context) =>
        {
            await context.ChallengeAsync(ZeeKayDaCookies.Session);
        });

        endpoints.MapGet("/test/session", async (HttpContext context) =>
        {
            var result = await context.AuthenticateAsync(ZeeKayDaCookies.Session);

            return result.Succeeded
                ? Results.Ok(new
                {
                    sid = result.Principal!.FindFirstValue(SsoSessionClaimTypes.SessionId),
                    sub = result.Principal.FindFirstValue("sub"),
                    authTime = result.Principal.FindFirstValue(SsoSessionClaimTypes.AuthTime),
                    amr = result.Principal.FindAll(SsoSessionClaimTypes.Amr).Select(c => c.Value).ToArray(),
                })
                : Results.NotFound();
        });
    }

    private static Dictionary<string, string?> ValidQuery() => new()
    {
        ["client_id"] = "test-client",
        ["redirect_uri"] = RegisteredRedirect,
        ["response_type"] = "code",
        ["scope"] = "openid",
        ["nonce"] = "n-0S6_WzA2Mj",
        ["code_challenge"] = Challenge,
        ["code_challenge_method"] = "S256",
    };

    /// <summary>Starts an authorization request and returns the response it answers with.</summary>
    private Task<HttpResponseMessage> AuthorizeAsync(Dictionary<string, string?>? query = null) =>
        _client.GetAsync(
            QueryHelpers.AddQueryString("/connect/authorize", query ?? ValidQuery()),
            TestContext.Current.CancellationToken);

    /// <summary>The interaction identifier the framework put on the login redirect.</summary>
    private static string InteractionIdFrom(HttpResponseMessage response)
    {
        var location = response.Headers.Location!.OriginalString;
        return QueryHelpers.ParseQuery(location[location.IndexOf('?')..])[
            InteractionHandoff.InteractionIdParameter]!;
    }

    private async Task<HttpResponseMessage> PostLoginAsync(
        string? interactionId,
        params (string Key, string Value)[] fields)
    {
        var url = interactionId is null
            ? LoginPath
            : QueryHelpers.AddQueryString(LoginPath, InteractionHandoff.InteractionIdParameter, interactionId);

        using var content = new FormUrlEncodedContent(
            fields.Select(field => KeyValuePair.Create(field.Key, field.Value)));

        return await _client.PostAsync(url, content, TestContext.Current.CancellationToken);
    }

    /// <summary>Runs a full authorize → login → signed-in round trip.</summary>
    private async Task<HttpResponseMessage> SignInAsync(Dictionary<string, string?>? query = null, string sub = "user-1")
    {
        var handoff = await AuthorizeAsync(query);
        return await PostLoginAsync(InteractionIdFrom(handoff), ("sub", sub));
    }

    private async Task<string?> ReadSessionIdAsync()
    {
        var response = await _client.GetAsync("/test/session", TestContext.Current.CancellationToken);
        if (response.StatusCode == HttpStatusCode.NotFound)
            return null;

        var body = await response.Content.ReadAsStringAsync(TestContext.Current.CancellationToken);
        return System.Text.Json.JsonDocument.Parse(body).RootElement.GetProperty("sid").GetString();
    }

    // ── Handoff ───────────────────────────────────────────────────────────────────────────────

    [Fact]
    public async Task An_unauthenticated_request_reaches_the_login_page_carrying_the_interaction_id()
    {
        var response = await AuthorizeAsync();

        response.StatusCode.Should().Be(HttpStatusCode.Redirect);
        response.Headers.Location!.OriginalString.Should().StartWith($"{LoginPath}?zkd_i=");
        InteractionIdFrom(response).Should().NotBeNullOrEmpty();
    }

    [Fact]
    public async Task SignInAsync_completes_the_interaction_and_establishes_a_session()
    {
        var response = await SignInAsync();

        response.StatusCode.Should().Be(HttpStatusCode.NotImplemented,
            "the session is established; consent (#86) and code issuance (#87) are what remain");
        (await ReadSessionIdAsync()).Should().NotBeNullOrEmpty();
    }

    [Fact]
    public async Task A_signed_in_request_continues_without_visiting_the_login_page()
    {
        await SignInAsync();

        var response = await AuthorizeAsync();

        response.StatusCode.Should().Be(HttpStatusCode.NotImplemented,
            "the session answers for the user, so there is nothing to hand off");
    }

    [Fact]
    public async Task A_host_with_no_login_page_answers_the_client_with_server_error()
    {
        using var factory = new TestWebAppFactory(
            configureOptions: options => options.AuthorizationEndpoint.Interaction.LoginPath = null);
        using var client = factory.CreateClient(new()
        {
            BaseAddress = new Uri("https://test.example.com"),
            AllowAutoRedirect = false,
        });

        var response = await client.GetAsync(
            QueryHelpers.AddQueryString("/connect/authorize", ValidQuery()),
            TestContext.Current.CancellationToken);

        response.StatusCode.Should().Be(HttpStatusCode.Redirect);
        response.Headers.Location!.OriginalString.Should().StartWith(RegisteredRedirect)
            .And.Contain("error=server_error");
    }

    [Fact]
    public async Task Challenging_the_session_scheme_answers_401_rather_than_redirecting()
    {
        var response = await _client.GetAsync("/test/challenge-session", TestContext.Current.CancellationToken);

        response.StatusCode.Should().Be(HttpStatusCode.Unauthorized,
            "the scheme has no login page of its own to redirect to, and a redirect here would be a bug " +
            "that silently appears to work");
    }

    // ── The zkd_i binding ─────────────────────────────────────────────────────────────────────

    [Fact]
    public async Task SignInAsync_without_an_interaction_id_is_refused()
    {
        // A planted interaction context is exactly this shape: the browser carries a context the
        // user never asked for, and reaches the login page by its own route.
        await AuthorizeAsync();

        var signIn = async () => await PostLoginAsync(interactionId: null, ("sub", "user-1"));

        await signIn.Should().ThrowAsync<ZeeKayDaInteractionException>();
    }

    [Fact]
    public async Task SignInAsync_naming_an_interaction_the_browser_is_not_carrying_is_refused()
    {
        // Two tabs: the first starts an authorization request, the second replaces the context.
        // Without the binding, completing the first would issue a code for the second's client.
        var firstTab = await AuthorizeAsync();
        await AuthorizeAsync();

        var signIn = async () => await PostLoginAsync(InteractionIdFrom(firstTab), ("sub", "user-1"));

        await signIn.Should().ThrowAsync<ZeeKayDaInteractionException>();
    }

    [Fact]
    public async Task SignInAsync_after_the_interaction_has_expired_is_refused()
    {
        var handoff = await AuthorizeAsync();
        var interactionId = InteractionIdFrom(handoff);

        _time.Advance(TimeSpan.FromMinutes(31));

        var signIn = async () => await PostLoginAsync(interactionId, ("sub", "user-1"));

        await signIn.Should().ThrowAsync<ZeeKayDaInteractionException>();
    }

    // ── The SSO session ───────────────────────────────────────────────────────────────────────

    [Fact]
    public async Task A_host_supplied_session_id_claim_is_stripped_rather_than_honoured()
    {
        var handoff = await AuthorizeAsync();

        await PostLoginAsync(InteractionIdFrom(handoff), ("sub", "user-1"), ("forge_sid", "chosen-by-the-host"));

        (await ReadSessionIdAsync()).Should().NotBe("chosen-by-the-host",
            "a claim in the reserved namespace never survives promotion");
    }

    [Fact]
    public async Task The_session_id_is_stable_across_a_prompt_login_re_authentication()
    {
        await SignInAsync();
        var original = await ReadSessionIdAsync();

        var reauth = ValidQuery();
        reauth["prompt"] = "login";
        await SignInAsync(reauth);

        (await ReadSessionIdAsync()).Should().Be(original,
            "re-authentication refreshes auth_time; it does not start a new session");
    }

    [Fact]
    public async Task The_session_id_changes_when_the_subject_changes()
    {
        await SignInAsync(sub: "user-1");
        var original = await ReadSessionIdAsync();

        var reauth = ValidQuery();
        reauth["prompt"] = "login";
        await SignInAsync(reauth, sub: "user-2");

        (await ReadSessionIdAsync()).Should().NotBe(original);
    }

    [Fact]
    public async Task The_session_cookie_value_changes_on_every_promotion_while_the_session_id_does_not()
    {
        var first = await SignInAsync();
        var firstCookie = SessionCookieFrom(first);
        var sessionId = await ReadSessionIdAsync();

        var reauth = ValidQuery();
        reauth["prompt"] = "login";
        var second = await SignInAsync(reauth);

        SessionCookieFrom(second).Should().NotBe(firstCookie,
            "the cookie is rewritten on every promotion, which is what makes fixation useless");
        (await ReadSessionIdAsync()).Should().Be(sessionId,
            "the identifier is not the cookie value, and bindings keyed on it must survive the rotation");
    }

    private static string SessionCookieFrom(HttpResponseMessage response) => response.Headers
        .GetValues("Set-Cookie")
        .Single(value => value.StartsWith($"{ZeeKayDaCookies.Session}=", StringComparison.Ordinal));

    // ── prompt and max_age ────────────────────────────────────────────────────────────────────

    [Fact]
    public async Task prompt_none_without_a_session_is_refused_with_login_required()
    {
        var query = ValidQuery();
        query["prompt"] = "none";

        var response = await AuthorizeAsync(query);

        response.StatusCode.Should().Be(HttpStatusCode.Redirect);
        response.Headers.Location!.OriginalString.Should().StartWith(RegisteredRedirect)
            .And.Contain("error=login_required");
    }

    [Fact]
    public async Task prompt_none_with_a_session_continues_without_interacting()
    {
        await SignInAsync();

        var query = ValidQuery();
        query["prompt"] = "none";

        (await AuthorizeAsync(query)).StatusCode.Should().Be(HttpStatusCode.NotImplemented);
    }

    [Fact]
    public async Task prompt_login_re_authenticates_a_user_who_already_has_a_session()
    {
        await SignInAsync();

        var query = ValidQuery();
        query["prompt"] = "login";

        (await AuthorizeAsync(query)).Headers.Location!.OriginalString.Should().StartWith($"{LoginPath}?");
    }

    [Theory]
    [InlineData(60, true)]
    [InlineData(3600, false)]
    public async Task max_age_re_authenticates_only_a_session_older_than_it_allows(int maxAge, bool expectsLogin)
    {
        await SignInAsync();
        _time.Advance(TimeSpan.FromMinutes(10));

        var query = ValidQuery();
        query["max_age"] = maxAge.ToString(System.Globalization.CultureInfo.InvariantCulture);

        var response = await AuthorizeAsync(query);

        if (expectsLogin)
            response.Headers.Location!.OriginalString.Should().StartWith($"{LoginPath}?");
        else
            response.StatusCode.Should().Be(HttpStatusCode.NotImplemented);
    }
}
