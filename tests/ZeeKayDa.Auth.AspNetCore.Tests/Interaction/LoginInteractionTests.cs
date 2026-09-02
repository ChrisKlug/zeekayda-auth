using System.Net;
using System.Security.Claims;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Routing;
using Microsoft.AspNetCore.WebUtilities;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Primitives;
using Microsoft.Extensions.Time.Testing;
using ZeeKayDa.Auth.AspNetCore.Interaction;
using ZeeKayDa.Auth.Authorization;

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
    private const string CancelPath = "/account/login/cancel";

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
            // in with them — under any casing, since claim types are matched case-insensitively.
            // The test passes one deliberately.
            if (form["forge_type"].FirstOrDefault() is { Length: > 0 } forgedType)
                claims.Add(new Claim(forgedType, form["forge_value"].FirstOrDefault() ?? string.Empty));

            // Absent, the page reports a password — the ordinary case, and what most tests here
            // want. "amr_omit" drives the report-nothing case; repeated "amr" fields drive the
            // multi-factor one.
            string[] methods =
                form.ContainsKey("amr_omit") ? []
                : form.ContainsKey("amr") ? [.. form["amr"].Select(value => value ?? string.Empty)]
                : [AuthenticationMethods.Password];

            await login.SignInAsync(
                new ClaimsPrincipal(new ClaimsIdentity(claims, "test")),
                methods);
        });

        // The Cancel button, exactly as the issue's sample host writes it.
        endpoints.MapPost(CancelPath, (ILoginInteraction login) => login.DenyAsync());

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

    private Task<HttpResponseMessage> PostCancelAsync(
        string? interactionId,
        params (string Key, string Value)[] fields) =>
        PostCancelAsync(interactionId, extraQuery: null, fields);

    private async Task<HttpResponseMessage> PostCancelAsync(
        string? interactionId,
        Dictionary<string, string?>? extraQuery,
        params (string Key, string Value)[] fields)
    {
        var query = new Dictionary<string, string?>(StringComparer.Ordinal);
        if (interactionId is not null)
            query[InteractionHandoff.InteractionIdParameter] = interactionId;

        foreach (var (key, value) in extraQuery ?? [])
            query[key] = value;

        using var content = new FormUrlEncodedContent(
            fields.Select(field => KeyValuePair.Create(field.Key, field.Value)));

        return await _client.PostAsync(
            QueryHelpers.AddQueryString(CancelPath, query), content, TestContext.Current.CancellationToken);
    }

    /// <summary>Runs a full authorize → login page → cancelled round trip.</summary>
    private async Task<HttpResponseMessage> CancelAsync(
        Dictionary<string, string?>? query = null,
        params (string Key, string Value)[] fields)
    {
        var handoff = await AuthorizeAsync(query);
        return await PostCancelAsync(InteractionIdFrom(handoff), fields);
    }

    /// <summary>The parsed query of a redirect back to the client.</summary>
    private static Dictionary<string, StringValues> RedirectQueryOf(HttpResponseMessage response)
    {
        var location = response.Headers.Location!.OriginalString;
        return QueryHelpers.ParseQuery(location[location.IndexOf('?')..]);
    }

    /// <summary>
    /// Where a redirect actually points — scheme, authority and path, with the protocol query
    /// stripped. A prefix check would accept an attacker-chosen host that merely starts the same
    /// way, and would not notice a destination assembled from request input at all.
    /// </summary>
    private static string DestinationOf(HttpResponseMessage response) =>
        new Uri(response.Headers.Location!.OriginalString).GetLeftPart(UriPartial.Path);

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

    private async Task<System.Text.Json.JsonElement> ReadSessionAsync()
    {
        var response = await _client.GetAsync("/test/session", TestContext.Current.CancellationToken);
        var body = await response.Content.ReadAsStringAsync(TestContext.Current.CancellationToken);

        return System.Text.Json.JsonDocument.Parse(body).RootElement.Clone();
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

    // ── Cancelling at the login page ──────────────────────────────────────────────────────────

    [Fact]
    public async Task DenyAsync_answers_the_client_with_access_denied_at_its_registered_redirect_uri()
    {
        var query = ValidQuery();
        query["state"] = "opaque-client-state";

        var response = await CancelAsync(query);

        response.StatusCode.Should().Be(HttpStatusCode.Redirect);
        DestinationOf(response).Should().Be(RegisteredRedirect);

        var parameters = RedirectQueryOf(response);
        parameters["error"].Should().Equal(["access_denied"]);
        parameters["state"].Should().Equal(["opaque-client-state"],
            "state round-trips byte for byte on every authorization response, errors included");
        parameters["iss"].Should().Equal(["https://test.example.com"],
            "iss is unconditional on every authorization response (RFC 9207)");
    }

    [Fact]
    public async Task DenyAsync_ignores_every_destination_the_cancelling_request_tries_to_supply()
    {
        // The invariant this protects is that no return URL is ever taken from the request — the
        // reason the interaction identifier is an opaque id and not a URL in the first place. A
        // test that only checks the destination's prefix would still pass if the destination were
        // read from request input whenever it happened to be present, so hostile values are
        // supplied here on both the query string and the form, under the names a host or a
        // careless future change would most plausibly reach for.
        const string Attacker = "https://attacker.example.net/collect";

        var handoff = await AuthorizeAsync();

        var response = await PostCancelAsync(
            InteractionIdFrom(handoff),
            extraQuery: new Dictionary<string, string?>(StringComparer.Ordinal)
            {
                ["redirect_uri"] = Attacker,
                ["ReturnUrl"] = Attacker,
            },
            ("redirect_uri", Attacker),
            ("ReturnUrl", Attacker),
            ("returnUrl", Attacker));

        response.StatusCode.Should().Be(HttpStatusCode.Redirect);
        DestinationOf(response).Should().Be(RegisteredRedirect,
            "the destination comes from the decrypted interaction context, never from the request");
        response.Headers.Location!.OriginalString.Should().NotContain("attacker.example.net");
    }

    [Fact]
    public async Task DenyAsync_names_the_cancellation_in_a_framework_owned_description()
    {
        // access_denied alone cannot separate a user who pressed Cancel from one refused by
        // policy. The description is what says so — framework-owned, echoing no value, and pinned
        // here because a client developer reads it. A client that needs to branch in code gets
        // the opt-in zkd_error sub-code instead, so this text is a courtesy, not a contract.
        var response = await CancelAsync();

        RedirectQueryOf(response)["error_description"]
            .Should().Equal(["The user cancelled the request at the sign-in page."]);
    }

    [Fact]
    public async Task DenyAsync_forbids_the_client_from_caching_the_response()
    {
        var response = await CancelAsync();

        response.Headers.CacheControl!.NoStore.Should().BeTrue();
    }

    [Fact]
    public async Task DenyAsync_establishes_no_session()
    {
        await CancelAsync();

        (await ReadSessionIdAsync()).Should().BeNull("cancelling is not signing in");
    }

    [Fact]
    public async Task DenyAsync_leaves_an_existing_session_untouched()
    {
        await SignInAsync();
        var established = await ReadSessionIdAsync();

        // prompt=login is how a second client's request reaches the login page while a session
        // already exists. Cancelling it must not sign the user out of the first.
        var query = ValidQuery();
        query["prompt"] = "login";
        await CancelAsync(query);

        (await ReadSessionIdAsync()).Should().Be(established,
            "a user cancelling one client's request is not signed out of another's");
    }

    [Fact]
    public async Task A_cancelled_request_cannot_afterwards_be_signed_in()
    {
        var handoff = await AuthorizeAsync();
        var interactionId = InteractionIdFrom(handoff);

        await PostCancelAsync(interactionId);

        // The context is discarded on the way out, so there is nothing left for a later sign-in
        // to pick up and complete.
        var signIn = async () => await PostLoginAsync(interactionId, ("sub", "user-1"));

        await signIn.Should().ThrowAsync<ZeeKayDaInteractionException>();
    }

    [Fact]
    public async Task DenyAsync_without_an_interaction_id_is_refused()
    {
        await AuthorizeAsync();

        var cancel = async () => await PostCancelAsync(interactionId: null);

        await cancel.Should().ThrowAsync<ZeeKayDaInteractionException>();
    }

    [Fact]
    public async Task DenyAsync_naming_an_interaction_the_browser_is_not_carrying_is_refused()
    {
        // Aiming a deny at another tab's request would be a cross-tab denial of service.
        var firstTab = await AuthorizeAsync();
        var secondTab = await AuthorizeAsync();

        var cancel = async () => await PostCancelAsync(InteractionIdFrom(firstTab));

        await cancel.Should().ThrowAsync<ZeeKayDaInteractionException>();

        // Refusing is only half of it: the interaction the browser *is* carrying must survive the
        // refused deny, or a rejected cross-tab attempt would still have killed the live request.
        var signIn = await PostLoginAsync(InteractionIdFrom(secondTab), ("sub", "user-1"));

        signIn.StatusCode.Should().Be(HttpStatusCode.NotImplemented,
            "the live interaction is untouched by a deny that named a different one");
    }

    [Fact]
    public async Task DenyAsync_after_the_interaction_has_expired_recovers_no_redirect_uri()
    {
        var handoff = await AuthorizeAsync();
        var interactionId = InteractionIdFrom(handoff);

        _time.Advance(TimeSpan.FromMinutes(31));

        // The destination comes from the decrypted context and nothing else. With no context there
        // is no destination, and the request fails where it stands rather than redirecting
        // somewhere derived from what this request happened to carry.
        var cancel = async () => await PostCancelAsync(interactionId);

        await cancel.Should().ThrowAsync<ZeeKayDaInteractionException>();
    }

    // ── The SSO session ───────────────────────────────────────────────────────────────────────

    [Theory]
    [InlineData("zkd:sid")]
    [InlineData("ZKD:sid")]
    [InlineData("Zkd:Sid")]
    public async Task A_host_supplied_session_id_claim_is_stripped_whatever_its_case(string claimType)
    {
        var handoff = await AuthorizeAsync();

        await PostLoginAsync(
            InteractionIdFrom(handoff),
            ("sub", "user-1"),
            ("forge_type", claimType),
            ("forge_value", "chosen-by-the-host"));

        (await ReadSessionIdAsync()).Should().NotBe("chosen-by-the-host",
            "claim types are matched case-insensitively, so the reserved namespace must be stripped that way too");
    }

    [Fact]
    public async Task A_host_supplied_amr_claim_is_stripped_whatever_its_case()
    {
        var handoff = await AuthorizeAsync();

        await PostLoginAsync(
            InteractionIdFrom(handoff),
            ("sub", "user-1"),
            ("forge_type", "ZKD:amr"),
            ("forge_value", "mfa"));

        // An RP's step-up check reads amr, so a host must not be able to add to what the framework
        // recorded — "mfa" arriving from the login form would be a lie the RP cannot detect.
        (await ReadSessionAsync()).GetProperty("amr").EnumerateArray()
            .Select(value => value.GetString())
            .Should().Equal(["pwd"]);
    }

    [Fact]
    public async Task Every_authentication_method_reported_reaches_the_session()
    {
        var handoff = await AuthorizeAsync();

        // RFC 8176 §2 asks that a multi-factor sign-in name the factors alongside "mfa", so the
        // signature has to carry more than one value — the string parameter it replaced could not.
        await PostLoginAsync(
            InteractionIdFrom(handoff),
            ("sub", "user-1"),
            ("amr", AuthenticationMethods.MultiFactor),
            ("amr", AuthenticationMethods.Password),
            ("amr", AuthenticationMethods.OneTimePassword));

        (await ReadSessionAsync()).GetProperty("amr").EnumerateArray()
            .Select(value => value.GetString())
            .Should().Equal(["mfa", "pwd", "otp"]);
    }

    [Fact]
    public async Task A_sign_in_reporting_no_authentication_method_claims_none()
    {
        var handoff = await AuthorizeAsync();

        await PostLoginAsync(InteractionIdFrom(handoff), ("sub", "user-1"), ("amr_omit", "1"));

        // Not "pwd" by default: amr is optional, and inventing a method for a host that named
        // none would put a claim an RP may gate on into a token on no evidence at all.
        (await ReadSessionAsync()).GetProperty("amr").EnumerateArray().Should().BeEmpty();

        // Omitting the method is not a failed sign-in — the session is still established.
        (await ReadSessionIdAsync()).Should().NotBeNull();
    }

    [Fact]
    public async Task A_blank_authentication_method_is_refused()
    {
        var handoff = await AuthorizeAsync();

        // A blank amr claim would reach the RP as a method it cannot interpret. Caught at the
        // argument, so the blame lands on the caller rather than on the session cookie.
        var signIn = async () => await PostLoginAsync(
            InteractionIdFrom(handoff), ("sub", "user-1"), ("amr", "  "));

        await signIn.Should().ThrowAsync<ArgumentException>();
    }

    [Fact]
    public async Task A_host_supplied_auth_time_claim_cannot_defeat_max_age()
    {
        // A future auth_time would make (now - authTime) negative, so no max_age could ever
        // exceed it and re-authentication would never be required again.
        var handoff = await AuthorizeAsync();
        await PostLoginAsync(
            InteractionIdFrom(handoff),
            ("sub", "user-1"),
            ("forge_type", "ZKD:auth_time"),
            ("forge_value", Now.AddYears(1).ToUnixTimeSeconds().ToString(System.Globalization.CultureInfo.InvariantCulture)));

        _time.Advance(TimeSpan.FromMinutes(10));
        var query = ValidQuery();
        query["max_age"] = "60";

        (await AuthorizeAsync(query)).Headers.Location!.OriginalString.Should().StartWith($"{LoginPath}?");
    }

    [Fact]
    public async Task A_refused_request_does_not_leave_an_interaction_behind()
    {
        // prompt=none is refused after the context is written, so the refusal must also clear it —
        // otherwise the refused request's context is left for the next sign-in to pick up.
        var query = ValidQuery();
        query["prompt"] = "none";
        await AuthorizeAsync(query);

        var signIn = async () => await PostLoginAsync("any-interaction-id", ("sub", "user-1"));

        await signIn.Should().ThrowAsync<ZeeKayDaInteractionException>();
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
