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
    private const string SignInThenReturnPath = "/account/login/sign-in-then-return";
    private const string CancelThenReturnPath = "/account/login/cancel-then-return";
    private const string HijackTarget = "https://attacker.example.net/collect";
    private const string CancelPath = "/account/login/cancel";
    private const string SignInByLinkPath = "/account/login/sign-in-by-link";
    private const string CancelByLinkPath = "/account/login/cancel-by-link";
    private const string ChallengeByLinkPath = "/account/login/challenge-by-link";

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

        // Pages wired the way the XML docs say not to: a terminal step taken from a GET — the
        // request the framework itself arrives with, and one a link from anywhere can make.
        endpoints.MapGet(SignInByLinkPath, (ILoginInteraction login) => login.SignInAsync(
            new ClaimsPrincipal(new ClaimsIdentity([new Claim("sub", "user-1")], "test")),
            AuthenticationMethods.Password));
        endpoints.MapGet(CancelByLinkPath, (ILoginInteraction login) => login.DenyAsync());
        endpoints.MapGet(ChallengeByLinkPath, (ILoginInteraction login) => login.ChallengeAsync("acme"));

        // Pages that do the thing the XML docs tell hosts not to do: call a terminal method and
        // then return a result of their own. The framework must not let the second one land.
        endpoints.MapPost(SignInThenReturnPath, async (ILoginInteraction login) =>
        {
            await login.SignInAsync(
                new ClaimsPrincipal(new ClaimsIdentity([new Claim("sub", "user-1")], "test")),
                AuthenticationMethods.Password);

            return Results.Redirect(HijackTarget);
        });

        endpoints.MapPost(CancelThenReturnPath, async (ILoginInteraction login) =>
        {
            await login.DenyAsync();
            return Results.Redirect(HijackTarget);
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

        response.ShouldHaveReachedConsent("the session is established and the flow moves on to consent");
        (await ReadSessionIdAsync()).Should().NotBeNullOrEmpty();
    }

    [Fact]
    public async Task A_signed_in_request_continues_without_visiting_the_login_page()
    {
        await SignInAsync();

        var response = await AuthorizeAsync();

        response.ShouldHaveReachedConsent("the session answers for the user, so the flow moves straight to consent");
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
        //
        // Hostile text is supplied on both the query string and the form under the names a
        // reintroduced host-text path would most plausibly read. Non-disclosure is the property
        // that removing the host-supplied overload existed to guarantee, and a test that sends
        // nothing would still pass against a description sourced from input whenever present.
        const string HostText = "The account is locked out.";

        var handoff = await AuthorizeAsync();

        var response = await PostCancelAsync(
            InteractionIdFrom(handoff),
            extraQuery: new Dictionary<string, string?>(StringComparer.Ordinal)
            {
                ["reason"] = HostText,
                ["error_description"] = HostText,
            },
            ("reason", HostText),
            ("description", HostText),
            ("error_description", HostText));

        RedirectQueryOf(response)["error_description"]
            .Should().Equal(["The user cancelled the request at the sign-in page."]);
        response.Headers.Location!.OriginalString.Should().NotContain("locked",
            "nothing the cancelling request carried may reach the client");
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

        signIn.ShouldHaveReachedConsent("the live interaction is untouched by a deny that named a different one");
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

    // ── A terminal step comes only from a form post ───────────────────────────────────────────

    [Theory]
    [InlineData(SignInByLinkPath)]
    [InlineData(CancelByLinkPath)]
    [InlineData(ChallengeByLinkPath)]
    public async Task A_terminal_step_taken_from_a_GET_is_refused_and_changes_nothing(string path)
    {
        // The framework's cookies are Lax, so they accompany a top-level GET from any site. A
        // cancel wired to a link could be triggered by a page that never showed the user
        // anything; a sign-in wired to one would complete on arrival. The refusal happens before
        // anything is read, so the interaction survives for the form post that follows.
        var handoff = await AuthorizeAsync();
        var interactionId = InteractionIdFrom(handoff);

        var byLink = async () => await _client.GetAsync(
            QueryHelpers.AddQueryString(path, InteractionHandoff.InteractionIdParameter, interactionId),
            TestContext.Current.CancellationToken);

        await byLink.Should().ThrowAsync<InvalidOperationException>().WithMessage("*POST*");
        (await PostLoginAsync(interactionId, ("sub", "user-1"))).ShouldHaveReachedConsent(
            "the form post still completes the interaction the link could not touch");
    }

    [Theory]
    [InlineData(SignInByLinkPath)]
    [InlineData(CancelByLinkPath)]
    [InlineData(ChallengeByLinkPath)]
    public async Task A_terminal_step_taken_from_a_GET_is_refused_before_any_interaction_state_is_read(string path)
    {
        // No zkd_i and no interaction: had the service resolved the interaction first, the
        // refusal would be the interaction one. Seeing the POST refusal proves the ordering.
        var byLink = async () => await _client.GetAsync(path, TestContext.Current.CancellationToken);

        await byLink.Should().ThrowAsync<InvalidOperationException>().WithMessage("*POST*");
    }

    // ── A terminal method really is the last word ─────────────────────────────────────────────

    [Theory]
    [InlineData(SignInThenReturnPath)]
    [InlineData(CancelThenReturnPath)]
    public async Task A_result_returned_after_a_terminal_call_cannot_replace_the_response(string path)
    {
        // Executing a redirect result sets the status and Location without flushing, so before the
        // response was committed a page written this way silently sent the user wherever it liked
        // — for a deny, the open redirect the interaction identifier exists to prevent, in host
        // code where nothing validates it. The page is wrong either way; what matters is that it
        // fails loudly the first time it runs instead of working and being unsafe.
        //
        // Both cases end in a bodyless redirect — to the client for the deny, to the consent
        // page for the sign-in — so neither commits the response by accident, and both fail
        // without the explicit commit.
        var handoff = await AuthorizeAsync();

        using var content = new FormUrlEncodedContent([]);
        var post = async () => await _client.PostAsync(
            QueryHelpers.AddQueryString(
                path, InteractionHandoff.InteractionIdParameter, InteractionIdFrom(handoff)),
            content,
            TestContext.Current.CancellationToken);

        // The outer type differs by path — a response with a body surfaces the failure while its
        // content is copied, a bodyless redirect surfaces it directly — so the assertion is on the
        // cause, which is the same for both.
        var thrown = (await post.Should().ThrowAsync<Exception>()).Which;

        // Narrowed to the type as well as the wording: matching the message alone would accept any
        // failure that happened to carry the phrase, and matching the type alone would accept any
        // InvalidOperationException from anywhere in the request — including the interaction
        // refusals this class exercises next door. If a framework upgrade rewords this, the test
        // fails loudly and the substring is what needs editing.
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
            response.ShouldHaveReachedConsent();
    }
}
