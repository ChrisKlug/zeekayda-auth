using System.Net;
using System.Security.Claims;
using System.Text.Json;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Routing;
using Microsoft.AspNetCore.WebUtilities;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Time.Testing;
using ZeeKayDa.Auth.AspNetCore.Endpoints;
using ZeeKayDa.Auth.AspNetCore.Interaction;
using ZeeKayDa.Auth.AspNetCore.Tests.Interaction;
using ZeeKayDa.Auth.Authorization;
using ZeeKayDa.Auth.Stores;

namespace ZeeKayDa.Auth.AspNetCore.Tests.Endpoints;

/// <summary>
/// Integration tests for RP-initiated logout: when the user is asked, what a confirmation is bound
/// to, where the user is sent afterwards, and what is left of the session.
/// </summary>
/// <remarks>
/// The test host maps a logout page written as a real one would be — a GET that reads
/// <see cref="ILogoutInteraction.GetRequestAsync"/> and a POST that ends in
/// <see cref="ILogoutInteraction.SignOutAsync"/> — for the tests that configure one, and a probe
/// that reports whether the encrypted session cookie still authenticates.
/// </remarks>
public sealed class EndSessionEndpointTests : IDisposable
{
    private const string EndSessionPath = "/connect/endsession";
    private const string ConfirmPath = "/connect/endsession/confirm";
    private const string TokenPath = "/connect/token";
    private const string LoginPath = "/account/login";
    private const string LogoutPath = "/account/logout";
    private const string SignOutByLinkPath = "/account/logout/by-link";
    private const string SignedOutPath = "/account/signed-out";
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

    private readonly FakeTimeProvider _time = new(new DateTimeOffset(2026, 9, 16, 12, 0, 0, TimeSpan.Zero));
    private readonly TestWebAppFactory _factory;
    private readonly HttpClient _client;

    public EndSessionEndpointTests()
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

    // ── No session: nothing to ask ────────────────────────────────────────────────────────────────

    [Fact]
    public async Task Without_a_session_the_user_lands_on_the_framework_signed_out_page()
    {
        var response = await EndSessionAsync(new());

        response.StatusCode.Should().Be(HttpStatusCode.OK);
        (await response.Content.ReadAsStringAsync(Cancellation)).Should().Contain("You have been signed out.");
        response.Headers.CacheControl!.NoStore.Should().BeTrue();
    }

    [Fact]
    public async Task Without_a_session_a_registered_post_logout_redirect_uri_receives_the_user_and_state()
    {
        var response = await EndSessionAsync(new()
        {
            ["client_id"] = App,
            ["post_logout_redirect_uri"] = AppSignedOut,
            ["state"] = State,
        });

        response.StatusCode.Should().Be(HttpStatusCode.Redirect);
        Location(response).Should().Be($"{AppSignedOut}?state={State}");
    }

    [Fact]
    public async Task A_sign_out_may_arrive_as_a_form_post()
    {
        using var form = new FormUrlEncodedContent(new Dictionary<string, string>
        {
            ["client_id"] = App,
            ["post_logout_redirect_uri"] = AppSignedOut,
            ["state"] = State,
        });

        var response = await _client.PostAsync(EndSessionPath, form, Cancellation);

        Location(response).Should().Be($"{AppSignedOut}?state={State}");
    }

    [Fact]
    public async Task A_post_that_is_not_form_encoded_is_read_as_carrying_nothing()
    {
        using var content = new StringContent("{\"client_id\":\"app\"}", System.Text.Encoding.UTF8, "application/json");

        var response = await _client.PostAsync(EndSessionPath, content, Cancellation);

        response.StatusCode.Should().Be(HttpStatusCode.OK, "a sign-out with no readable parameters still signs the user out");
    }

    [Theory]
    [InlineData("https://app.example.com/not-registered")]
    [InlineData(OtherSignedOut)]
    public async Task A_post_logout_redirect_uri_the_client_did_not_register_is_not_used(string postLogoutRedirectUri)
    {
        // The second case is registered — to a different client. A redirect URI is honoured only
        // against the registration of the client the request resolves to.
        var response = await EndSessionAsync(new()
        {
            ["client_id"] = App,
            ["post_logout_redirect_uri"] = postLogoutRedirectUri,
            ["state"] = State,
        });

        response.StatusCode.Should().Be(HttpStatusCode.OK, "the user is signed out, but sent nowhere the client did not register");
        response.Headers.Location.Should().BeNull();
    }

    [Fact]
    public async Task A_post_logout_redirect_uri_with_no_client_to_check_it_against_is_not_used()
    {
        var response = await EndSessionAsync(new() { ["post_logout_redirect_uri"] = AppSignedOut });

        response.StatusCode.Should().Be(HttpStatusCode.OK);
        response.Headers.Location.Should().BeNull();
    }

    [Fact]
    public async Task A_parameter_sent_twice_is_ignored()
    {
        var url = $"{EndSessionPath}?client_id={App}&client_id={App}&post_logout_redirect_uri={Uri.EscapeDataString(AppSignedOut)}";

        var response = await _client.GetAsync(url, Cancellation);

        response.StatusCode.Should().Be(HttpStatusCode.OK, "with no single client_id there is no client to honour the redirect URI for");
    }

    [Fact]
    public async Task A_state_at_the_cap_is_echoed()
    {
        var state = new string('s', EndSessionEndpoint.MaxStateLength);

        var response = await EndSessionAsync(new()
        {
            ["client_id"] = App,
            ["post_logout_redirect_uri"] = AppSignedOut,
            ["state"] = state,
        });

        Location(response).Should().Be($"{AppSignedOut}?state={state}");
    }

    [Fact]
    public async Task A_state_past_the_cap_sends_the_user_to_the_signed_out_page_instead_of_the_client()
    {
        var response = await EndSessionAsync(new()
        {
            ["client_id"] = App,
            ["post_logout_redirect_uri"] = AppSignedOut,
            ["state"] = new string('s', EndSessionEndpoint.MaxStateLength + 1),
        });

        response.StatusCode.Should().Be(HttpStatusCode.OK);
        response.Headers.Location.Should().BeNull();
    }

    [Fact]
    public async Task SignedOutPath_sends_the_user_to_the_host_page()
    {
        using var factory = NewFactory(options => options.SignedOutPath = SignedOutPath);
        using var client = NewClient(factory);

        var response = await EndSessionAsync(client, new());

        response.StatusCode.Should().Be(HttpStatusCode.Redirect);
        Location(response).Should().Be(SignedOutPath);
    }

    [Fact]
    public async Task The_endpoint_is_not_served_on_a_host_without_the_code_grant()
    {
        using var factory = new TestWebAppFactory(options => options.GrantTypesSupported = [GrantType.ClientCredentials]);
        using var client = NewClient(factory);

        var response = await client.GetAsync(EndSessionPath, Cancellation);

        response.StatusCode.Should().Be(HttpStatusCode.NotFound);
    }

    // ── With a session: the question ──────────────────────────────────────────────────────────────

    [Fact]
    public async Task With_a_session_and_no_hint_the_user_is_asked_first()
    {
        await SignInAsync(_client);

        var response = await EndSessionAsync(new()
        {
            ["client_id"] = App,
            ["post_logout_redirect_uri"] = AppSignedOut,
            ["state"] = State,
        });

        response.StatusCode.Should().Be(HttpStatusCode.Redirect);
        Location(response).Should().StartWith($"{ConfirmPath}?{InteractionHandoff.InteractionIdParameter}=");
        (await HasSessionAsync(_client)).Should().BeTrue("nobody is signed out before they answer");
    }

    [Fact]
    public async Task The_framework_confirmation_page_names_the_client_encoded_and_cannot_be_framed()
    {
        await SignInAsync(_client);
        var asked = await EndSessionAsync(new() { ["client_id"] = App });

        var page = await _client.GetAsync(Location(asked), Cancellation);

        page.StatusCode.Should().Be(HttpStatusCode.OK);
        var html = await page.Content.ReadAsStringAsync(Cancellation);
        html.Should().Contain("<h1>Sign out of Tom &amp; Jerry &lt;App&gt;?</h1>");
        html.Should().Contain("<form method=\"post\">");
        page.Headers.GetValues("X-Frame-Options").Should().Contain("DENY");
    }

    [Fact]
    public async Task Without_a_client_the_confirmation_page_asks_plainly()
    {
        await SignInAsync(_client);
        var asked = await EndSessionAsync(new());

        var page = await _client.GetAsync(Location(asked), Cancellation);

        (await page.Content.ReadAsStringAsync(Cancellation)).Should().Contain("<h1>Sign out?</h1>");
    }

    [Fact]
    public async Task Confirming_ends_the_session_and_returns_the_user_to_the_client_with_state()
    {
        await SignInAsync(_client);
        var asked = await EndSessionAsync(new()
        {
            ["client_id"] = App,
            ["post_logout_redirect_uri"] = AppSignedOut,
            ["state"] = State,
        });

        var confirmed = await PostEmptyFormAsync(_client, Location(asked));

        confirmed.StatusCode.Should().Be(HttpStatusCode.Redirect);
        Location(confirmed).Should().Be($"{AppSignedOut}?state={State}");
        (await HasSessionAsync(_client)).Should().BeFalse();
    }

    [Fact]
    public async Task The_session_cookie_is_deleted_with_the_attributes_it_was_issued_with()
    {
        // A deletion whose path, Secure or SameSite differs from the original is a different
        // cookie to the browser, which keeps the session it was meant to end.
        await SignInAsync(_client);
        var asked = await EndSessionAsync(new());

        var confirmed = await PostEmptyFormAsync(_client, Location(asked));

        var deletion = SetCookieFor(confirmed, ZeeKayDaCookies.Session).ToLowerInvariant();
        deletion.Should().Contain("expires=thu, 01 jan 1970");
        deletion.Should().Contain("path=/;").And.Contain("secure").And.Contain("samesite=lax").And.Contain("httponly");
    }

    [Fact]
    public async Task A_confirmation_is_answered_once()
    {
        await SignInAsync(_client);
        var asked = await EndSessionAsync(new());
        await PostEmptyFormAsync(_client, Location(asked));

        var again = await PostEmptyFormAsync(_client, Location(asked));

        again.StatusCode.Should().Be(HttpStatusCode.BadRequest);
        (await again.Content.ReadAsStringAsync(Cancellation)).Should().Contain("There is no sign-out to confirm.");
    }

    [Fact]
    public async Task A_confirmation_after_the_sign_out_expired_is_refused()
    {
        await SignInAsync(_client);
        var asked = await EndSessionAsync(new());

        _time.Advance(LogoutRequestStore.Lifetime);
        var confirmed = await PostEmptyFormAsync(_client, Location(asked));

        confirmed.StatusCode.Should().Be(HttpStatusCode.BadRequest);
        (await HasSessionAsync(_client)).Should().BeTrue();
    }

    [Fact]
    public async Task A_confirmation_is_refused_once_the_browser_holds_a_different_session()
    {
        // The answer to a question about one session is not an instruction about its replacement.
        await SignInAsync(_client);
        var asked = await EndSessionAsync(new());

        var other = await EndSessionAsync(new());
        await PostEmptyFormAsync(_client, Location(other));
        await SignInAsync(_client, App, subject: "user-2");

        var confirmed = await PostEmptyFormAsync(_client, Location(asked));

        confirmed.StatusCode.Should().Be(HttpStatusCode.BadRequest);
        (await HasSessionAsync(_client)).Should().BeTrue("the session nobody was asked about is left alone");
    }

    [Fact]
    public async Task A_confirmation_without_the_binding_cookie_signs_nobody_out()
    {
        // A cross-site form post does not carry the SameSite=Lax binding cookie. Even a request
        // that carries the session cookie and the right zkd_i — the identifier travels in a URL,
        // and URLs leak — finds nothing to confirm without it.
        var signIn = await SignInAsync(_client);
        var asked = await EndSessionAsync(new());

        using var forger = NewClient(_factory, handleCookies: false);
        using var forged = new HttpRequestMessage(HttpMethod.Post, Location(asked)) { Content = new FormUrlEncodedContent([]) };
        forged.Headers.Add("Cookie", CookiePairFrom(signIn, ZeeKayDaCookies.Session));
        var response = await forger.SendAsync(forged, Cancellation);

        response.StatusCode.Should().Be(HttpStatusCode.BadRequest);
        response.Headers.TryGetValues("Set-Cookie", out var cookies);
        (cookies ?? []).Should().NotContain(cookie => cookie.StartsWith(ZeeKayDaCookies.Session + "=", StringComparison.Ordinal));
        (await HasSessionAsync(_client)).Should().BeTrue();
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
    public async Task A_request_carrying_no_session_cookie_deletes_no_session()
    {
        // A cross-site form post carries no SameSite=Lax cookie. Answering it with a cookie
        // deletion would end the session without asking — the very thing the question exists for.
        await SignInAsync(_client);

        using var crossSite = NewClient(_factory, handleCookies: false);
        var response = await PostEmptyFormAsync(crossSite, EndSessionPath);

        response.StatusCode.Should().Be(HttpStatusCode.OK);
        response.Headers.Contains("Set-Cookie").Should().BeFalse();
        (await HasSessionAsync(_client)).Should().BeTrue("the browser holding the session was never asked");
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
        using var otherBrowser = NewClient(_factory);
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
        using var factory = NewFactory(options => options.LogoutPath = LogoutPath);
        using var client = NewClient(factory);
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
        }

        page.Headers.GetValues("X-Frame-Options").Should().Contain("DENY");

        var confirmed = await PostEmptyFormAsync(client, Location(asked));
        Location(confirmed).Should().Be($"{AppSignedOut}?state={State}");
        (await HasSessionAsync(client)).Should().BeFalse();
    }

    [Fact]
    public async Task A_host_logout_page_reached_for_a_sign_out_naming_no_client_is_given_none()
    {
        using var factory = NewFactory(options => options.LogoutPath = LogoutPath);
        using var client = NewClient(factory);
        await SignInAsync(client);
        var asked = await EndSessionAsync(client, new());

        var page = await client.GetAsync(Location(asked), Cancellation);

        using var body = JsonDocument.Parse(await page.Content.ReadAsStringAsync(Cancellation));
        body.RootElement.GetProperty("clientId").ValueKind.Should().Be(JsonValueKind.Null);
    }

    [Fact]
    public async Task A_host_with_its_own_logout_page_serves_no_framework_confirmation_route()
    {
        using var factory = NewFactory(options => options.LogoutPath = LogoutPath);
        using var client = NewClient(factory);

        var response = await client.GetAsync(ConfirmPath, Cancellation);

        response.StatusCode.Should().Be(HttpStatusCode.NotFound);
    }

    [Fact]
    public async Task SignOutAsync_from_a_GET_is_refused_and_signs_nobody_out()
    {
        // The framework reaches the logout page with a GET. A page that signed out in its render
        // handler would end the session the moment the user arrived, which is what the question
        // exists to prevent.
        using var factory = NewFactory(options => options.LogoutPath = LogoutPath);
        using var client = NewClient(factory);
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
        using var factory = NewFactory(options => options.LogoutPath = LogoutPath);
        using var client = NewClient(factory);

        var read = async () => await client.GetAsync(LogoutPath, Cancellation);

        await read.Should().ThrowAsync<ZeeKayDaInteractionException>();
    }

    // ── Store failures ────────────────────────────────────────────────────────────────────────────

    [Fact]
    public async Task A_sign_out_that_cannot_be_stored_for_confirmation_signs_nobody_out()
    {
        using var factory = NewFactory(store: new LogoutRefusingStore(refuseWrites: true));
        using var client = NewClient(factory);
        await SignInAsync(client);

        var response = await EndSessionAsync(client, new());

        response.StatusCode.Should().Be(HttpStatusCode.InternalServerError);
        (await HasSessionAsync(client)).Should().BeTrue("a user who could not be asked is not signed out");
    }

    [Fact]
    public async Task A_confirmation_page_whose_sign_out_cannot_be_read_signs_nobody_out()
    {
        using var factory = NewFactory(store: new LogoutRefusingStore(refuseReads: true));
        using var client = NewClient(factory);
        await SignInAsync(client);
        var asked = await EndSessionAsync(client, new());

        var confirmed = await PostEmptyFormAsync(client, Location(asked));

        confirmed.StatusCode.Should().Be(HttpStatusCode.InternalServerError);
        (await HasSessionAsync(client)).Should().BeTrue();
    }

    // ── Host and helpers ──────────────────────────────────────────────────────────────────────────

    private TestWebAppFactory NewFactory(
        Action<EndSessionEndpointOptions>? configure = null,
        IInteractionBackingStore? store = null) => new(
        configureOptions: options => configure?.Invoke(options.EndSessionEndpoint),
        configureBuilder: builder =>
        {
            builder.Services.AddSingleton<TimeProvider>(_time);

            if (store is not null)
            {
                builder.AddInMemoryAuthorizationCodeStore(allowOutsideDevelopment: true);
                builder.AddInMemoryRefreshTokenStore(allowOutsideDevelopment: true);
                builder.Services.AddSingleton(store);
            }

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
        },
        mapEndpoints: MapHostPages);

    private static HttpClient NewClient(TestWebAppFactory factory, bool handleCookies = true) => factory.CreateClient(new()
    {
        BaseAddress = new Uri("https://test.example.com"),
        AllowAutoRedirect = false,
        HandleCookies = handleCookies,
    });

    /// <summary>The host's pages: sign-in, a logout page, a miswired logout link, and a session probe.</summary>
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

        endpoints.MapGet(LogoutPath, async (HttpContext context, ILogoutInteraction logout) =>
        {
            var request = await logout.GetRequestAsync(context.RequestAborted);

            return Results.Ok(new { clientId = request.Client?.ClientId, displayName = request.Client?.DisplayName });
        });

        endpoints.MapPost(LogoutPath, (ILogoutInteraction logout) => logout.SignOutAsync());
        endpoints.MapGet(SignOutByLinkPath, (ILogoutInteraction logout) => logout.SignOutAsync());

        endpoints.MapGet(SessionProbePath, async (HttpContext context) =>
        {
            var result = await context.AuthenticateAsync(ZeeKayDaCookies.Session);

            return result.Succeeded ? Results.Ok() : Results.NotFound();
        });
    }

    private static string AuthorizeUrl(string clientId) =>
        QueryHelpers.AddQueryString("/connect/authorize", new Dictionary<string, string?>
        {
            ["client_id"] = clientId,
            ["redirect_uri"] = Redirect,
            ["response_type"] = "code",
            ["scope"] = "openid",
            ["nonce"] = Nonce,
            ["code_challenge"] = Challenge,
            ["code_challenge_method"] = "S256",
        });

    /// <summary>Signs the browser in through an authorization request for <paramref name="clientId"/>.</summary>
    private static async Task<HttpResponseMessage> SignInAsync(HttpClient client, string clientId = App, string subject = "user-1")
    {
        var authorize = await client.GetAsync(AuthorizeUrl(clientId), Cancellation);
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

    /// <summary>The <c>name=value</c> pair a browser would send back for the cookie the response set.</summary>
    private static string CookiePairFrom(HttpResponseMessage response, string name) =>
        SetCookieFor(response, name).Split(';')[0];

    /// <summary>A working in-memory store that refuses to hold, or to give back, sign-out requests.</summary>
    private sealed class LogoutRefusingStore(bool refuseWrites = false, bool refuseReads = false) : IInteractionBackingStore
    {
        private readonly InMemoryInteractionBackingStore _inner = new(TimeProvider.System);

        public ValueTask SetAsync(StoreKey key, ReadOnlyMemory<byte> value, DateTimeOffset expiresAt, CancellationToken cancellationToken) =>
            refuseWrites && IsLogout(key)
                ? throw new InvalidOperationException("The store is unavailable.")
                : _inner.SetAsync(key, value, expiresAt, cancellationToken);

        public ValueTask<ReadOnlyMemory<byte>?> GetAsync(StoreKey key, CancellationToken cancellationToken) =>
            refuseReads && IsLogout(key)
                ? throw new InvalidOperationException("The store is unavailable.")
                : _inner.GetAsync(key, cancellationToken);

        public ValueTask RemoveAsync(StoreKey key, CancellationToken cancellationToken) =>
            _inner.RemoveAsync(key, cancellationToken);

        private static bool IsLogout(StoreKey key) => key.ToString().StartsWith("zkd:interaction:l:", StringComparison.Ordinal);
    }
}
