using System.Net;
using System.Security.Claims;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Time.Testing;
using ZeeKayDa.Auth.AspNetCore.Endpoints;
using ZeeKayDa.Auth.AspNetCore.Interaction;
using ZeeKayDa.Auth.AspNetCore.Tests.Interaction;
using ZeeKayDa.Auth.Authorization;
using ZeeKayDa.Auth.Stores;

namespace ZeeKayDa.Auth.AspNetCore.Tests.Endpoints;

/// <summary>
/// What the end-session endpoint's handler and its confirmation page do with a request, without a
/// web host: the signed-out page, a post-logout redirect, the confirmation page's own rendering and
/// its POST, and the store failures either can hit. A session is established directly through
/// <see cref="SsoSession.PromoteAsync"/> — the same call a real sign-in makes — rather than through
/// the authorize/login/token round trip, and a small cookie jar carries what each response set
/// forward to the next request, the way a browser would.
/// </summary>
/// <remarks>
/// What still needs a real host: routing (whether the endpoint is served at all, case-sensitive
/// paths, the issuer-host constraint), the route group's own conventions (security headers,
/// <c>AllowAnonymous</c> against a fallback policy), a valid minted <c>id_token_hint</c> (hand-built
/// one would test the test, not the framework), and anything resolved from a real authorization
/// request in flight or a host-authored logout page. Those stay in
/// <see cref="EndSessionEndpointHostTests"/>.
/// </remarks>
public sealed class EndSessionEndpointTests
{
    private const string EndSessionPath = "/connect/endsession";
    private const string ConfirmPath = "/connect/endsession/confirm";
    private const string App = "app";
    private const string AppName = "Tom & Jerry <App>";
    private const string OtherApp = "other-app";
    private const string AppSignedOut = "https://app.example.com/signed-out";
    private const string OtherSignedOut = "https://other.example.com/signed-out";
    private const string Redirect = "https://test.example.com/callback";
    private const string State = "af0ifjsldkj";
    private const string SignedOutPath = "/account/signed-out";

    private static CancellationToken Cancellation => TestContext.Current.CancellationToken;

    // ── No session: nothing to ask ────────────────────────────────────────────────────────────────

    [Fact]
    public async Task Without_a_session_the_user_lands_on_the_framework_signed_out_page()
    {
        using var response = await EndSessionAsync(EndpointHost.Default, new());

        response.StatusCode.Should().Be(HttpStatusCode.OK);
        (await response.Content.ReadAsStringAsync(Cancellation)).Should().Contain("You have been signed out.");
        response.Headers.CacheControl!.NoStore.Should().BeTrue();
    }

    [Fact]
    public async Task The_framework_signed_out_page_cannot_be_framed()
    {
        using var response = await EndSessionAsync(EndpointHost.Default, new());

        response.Headers.GetValues("Content-Security-Policy").Should().Contain("frame-ancestors 'none'");
        response.Headers.GetValues("X-Frame-Options").Should().Equal("DENY");
    }

    [Fact]
    public async Task Without_a_session_a_registered_post_logout_redirect_uri_receives_the_user_and_state()
    {
        using var host = NewHost();

        using var response = await EndSessionAsync(host, new()
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
        using var host = NewHost();
        var request = host.Post(EndSessionPath).WithForm(new Dictionary<string, string>
        {
            ["client_id"] = App,
            ["post_logout_redirect_uri"] = AppSignedOut,
            ["state"] = State,
        });

        using var response = await host.InvokeAsync<EndSessionEndpoint>(e => e.HandleAsync, request);

        Location(response).Should().Be($"{AppSignedOut}?state={State}");
    }

    [Fact]
    public async Task A_post_that_is_not_form_encoded_is_read_as_carrying_nothing()
    {
        var request = EndpointHost.Default.Post(EndSessionPath)
            .WithBody("{\"client_id\":\"app\"}", "application/json");

        using var response = await EndpointHost.Default.InvokeAsync<EndSessionEndpoint>(e => e.HandleAsync, request);

        response.StatusCode.Should().Be(HttpStatusCode.OK, "a sign-out with no readable parameters still signs the user out");
    }

    [Theory]
    [InlineData("https://app.example.com/not-registered")]
    [InlineData(OtherSignedOut)]
    public async Task A_post_logout_redirect_uri_the_client_did_not_register_is_not_used(string postLogoutRedirectUri)
    {
        // The second case is registered — to a different client. A redirect URI is honoured only
        // against the registration of the client the request resolves to.
        using var host = NewHost();

        using var response = await EndSessionAsync(host, new()
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
        using var response = await EndSessionAsync(EndpointHost.Default, new() { ["post_logout_redirect_uri"] = AppSignedOut });

        response.StatusCode.Should().Be(HttpStatusCode.OK);
        response.Headers.Location.Should().BeNull();
    }

    [Fact]
    public async Task A_parameter_sent_twice_is_ignored()
    {
        using var host = NewHost();
        var request = host.Get(
            $"{EndSessionPath}?client_id={App}&client_id={App}&post_logout_redirect_uri={Uri.EscapeDataString(AppSignedOut)}");

        using var response = await host.InvokeAsync<EndSessionEndpoint>(e => e.HandleAsync, request);

        response.StatusCode.Should().Be(HttpStatusCode.OK, "with no single client_id there is no client to honour the redirect URI for");
    }

    [Fact]
    public async Task A_state_at_the_cap_is_echoed()
    {
        using var host = NewHost();
        var state = new string('s', EndSessionEndpoint.MaxStateLength);

        using var response = await EndSessionAsync(host, new()
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
        using var host = NewHost();

        using var response = await EndSessionAsync(host, new()
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
        using var host = new EndpointHost(options => options.EndSessionEndpoint.SignedOutPath = SignedOutPath);

        using var response = await EndSessionAsync(host, new());

        response.StatusCode.Should().Be(HttpStatusCode.Redirect);
        Location(response).Should().Be(SignedOutPath);
    }

    // ── With a session: the question ──────────────────────────────────────────────────────────────

    [Fact]
    public async Task With_a_session_and_no_hint_the_user_is_asked_first()
    {
        using var host = NewHost();
        var jar = await SignInAsync(host);

        var response = await EndSessionAsync(host, jar, new()
        {
            ["client_id"] = App,
            ["post_logout_redirect_uri"] = AppSignedOut,
            ["state"] = State,
        });

        response.StatusCode.Should().Be(HttpStatusCode.Redirect);
        Location(response).Should().StartWith($"{ConfirmPath}?{InteractionHandoff.InteractionIdParameter}=");
        (await HasSessionAsync(host, jar)).Should().BeTrue("nobody is signed out before they answer");
    }

    [Fact]
    public async Task The_framework_confirmation_page_names_the_client_encoded_and_cannot_be_framed()
    {
        using var host = NewHost();
        var jar = await SignInAsync(host);
        var asked = await EndSessionAsync(host, jar, new() { ["client_id"] = App });

        var page = await ConfirmGetAsync(host, jar, Location(asked));

        page.StatusCode.Should().Be(HttpStatusCode.OK);
        var html = await page.Content.ReadAsStringAsync(Cancellation);
        html.Should().Contain("<h1>Sign out of Tom &amp; Jerry &lt;App&gt;?</h1>");
        html.Should().Contain("<form method=\"post\">");
        page.Headers.GetValues("X-Frame-Options").Should().Contain("DENY");
    }

    [Fact]
    public async Task Without_a_client_the_confirmation_page_asks_plainly()
    {
        using var host = NewHost();
        var jar = await SignInAsync(host);
        var asked = await EndSessionAsync(host, jar, new());

        var page = await ConfirmGetAsync(host, jar, Location(asked));

        (await page.Content.ReadAsStringAsync(Cancellation)).Should().Contain("<h1>Sign out?</h1>");
    }

    [Fact]
    public async Task Confirming_ends_the_session_and_returns_the_user_to_the_client_with_state()
    {
        using var host = NewHost();
        var jar = await SignInAsync(host);
        var asked = await EndSessionAsync(host, jar, new()
        {
            ["client_id"] = App,
            ["post_logout_redirect_uri"] = AppSignedOut,
            ["state"] = State,
        });

        var confirmed = await ConfirmPostAsync(host, jar, Location(asked));

        confirmed.StatusCode.Should().Be(HttpStatusCode.Redirect);
        Location(confirmed).Should().Be($"{AppSignedOut}?state={State}");
        (await HasSessionAsync(host, jar)).Should().BeFalse();
    }

    [Fact]
    public async Task The_session_cookie_is_deleted_with_the_attributes_it_was_issued_with()
    {
        // A deletion whose path, Secure or SameSite differs from the original is a different
        // cookie to the browser, which keeps the session it was meant to end.
        using var host = NewHost();
        var jar = await SignInAsync(host);
        var asked = await EndSessionAsync(host, jar, new());

        var confirmed = await ConfirmPostAsync(host, jar, Location(asked));

        var deletion = SetCookieFor(confirmed, ZeeKayDaCookies.Session).ToLowerInvariant();
        deletion.Should().Contain("expires=thu, 01 jan 1970");
        deletion.Should().Contain("path=/;").And.Contain("secure").And.Contain("samesite=lax").And.Contain("httponly");
    }

    [Fact]
    public async Task A_confirmation_submitted_twice_ends_on_the_signed_out_page()
    {
        // A double-clicked Sign out: the first submission signed the user out, so the second has
        // nothing to confirm, and the truthful answer to it is the signed-out page.
        using var host = NewHost();
        var jar = await SignInAsync(host);
        var asked = await EndSessionAsync(host, jar, new());
        await ConfirmPostAsync(host, jar, Location(asked));

        var again = await ConfirmPostAsync(host, jar, Location(asked));

        again.StatusCode.Should().Be(HttpStatusCode.OK);
        (await again.Content.ReadAsStringAsync(Cancellation)).Should().Contain("You have been signed out.");
    }

    [Fact]
    public async Task A_confirmation_after_the_sign_out_expired_is_refused()
    {
        var time = new FakeTimeProvider(new DateTimeOffset(2026, 9, 16, 12, 0, 0, TimeSpan.Zero));
        using var host = NewHost(time);
        var jar = await SignInAsync(host);
        var asked = await EndSessionAsync(host, jar, new());

        time.Advance(LogoutRequestStore.Lifetime);
        var confirmed = await ConfirmPostAsync(host, jar, Location(asked));

        confirmed.StatusCode.Should().Be(HttpStatusCode.BadRequest);
        (await HasSessionAsync(host, jar)).Should().BeTrue();
    }

    [Fact]
    public async Task A_confirmation_is_refused_once_the_browser_holds_a_different_session()
    {
        // The answer to a question about one session is not an instruction about its replacement.
        // The browser is still signed in, so it is not shown the signed-out page either.
        //
        // The original scenario configures a host logout page; this asks the same question of the
        // framework's own confirmation page instead, since both end in the identical
        // ILogoutInteraction.SignOutAsync session check this test is about.
        using var host = NewHost();
        var jar = await SignInAsync(host);
        var asked = await EndSessionAsync(host, jar, new());

        // A fresh sign-in as someone else mints a new session identifier and leaves the open
        // confirmation's binding cookie alone, so only the session check can refuse it.
        await SignInAsync(host, subject: "user-2", jar: jar);

        var confirmed = await ConfirmPostAsync(host, jar, Location(asked));

        await confirmed.ShouldHaveFoundNothingToContinueAsync();
        (await HasSessionAsync(host, jar)).Should().BeTrue("the session nobody was asked about is left alone");
    }

    [Fact]
    public async Task A_confirmation_without_the_binding_cookie_signs_nobody_out()
    {
        // A cross-site form post does not carry the SameSite=Lax binding cookie. Even a request
        // that carries the session cookie and the right zkd_i — the identifier travels in a URL,
        // and URLs leak — finds nothing to confirm without it.
        using var host = NewHost();
        var jar = await SignInAsync(host);
        var asked = await EndSessionAsync(host, jar, new());

        var forged = jar.OnlyContaining(ZeeKayDaCookies.Session);
        var response = await ConfirmPostAsync(host, forged, Location(asked));

        response.StatusCode.Should().Be(HttpStatusCode.BadRequest);
        response.Headers.TryGetValues("Set-Cookie", out var cookies);
        (cookies ?? []).Should().NotContain(cookie => cookie.StartsWith(ZeeKayDaCookies.Session + "=", StringComparison.Ordinal));
        (await HasSessionAsync(host, jar)).Should().BeTrue();
    }

    [Fact]
    public async Task A_request_carrying_no_session_cookie_deletes_no_session()
    {
        // A cross-site form post carries no SameSite=Lax cookie. Answering it with a cookie
        // deletion would end the session without asking — the very thing the question exists for.
        using var host = NewHost();
        var jar = await SignInAsync(host);

        var response = await EndSessionEmptyPostAsync(host, CookieJar.Empty);

        response.StatusCode.Should().Be(HttpStatusCode.OK);
        response.Headers.Contains("Set-Cookie").Should().BeFalse();
        (await HasSessionAsync(host, jar)).Should().BeTrue("the browser holding the session was never asked");
    }

    // ── Store failures ────────────────────────────────────────────────────────────────────────────

    [Fact]
    public async Task A_sign_out_that_cannot_be_stored_for_confirmation_signs_nobody_out()
    {
        using var host = NewHostWithStore(new LogoutRefusingStore(refuseWrites: true));
        var jar = await SignInAsync(host);

        var response = await EndSessionAsync(host, jar, new());

        response.StatusCode.Should().Be(HttpStatusCode.InternalServerError);
        (await HasSessionAsync(host, jar)).Should().BeTrue("a user who could not be asked is not signed out");
    }

    [Fact]
    public async Task A_confirmation_page_whose_sign_out_cannot_be_read_signs_nobody_out()
    {
        using var host = NewHostWithStore(new LogoutRefusingStore(refuseReads: true));
        var jar = await SignInAsync(host);
        var asked = await EndSessionAsync(host, jar, new());

        var confirmed = await ConfirmPostAsync(host, jar, Location(asked));

        confirmed.StatusCode.Should().Be(HttpStatusCode.InternalServerError);
        (await HasSessionAsync(host, jar)).Should().BeTrue();
    }

    // ── Host and helpers ──────────────────────────────────────────────────────────────────────────

    /// <summary>
    /// A container with <c>App</c> and <c>OtherApp</c> registered, each with its own post-logout
    /// redirect URI, and — when <paramref name="time"/> is given — that clock in place of the real
    /// one, for the tests that advance it. A fresh instance per test isolates configuration; the
    /// tests here that establish a session write to the interaction store too, so isolating server
    /// state matters just as much as it did before <c>ConfirmAsync</c> was reachable.
    /// </summary>
    private static EndpointHost NewHost(TimeProvider? time = null) => new(configureBuilder: builder =>
    {
        if (time is not null)
            builder.Services.AddSingleton(time);

        builder.AddInMemoryClients(clients => clients
            .AddPublic(App, [Redirect], [AppSignedOut], ["openid"], client =>
            {
                client.RequireConsent = false;
                client.DisplayName = AppName;
            })
            .AddPublic(OtherApp, [Redirect], [OtherSignedOut], ["openid"], client => client.RequireConsent = false));
    });

    /// <summary>A container whose interaction store is <paramref name="store"/>, for the store-failure tests.</summary>
    private static EndpointHost NewHostWithStore(IInteractionBackingStore store) => new(configureBuilder: builder =>
    {
        builder.AddInMemoryAuthorizationCodeStore(allowOutsideDevelopment: true);
        builder.AddInMemoryRefreshTokenStore(allowOutsideDevelopment: true);
        builder.Services.AddSingleton(store);
    });

    private static Task<HttpResponseMessage> EndSessionAsync(EndpointHost host, Dictionary<string, string?> parameters) =>
        InvokeAsync(host, CookieJar.Empty, e => e.HandleAsync, host.Get(BuildPathAndQuery(EndSessionPath, parameters)));

    private static Task<HttpResponseMessage> EndSessionAsync(EndpointHost host, CookieJar jar, Dictionary<string, string?> parameters) =>
        InvokeAsync(host, jar, e => e.HandleAsync, host.Get(BuildPathAndQuery(EndSessionPath, parameters)));

    private static Task<HttpResponseMessage> EndSessionEmptyPostAsync(EndpointHost host, CookieJar jar) =>
        InvokeAsync(host, jar, e => e.HandleAsync, host.Post(EndSessionPath).WithForm([]));

    private static Task<HttpResponseMessage> ConfirmGetAsync(EndpointHost host, CookieJar jar, string location) =>
        InvokeAsync(host, jar, e => e.ConfirmAsync, host.Get(location));

    private static Task<HttpResponseMessage> ConfirmPostAsync(EndpointHost host, CookieJar jar, string location) =>
        InvokeAsync(host, jar, e => e.ConfirmAsync, host.Post(location).WithForm([]));

    private static async Task<HttpResponseMessage> InvokeAsync(
        EndpointHost host, CookieJar jar, Func<EndSessionEndpoint, Delegate> handler, TestRequest request)
    {
        if (jar.Header is { } cookie)
            request.WithHeader("Cookie", cookie);

        var response = await host.InvokeAsync<EndSessionEndpoint>(handler, request);
        jar.Apply(response);
        return response;
    }

    private static string BuildPathAndQuery(string path, Dictionary<string, string?> parameters)
    {
        var query = string.Join('&', parameters
            .Where(pair => pair.Value is not null)
            .Select(pair => $"{Uri.EscapeDataString(pair.Key)}={Uri.EscapeDataString(pair.Value!)}"));

        return query.Length == 0 ? path : $"{path}?{query}";
    }

    /// <summary>
    /// Establishes an SSO session the way a real sign-in does — through
    /// <see cref="SsoSession.PromoteAsync"/> — and returns a jar seeded with the resulting session
    /// cookie, or updates <paramref name="jar"/> in place and returns it, for a re-authentication
    /// over a session the browser already holds.
    /// </summary>
    private static async Task<CookieJar> SignInAsync(EndpointHost host, string subject = "user-1", CookieJar? jar = null)
    {
        jar ??= new CookieJar();

        await host.EnsureStartedAsync();
        await using var scope = host.Services.CreateAsyncScope();
        var context = host.Get("/sign-in").Build(scope.ServiceProvider);
        if (jar.Header is { } cookie)
            context.Request.Headers["Cookie"] = cookie;

        var principal = new ClaimsPrincipal(new ClaimsIdentity([new Claim("sub", subject)], "test"));
        await scope.ServiceProvider.GetRequiredService<SsoSession>()
            .PromoteAsync(context, principal, [AuthenticationMethods.Password]);

        jar.Apply(context);
        return jar;
    }

    /// <summary>Whether the encrypted session cookie <paramref name="jar"/> carries still authenticates.</summary>
    private static async Task<bool> HasSessionAsync(EndpointHost host, CookieJar jar)
    {
        await host.EnsureStartedAsync();
        await using var scope = host.Services.CreateAsyncScope();
        var context = host.Get("/session-probe").Build(scope.ServiceProvider);
        if (jar.Header is { } cookie)
            context.Request.Headers["Cookie"] = cookie;

        var result = await context.AuthenticateAsync(ZeeKayDaCookies.Session);
        return result.Succeeded;
    }

    private static string Location(HttpResponseMessage response) => response.Headers.Location!.OriginalString;

    private static string SetCookieFor(HttpResponseMessage response, string name) => response.Headers
        .GetValues("Set-Cookie")
        .Single(value => value.StartsWith(name + "=", StringComparison.Ordinal));

    /// <summary>
    /// A working in-memory store that refuses to hold, or to give back, sign-out requests.
    /// <see cref="TimeProvider.System"/> is enough here: neither store-failure test advances a
    /// clock, unlike the expiry test above.
    /// </summary>
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

    /// <summary>
    /// A minimal browser cookie jar: applies what a response set, dropping anything deleted, and
    /// hands back a single <c>Cookie</c> header for the next request — the part of cookie-jar
    /// semantics these tests depend on (a session or binding cookie the browser stops sending once
    /// the server deletes it).
    /// </summary>
    private sealed class CookieJar
    {
        private readonly Dictionary<string, string> _cookies = new(StringComparer.Ordinal);

        public static CookieJar Empty => new();

        /// <summary>A jar holding only the named cookie from this one, for a forged cross-site request.</summary>
        public CookieJar OnlyContaining(string name)
        {
            var isolated = new CookieJar();
            if (_cookies.TryGetValue(name, out var value))
                isolated._cookies[name] = value;

            return isolated;
        }

        public void Apply(HttpContext context) => Apply(context.Response.Headers["Set-Cookie"].OfType<string>());

        public void Apply(HttpResponseMessage response) =>
            Apply(response.Headers.TryGetValues("Set-Cookie", out var values) ? values : []);

        public string? Header => _cookies.Count == 0
            ? null
            : string.Join("; ", _cookies.Select(pair => $"{pair.Key}={pair.Value}"));

        private void Apply(IEnumerable<string> setCookies)
        {
            foreach (var setCookie in setCookies)
            {
                var pair = setCookie.Split(';')[0];
                var separator = pair.IndexOf('=');
                if (separator <= 0)
                    continue;

                var name = pair[..separator];
                if (setCookie.Contains("expires=Thu, 01 Jan 1970", StringComparison.Ordinal))
                    _cookies.Remove(name);
                else
                    _cookies[name] = pair[(separator + 1)..];
            }
        }
    }
}
