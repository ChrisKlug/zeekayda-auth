using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;
using Microsoft.Extensions.Time.Testing;
using Microsoft.Net.Http.Headers;
using ZeeKayDa.Auth.AspNetCore.Interaction;

namespace ZeeKayDa.Auth.AspNetCore.Tests.Interaction;

/// <summary>
/// The accounts one browser's session cookie holds: how they join and leave it, how long each
/// lives, and which of them answers a request.
/// </summary>
public sealed class SsoSessionAccountsTests : IDisposable
{
    private const string Alice = "alice";
    private const string Bob = "bob";
    private const string Carol = "carol";
    private const string Dave = "dave";

    private static readonly DateTimeOffset Start = new(2026, 10, 17, 12, 0, 0, TimeSpan.Zero);

    private readonly List<BrowserWithSession> _browsers = [];

    public void Dispose()
    {
        foreach (var browser in _browsers)
            browser.Dispose();
    }

    private BrowserWithSession NewBrowser(int? maxSignedInAccounts = null)
    {
        var browser = new BrowserWithSession(maxSignedInAccounts);
        _browsers.Add(browser);

        return browser;
    }

    private static string[] Subjects(SsoSessionList sessions) => [.. sessions.Accounts.Select(account => account.Subject)];

    // ── Joining: add and replace ──────────────────────────────────────────────────────────────────

    [Fact]
    public async Task A_promotion_that_adds_keeps_the_accounts_already_held_with_the_newest_first()
    {
        var browser = NewBrowser();
        await browser.SignInAsync(Alice);

        await browser.SignInAsync(Bob, addAccount: true);

        Subjects(await browser.ReadAsync()).Should().Equal(Bob, Alice);
    }

    [Fact]
    public async Task A_promotion_that_does_not_add_replaces_the_accounts_held()
    {
        var browser = NewBrowser();
        await browser.SignInAsync(Alice);
        await browser.SignInAsync(Bob, addAccount: true);

        await browser.SignInAsync(Carol, addAccount: false);

        Subjects(await browser.ReadAsync()).Should().Equal(Carol);
    }

    [Theory]
    [InlineData(true)]
    [InlineData(false)]
    public async Task Signing_in_again_as_a_held_account_keeps_its_session_id(bool addAccount)
    {
        var browser = NewBrowser();
        var first = await browser.SignInAsync(Alice);
        await browser.SignInAsync(Bob, addAccount: true);

        var again = await browser.SignInAsync(Alice, addAccount);

        again.SessionId.Should().Be(first.SessionId);
        (await browser.ReadAsync()).Find(Alice)!.SessionId.Should().Be(first.SessionId);
    }

    [Fact]
    public async Task Signing_in_as_an_account_the_browser_does_not_hold_mints_a_new_session_id()
    {
        var browser = NewBrowser();
        var alice = await browser.SignInAsync(Alice);

        var bob = await browser.SignInAsync(Bob, addAccount: true);

        bob.SessionId.Should().NotBe(alice.SessionId);
    }

    [Fact]
    public async Task Adding_past_the_limit_signs_out_the_account_signed_in_to_least_recently()
    {
        var browser = NewBrowser(maxSignedInAccounts: 2);
        await browser.SignInAsync(Alice);
        await browser.SignInAsync(Bob, addAccount: true);

        await browser.SignInAsync(Carol, addAccount: true);

        Subjects(await browser.ReadAsync()).Should().Equal(Carol, Bob);
    }

    [Fact]
    public async Task Adding_past_the_limit_keeps_an_older_account_that_was_chosen_since()
    {
        var browser = NewBrowser(maxSignedInAccounts: 3);
        await browser.SignInAsync(Alice);
        await browser.SignInAsync(Bob, addAccount: true);
        await browser.SignInAsync(Carol, addAccount: true);
        await browser.ChooseAsync(Alice, "client-2");

        await browser.SignInAsync(Dave, addAccount: true);

        Subjects(await browser.ReadAsync()).Should().Equal(Dave, Alice, Carol);
    }

    // ── Choosing ──────────────────────────────────────────────────────────────────────────────────

    [Fact]
    public async Task Choosing_an_account_makes_it_the_clients_own_and_the_most_recently_used()
    {
        var browser = NewBrowser();
        await browser.SignInAsync(Alice, clientId: "client-1");
        await browser.SignInAsync(Bob, addAccount: true, clientId: "client-1");

        await browser.ChooseAsync(Alice, "client-1");

        var sessions = await browser.ReadAsync();
        Subjects(sessions).Should().Equal(Alice, Bob);
        sessions.DefaultFor("client-1")!.Subject.Should().Be(Alice);
    }

    [Fact]
    public async Task Choosing_the_account_a_client_already_has_writes_no_cookie()
    {
        var browser = NewBrowser();
        await browser.SignInAsync(Alice, clientId: "client-1");
        await browser.SignInAsync(Bob, addAccount: true, clientId: "client-2");
        await browser.ChooseAsync(Alice, "client-1");
        browser.WroteCookie.Should().BeFalse("alice is already client-1's account, so the choice changes nothing");

        await browser.ChooseAsync(Alice, "client-3");

        browser.WroteCookie.Should().BeTrue("a client with no remembered account has one to record");
    }

    // ── Lifetime ──────────────────────────────────────────────────────────────────────────────────

    [Fact]
    public async Task An_account_past_the_cookie_lifetime_from_its_own_sign_in_is_dropped_while_a_newer_one_stays()
    {
        var browser = NewBrowser();
        await browser.SignInAsync(Alice);
        browser.Time.Advance(TimeSpan.FromDays(10));
        await browser.SignInAsync(Bob, addAccount: true);

        browser.Time.Advance(TimeSpan.FromDays(5));

        Subjects(await browser.ReadAsync()).Should().Equal(Bob);
    }

    [Fact]
    public async Task An_account_is_held_until_the_instant_its_lifetime_ends()
    {
        var browser = NewBrowser();
        await browser.SignInAsync(Alice);
        browser.Time.Advance(browser.Lifetime - TimeSpan.FromSeconds(1));
        Subjects(await browser.ReadAsync()).Should().Equal(Alice);

        browser.Time.Advance(TimeSpan.FromSeconds(1));

        (await browser.ReadAsync()).IsEmpty.Should().BeTrue();
    }

    [Fact]
    public async Task Choosing_an_older_account_does_not_extend_its_life_and_the_ticket_expires_with_the_newest_account()
    {
        var browser = NewBrowser();
        await browser.SignInAsync(Alice);
        browser.Time.Advance(TimeSpan.FromDays(10));
        var bob = await browser.SignInAsync(Bob, addAccount: true);
        browser.Time.Advance(TimeSpan.FromDays(2));

        await browser.ChooseAsync(Alice, "client-2");

        (await browser.TicketExpiryAsync()).Should().Be(bob.AuthTime + browser.Lifetime);
        browser.Time.Advance(TimeSpan.FromDays(3));
        Subjects(await browser.ReadAsync()).Should().Equal(Bob);
    }

    [Fact]
    public async Task Ending_another_account_does_not_extend_the_life_of_those_that_remain()
    {
        var browser = NewBrowser();
        await browser.SignInAsync(Alice);
        browser.Time.Advance(TimeSpan.FromDays(1));
        await browser.SignInAsync(Carol, addAccount: true);
        browser.Time.Advance(TimeSpan.FromDays(9));
        var bob = await browser.SignInAsync(Bob, addAccount: true);
        browser.Time.Advance(TimeSpan.FromDays(2));

        await browser.EndAsync(Carol);

        (await browser.TicketExpiryAsync()).Should().Be(bob.AuthTime + browser.Lifetime);
        browser.Time.Advance(TimeSpan.FromDays(3));
        Subjects(await browser.ReadAsync()).Should().Equal(Bob);
    }

    // ── Leaving ───────────────────────────────────────────────────────────────────────────────────

    [Fact]
    public async Task Ending_an_account_removes_that_account_only()
    {
        var browser = NewBrowser();
        await browser.SignInAsync(Alice);
        await browser.SignInAsync(Bob, addAccount: true);

        await browser.EndAsync(Bob);

        Subjects(await browser.ReadAsync()).Should().Equal(Alice);
    }

    [Fact]
    public async Task Ending_the_last_account_deletes_the_cookie()
    {
        var browser = NewBrowser();
        await browser.SignInAsync(Alice);

        await browser.EndAsync(Alice);

        browser.HoldsSessionCookie.Should().BeFalse();
        (await browser.ReadAsync()).IsEmpty.Should().BeTrue();
    }

    [Fact]
    public async Task Ending_an_account_forgets_the_clients_that_were_answered_by_it()
    {
        var browser = NewBrowser();
        await browser.SignInAsync(Alice, clientId: "client-1");
        await browser.SignInAsync(Bob, addAccount: true, clientId: "client-2");

        await browser.EndAsync(Alice);

        (await browser.ReadAsync()).Clients.Select(client => client.ClientId).Should().Equal("client-2");
    }

    // ── Remembered clients ────────────────────────────────────────────────────────────────────────

    [Fact]
    public async Task Remembered_clients_are_capped_and_the_least_recently_answered_is_forgotten_first()
    {
        var browser = NewBrowser();
        var clientIds = Enumerable.Range(0, SsoSession.MaxRememberedClients + 1).Select(i => $"client-{i}").ToArray();
        foreach (var clientId in clientIds)
            await browser.SignInAsync(Alice, addAccount: true, clientId: clientId);

        var remembered = (await browser.ReadAsync()).Clients.Select(client => client.ClientId).ToArray();

        remembered.Should().HaveCount(SsoSession.MaxRememberedClients);
        remembered.Should().NotContain("client-0");
        remembered.Should().StartWith(clientIds[^1]);
    }

    // ── Which account answers ─────────────────────────────────────────────────────────────────────

    private static SsoSessionState Account(string subject, string? loginIdentifier, DateTimeOffset authTime) => new()
    {
        SessionId = "sid-" + subject,
        Subject = subject,
        AuthTime = authTime,
        Amr = [],
        LoginIdentifier = loginIdentifier,
    };

    private static SsoSessionList TwoAccounts(params ClientAccount[] clients) => new(
        [
            Account(Alice, "Alice@Example.com", Start),
            Account(Bob, loginIdentifier: null, Start.AddMinutes(5)),
        ],
        clients);

    [Fact]
    public void An_id_token_hint_wins_over_a_login_hint()
    {
        var selected = TwoAccounts().Select("client-1", requiredSubject: Alice, loginHint: Bob);

        selected!.Subject.Should().Be(Alice);
    }

    [Theory]
    [InlineData("alice@example.com", Alice)]
    [InlineData("ALICE@EXAMPLE.COM", Alice)]
    [InlineData(Bob, Bob)]
    public void A_login_hint_names_the_account_whose_login_identifier_or_subject_it_matches(string loginHint, string expected)
    {
        var selected = TwoAccounts().Select("client-1", requiredSubject: null, loginHint);

        selected!.Subject.Should().Be(expected);
    }

    [Theory]
    [InlineData("BOB")]
    [InlineData("ALICE")]
    [InlineData("carol")]
    public void A_login_hint_matches_a_subject_only_exactly_and_a_hint_naming_nobody_selects_nobody(string loginHint)
    {
        var selected = TwoAccounts().Select("client-1", requiredSubject: null, loginHint);

        selected.Should().BeNull();
    }

    [Fact]
    public void An_id_token_hint_naming_an_account_that_is_not_held_selects_nobody()
    {
        var selected = TwoAccounts().Select("client-1", requiredSubject: Carol, loginHint: null);

        selected.Should().BeNull();
    }

    [Fact]
    public void Without_a_hint_the_clients_own_account_answers_even_when_another_signed_in_later()
    {
        var sessions = TwoAccounts(new ClientAccount("client-1", Alice));

        var selected = sessions.Select("client-1", requiredSubject: null, loginHint: null);

        selected!.Subject.Should().Be(Alice);
    }

    [Fact]
    public void Without_a_hint_a_client_with_no_account_of_its_own_gets_the_most_recently_signed_in()
    {
        var selected = TwoAccounts(new ClientAccount("client-1", Alice)).Select("client-2", requiredSubject: null, loginHint: null);

        selected!.Subject.Should().Be(Bob);
    }

    [Fact]
    public void Without_a_hint_a_client_whose_remembered_account_is_gone_gets_the_most_recently_signed_in()
    {
        var selected = TwoAccounts(new ClientAccount("client-1", Carol)).Select("client-1", requiredSubject: null, loginHint: null);

        selected!.Subject.Should().Be(Bob);
    }

    // ── Helpers ───────────────────────────────────────────────────────────────────────────────────

    /// <summary>
    /// One browser: a host on a clock the test moves, and the cookie jar that carries the session
    /// cookie from one request to the next as a real browser would.
    /// </summary>
    private sealed class BrowserWithSession : IDisposable
    {
        private readonly EndpointHost _host;
        private readonly Dictionary<string, string> _cookies = new(StringComparer.Ordinal);

        public BrowserWithSession(int? maxSignedInAccounts)
        {
            Time = new FakeTimeProvider(Start);
            _host = new EndpointHost(
                options =>
                {
                    if (maxSignedInAccounts is { } max)
                        options.AuthorizationEndpoint.Interaction.MaxSignedInAccounts = max;
                },
                builder => builder.Services.AddSingleton<TimeProvider>(Time));
        }

        public FakeTimeProvider Time { get; }

        /// <summary>Whether the last call set or deleted a cookie.</summary>
        public bool WroteCookie { get; private set; }

        public bool HoldsSessionCookie => _cookies.ContainsKey(ZeeKayDaCookies.Session);

        public TimeSpan Lifetime =>
            _host.Resolve<IOptionsMonitor<CookieAuthenticationOptions>>().Get(ZeeKayDaCookies.Session).ExpireTimeSpan;

        public void Dispose() => _host.Dispose();

        public Task<SsoSessionState> SignInAsync(
            string subject,
            bool addAccount = false,
            string? loginIdentifier = null,
            string clientId = "client-1") =>
            UseAsync((context, session) => session.PromoteAsync(
                context,
                new SignIn(SessionSubject.From(subject), [], ProviderScheme: null, loginIdentifier, addAccount),
                clientId));

        public Task<SsoSessionList> ReadAsync() => UseAsync((context, session) => session.ReadAsync(context));

        public Task ChooseAsync(string subject, string clientId) =>
            UseAsync(async (context, session) =>
            {
                var sessions = await session.ReadAsync(context);
                await session.ChooseAsync(context, sessions, sessions.Find(subject)!, clientId);

                return true;
            });

        public Task EndAsync(string subject) =>
            UseAsync(async (context, session) =>
            {
                var sessions = await session.ReadAsync(context);
                await session.EndAsync(context, sessions, sessions.Find(subject)!);

                return true;
            });

        /// <summary>When the session ticket in the cookie expires.</summary>
        public Task<DateTimeOffset?> TicketExpiryAsync() =>
            UseAsync(async (context, _) => (await context.AuthenticateAsync(ZeeKayDaCookies.Session)).Properties?.ExpiresUtc);

        private async Task<T> UseAsync<T>(Func<HttpContext, SsoSession, Task<T>> action)
        {
            await _host.EnsureStartedAsync();
            await using var scope = _host.Services.CreateAsyncScope();

            var request = _host.Get("/sign-in");
            if (_cookies.Count > 0)
                request.WithHeader("Cookie", string.Join("; ", _cookies.Select(cookie => $"{cookie.Key}={cookie.Value}")));

            var context = request.Build(scope.ServiceProvider);
            var result = await action(context, scope.ServiceProvider.GetRequiredService<SsoSession>());

            Absorb(context);

            return result;
        }

        /// <summary>Applies the response's <c>Set-Cookie</c> headers to the jar: a value is kept, an empty one deletes.</summary>
        private void Absorb(HttpContext context)
        {
            var headers = context.Response.Headers.SetCookie;
            WroteCookie = headers.Count > 0;

            foreach (var cookie in SetCookieHeaderValue.ParseList([.. headers.OfType<string>()]))
            {
                var name = cookie.Name.Value!;
                if (cookie.Value.Value is { Length: > 0 } value)
                    _cookies[name] = value;
                else
                    _cookies.Remove(name);
            }
        }
    }
}
