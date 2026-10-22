using System.Net;
using ZeeKayDa.Auth.Authorization;
using static ZeeKayDa.Auth.AspNetCore.Tests.Interaction.MultiAccountBrowser;
using static ZeeKayDa.Auth.AspNetCore.Tests.Interaction.MultiAccountHost;

namespace ZeeKayDa.Auth.AspNetCore.Tests.Interaction;

/// <summary>
/// What a login page can do with several accounts in one browser: add one beside those held or
/// replace them, name the identifier a client's <c>login_hint</c> will match, and see who is signed in.
/// </summary>
public sealed class LoginInteractionAccountsTests : IClassFixture<MultiAccountHostFixture>
{
    private readonly MultiAccountHostFixture _host;
    private readonly MultiAccountBrowser _browser;

    public LoginInteractionAccountsTests(MultiAccountHostFixture host)
    {
        host.Reset();
        _host = host;
        _browser = new MultiAccountBrowser(host.NewFlowClient());
    }

    public static TheoryData<string> RefusedLoginIdentifiers => new()
    {
        new string('a', 257),
        string.Empty,
        "   ",
        "alice\n@example.com",
        "alice\t@example.com",
        "alice\u2028@example.com",
        "alice\u200B@example.com",
    };

    // ── Adding and replacing ──────────────────────────────────────────────────────────────────────

    [Fact]
    public async Task AddAccountAsync_keeps_the_previous_account_and_both_answer_their_own_hint()
    {
        var alicesHint = await _browser.IdTokenForAsync(Alice, add: false);
        var bobsHint = await _browser.IdTokenForAsync(Bob, add: true);

        var session = await _browser.ReadSessionAsync();
        var forAlice = await _browser.AuthorizeAsync(prompt: "none", idTokenHint: alicesHint);
        var forBob = await _browser.AuthorizeAsync(prompt: "none", idTokenHint: bobsHint);

        session.Subjects.Should().Equal(Bob, Alice);
        (await _browser.SubjectAnsweredAsync(forAlice)).Should().Be(Alice);
        (await _browser.SubjectAnsweredAsync(forBob)).Should().Be(Bob);
    }

    [Fact]
    public async Task SignInAsync_replaces_the_previous_account_so_its_hint_is_answered_login_required()
    {
        var alicesHint = await _browser.IdTokenForAsync(Alice, add: false);
        await _browser.SignInAsync(Bob, add: false);

        var session = await _browser.ReadSessionAsync();
        var forAlice = await _browser.AuthorizeAsync(prompt: "none", idTokenHint: alicesHint);

        session.Subjects.Should().Equal(Bob);
        QueryAtClient(forAlice)["error"].ToString().Should().Be(AuthorizeRequestErrors.LoginRequired);
    }

    // ── The login identifier ──────────────────────────────────────────────────────────────────────

    [Theory]
    [MemberData(nameof(RefusedLoginIdentifiers))]
    public async Task A_login_identifier_a_login_hint_would_be_refused_is_refused_naming_the_parameter(string loginIdentifier)
    {
        var login = await _browser.AuthorizeAsync(prompt: "login");

        var signIn = async () => await _browser.PostLoginAsync(Location(login), Alice, add: true, loginIdentifier);

        (await signIn.Should().ThrowAsync<ArgumentException>()).Which.ParamName.Should().Be("loginIdentifier");
        (await _browser.ReadSessionAsync()).Accounts.Should().BeEmpty("a refused identifier signs nobody in");
    }

    [Fact]
    public async Task A_login_identifier_of_the_longest_length_a_login_hint_may_have_is_accepted()
    {
        var loginIdentifier = new string('a', 256);

        await _browser.SignInAsync(Alice, loginIdentifier: loginIdentifier);

        (await _browser.ReadSessionAsync()).Accounts.Should().ContainSingle().Which.LoginId.Should().Be(loginIdentifier);
    }

    [Fact]
    public async Task No_login_identifier_is_accepted_and_the_account_holds_none()
    {
        await _browser.SignInAsync(Alice, loginIdentifier: null);

        (await _browser.ReadSessionAsync()).Accounts.Should().ContainSingle().Which.LoginId.Should().BeNull();
    }

    // ── What the login page is told ───────────────────────────────────────────────────────────────

    [Fact]
    public async Task LoginRequest_lists_the_accounts_the_browser_holds()
    {
        await _browser.SignInAsync(Alice, loginIdentifier: "alice@example.com");
        await _browser.SignInAsync(Bob);
        var login = await _browser.AuthorizeAsync(prompt: "login");

        var page = await _browser.GetPageAsync(Location(login));

        page.GetProperty("accounts").EnumerateArray()
            .Select(account => (account.GetProperty("subject").GetString(), account.GetProperty("loginIdentifier").GetString()))
            .Should().BeEquivalentTo([(Alice, "alice@example.com"), (Bob, Bob)]);
    }

    [Fact]
    public async Task ReauthenticationRequired_is_judged_against_the_account_the_request_selects_not_the_freshest_in_the_browser()
    {
        var alicesHint = await _browser.IdTokenForAsync(Alice);
        _host.Time.Advance(TimeSpan.FromMinutes(2));
        await _browser.SignInAsync(Bob);
        var login = await _browser.AuthorizeAsync(idTokenHint: alicesHint, maxAge: "60");
        ShouldHaveGoneTo(login, LoginPath);

        var page = await _browser.GetPageAsync(Location(login));

        page.GetProperty("reauthenticationRequired").GetBoolean().Should().BeTrue("alice signed in two minutes ago, bob's fresher sign-in notwithstanding");
    }

    [Fact]
    public async Task ReauthenticationRequired_is_false_when_the_request_demands_no_fresh_sign_in()
    {
        await _browser.SignInAsync(Alice, loginIdentifier: "alice@example.com");
        var login = await _browser.AuthorizeAsync(loginHint: "carol@example.com");
        ShouldHaveGoneTo(login, LoginPath);

        var page = await _browser.GetPageAsync(Location(login));

        page.GetProperty("reauthenticationRequired").GetBoolean().Should().BeFalse();
    }

    // ── When the user authenticated ───────────────────────────────────────────────────────────────

    [Fact]
    public async Task A_sign_in_from_an_earlier_authentication_sends_a_later_max_age_request_to_authenticate_again()
    {
        var signedIn = await _browser.SignInFromHostCookieAsync(Alice, _host.Time.GetUtcNow().AddMinutes(-10));
        var alicesHint = await _browser.RedeemAsync(signedIn.ShouldHaveIssuedCodeTo(Redirect));
        var login = await _browser.AuthorizeAsync(idTokenHint: alicesHint, maxAge: "300");
        ShouldHaveGoneTo(login, LoginPath);

        var page = await _browser.GetPageAsync(Location(login));

        page.GetProperty("reauthenticationRequired").GetBoolean().Should().BeTrue("alice authenticated ten minutes ago, though the page signed her in just now");
    }

    [Fact]
    public async Task An_authentication_time_in_the_future_is_taken_as_now_so_it_cannot_satisfy_a_later_max_age()
    {
        var signedIn = await _browser.SignInFromHostCookieAsync(Alice, _host.Time.GetUtcNow().AddDays(1));
        var alicesHint = await _browser.RedeemAsync(signedIn.ShouldHaveIssuedCodeTo(Redirect));
        _host.Time.Advance(TimeSpan.FromMinutes(10));

        var login = await _browser.AuthorizeAsync(idTokenHint: alicesHint, maxAge: "300");

        ShouldHaveGoneTo(login, LoginPath);
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task The_ID_token_auth_time_is_when_the_page_says_the_user_authenticated(bool add)
    {
        var authenticatedAt = _host.Time.GetUtcNow().AddHours(-2);

        var signedIn = await _browser.SignInFromHostCookieAsync(Alice, authenticatedAt, add);

        AuthTimeOf(await _browser.RedeemAsync(signedIn.ShouldHaveIssuedCodeTo(Redirect))).Should().Be(authenticatedAt);
    }

    [Fact]
    public async Task Given_max_age_a_sign_in_authenticated_longer_ago_than_it_is_refused_and_issues_no_code()
    {
        var login = await _browser.AuthorizeAsync(maxAge: "300");
        ShouldHaveGoneTo(login, LoginPath);

        var signIn = async () => await _browser.PostLoginAsync(Location(login), Alice, authenticatedAt: _host.Time.GetUtcNow().AddMinutes(-10));

        await signIn.Should().ThrowAsync<ZeeKayDaInteractionException>().WithMessage("*max_age*");
        (await _browser.ReadSessionAsync()).Accounts.Should().BeEmpty();
    }

    [Fact]
    public async Task Given_max_age_a_sign_in_authenticated_within_it_issues_a_code()
    {
        var login = await _browser.AuthorizeAsync(maxAge: "300");
        ShouldHaveGoneTo(login, LoginPath);

        var signedIn = await _browser.PostLoginAsync(Location(login), Alice, authenticatedAt: _host.Time.GetUtcNow().AddMinutes(-4));

        signedIn.ShouldHaveIssuedCodeTo(Redirect);
    }

    [Fact]
    public async Task Given_max_age_zero_a_sign_in_authenticated_after_the_request_issues_a_code()
    {
        var login = await _browser.AuthorizeAsync(maxAge: "0");
        ShouldHaveGoneTo(login, LoginPath);
        _host.Time.Advance(TimeSpan.FromSeconds(20));
        var authenticatedAt = _host.Time.GetUtcNow();
        _host.Time.Advance(TimeSpan.FromSeconds(1));

        var signedIn = await _browser.PostLoginAsync(Location(login), Alice, authenticatedAt: authenticatedAt);

        signedIn.ShouldHaveIssuedCodeTo(Redirect);
    }

    [Fact]
    public async Task Given_max_age_zero_a_sign_in_authenticated_before_the_request_is_refused()
    {
        var authenticatedAt = _host.Time.GetUtcNow();
        _host.Time.Advance(TimeSpan.FromSeconds(1));
        var login = await _browser.AuthorizeAsync(maxAge: "0");
        ShouldHaveGoneTo(login, LoginPath);

        var signIn = async () => await _browser.PostLoginAsync(Location(login), Alice, authenticatedAt: authenticatedAt);

        await signIn.Should().ThrowAsync<ZeeKayDaInteractionException>();
        (await _browser.ReadSessionAsync()).Accounts.Should().BeEmpty();
    }

    [Fact]
    public async Task Given_prompt_login_a_sign_in_authenticated_before_the_request_is_refused()
    {
        var authenticatedAt = _host.Time.GetUtcNow();
        _host.Time.Advance(TimeSpan.FromSeconds(30));
        var login = await _browser.AuthorizeAsync(prompt: "login");
        ShouldHaveGoneTo(login, LoginPath);

        var signIn = async () => await _browser.PostLoginAsync(Location(login), Alice, authenticatedAt: authenticatedAt);

        await signIn.Should().ThrowAsync<ZeeKayDaInteractionException>().WithMessage("*prompt=login*");
        (await _browser.ReadSessionAsync()).Accounts.Should().BeEmpty();
    }
}
