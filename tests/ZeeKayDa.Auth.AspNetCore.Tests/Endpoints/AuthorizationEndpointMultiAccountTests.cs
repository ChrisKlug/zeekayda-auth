using ZeeKayDa.Auth.AspNetCore.Interaction;
using ZeeKayDa.Auth.AspNetCore.Tests.Interaction;
using ZeeKayDa.Auth.Authorization;
using static ZeeKayDa.Auth.AspNetCore.Tests.Interaction.MultiAccountBrowser;
using static ZeeKayDa.Auth.AspNetCore.Tests.Interaction.MultiAccountHost;

namespace ZeeKayDa.Auth.AspNetCore.Tests.Endpoints;

/// <summary>
/// One browser signed in as two users: which of them answers an authorization request, and when the
/// answer is a trip to the login page or the account picker instead (OIDC Core §3.1.2.1, §3.1.2.2,
/// §3.1.2.6). Every hint here is a real ID token the host minted.
/// </summary>
public sealed class AuthorizationEndpointMultiAccountTests
    : IClassFixture<MultiAccountHostFixture>, IClassFixture<MultiAccountNoPickerHostFixture>
{
    private const string AliceLoginId = "Alice@Example.com";
    private const string BobLoginId = "bob@example.com";

    private readonly MultiAccountHostFixture _host;
    private readonly MultiAccountBrowser _browser;
    private readonly MultiAccountBrowser _browserWithoutPicker;

    public AuthorizationEndpointMultiAccountTests(MultiAccountHostFixture host, MultiAccountNoPickerHostFixture noPicker)
    {
        host.Reset();
        noPicker.Reset();
        _host = host;
        _browser = new MultiAccountBrowser(host.NewFlowClient());
        _browserWithoutPicker = new MultiAccountBrowser(noPicker.NewFlowClient());
    }

    // ── The two-tab case ──────────────────────────────────────────────────────────────────────────

    [Theory]
    [InlineData(Alice)]
    [InlineData(Bob)]
    public async Task Prompt_none_with_the_hint_of_either_of_two_signed_in_accounts_issues_a_code_for_that_account(string subject)
    {
        var hints = new Dictionary<string, string>
        {
            [Alice] = await _browser.IdTokenForAsync(Alice),
            [Bob] = await _browser.IdTokenForAsync(Bob),
        };

        var response = await _browser.AuthorizeAsync(prompt: "none", idTokenHint: hints[subject]);

        (await _browser.SubjectAnsweredAsync(response)).Should().Be(subject);
    }

    // ── login_hint ────────────────────────────────────────────────────────────────────────────────

    [Fact]
    public async Task A_login_hint_matching_an_accounts_login_identifier_in_other_case_selects_that_account()
    {
        await _browser.SignInAsync(Alice, loginIdentifier: AliceLoginId);
        await _browser.SignInAsync(Bob, loginIdentifier: BobLoginId);

        var response = await _browser.AuthorizeAsync(prompt: "none", loginHint: AliceLoginId.ToUpperInvariant());

        (await _browser.SubjectAnsweredAsync(response)).Should().Be(Alice, "the client's own account is bob's, so only the hint can have chosen alice");
    }

    [Fact]
    public async Task A_login_hint_matching_no_account_sends_the_user_to_the_login_page()
    {
        await _browser.SignInAsync(Alice, loginIdentifier: AliceLoginId);
        await _browser.SignInAsync(Bob, loginIdentifier: BobLoginId);

        var response = await _browser.AuthorizeAsync(loginHint: "carol@example.com");

        ShouldHaveGoneTo(response, LoginPath);
    }

    [Fact]
    public async Task Prompt_none_with_a_login_hint_matching_no_account_is_answered_login_required()
    {
        await _browser.SignInAsync(Alice, loginIdentifier: AliceLoginId);
        await _browser.SignInAsync(Bob, loginIdentifier: BobLoginId);

        var response = await _browser.AuthorizeAsync(prompt: "none", loginHint: "carol@example.com");

        var query = QueryAtClient(response);
        query["error"].ToString().Should().Be(AuthorizeRequestErrors.LoginRequired);
        query.Should().NotContainKey("code");
    }

    // ── No hint ───────────────────────────────────────────────────────────────────────────────────

    [Fact]
    public async Task Without_a_hint_a_client_keeps_the_account_it_was_last_answered_for_after_another_account_is_added()
    {
        await _browser.SignInAsync(Alice, clientId: App);
        _host.Time.Advance(TimeSpan.FromMinutes(1));
        await _browser.SignInAsync(Bob, clientId: OtherApp);

        var response = await _browser.AuthorizeAsync(App, prompt: "none");

        (await _browser.SubjectAnsweredAsync(response)).Should().Be(Alice);
    }

    [Fact]
    public async Task Without_a_hint_a_client_the_browser_has_never_used_gets_the_most_recently_signed_in_account()
    {
        await _browser.SignInAsync(Alice, clientId: App);
        _host.Time.Advance(TimeSpan.FromMinutes(1));
        await _browser.SignInAsync(Bob, clientId: OtherApp);

        var response = await _browser.AuthorizeAsync(TrustedApp, prompt: "none");

        (await _browser.SubjectAnsweredAsync(response, TrustedApp)).Should().Be(Bob);
    }

    [Fact]
    public async Task A_client_answered_silently_follows_the_most_recent_sign_in_until_it_signs_in_or_picks()
    {
        await _browser.SignInAsync(Alice, clientId: App);
        _host.Time.Advance(TimeSpan.FromMinutes(1));
        await _browser.SignInAsync(Bob, clientId: OtherApp);
        (await _browser.SubjectAnsweredAsync(await _browser.AuthorizeAsync(TrustedApp, prompt: "none"), TrustedApp)).Should().Be(Bob);
        _host.Time.Advance(TimeSpan.FromMinutes(1));
        await _browser.SignInAsync(Carol, clientId: App);

        var response = await _browser.AuthorizeAsync(TrustedApp, prompt: "none");

        (await _browser.SubjectAnsweredAsync(response, TrustedApp)).Should().Be(Carol, "a silent answer is not remembered for the client");
    }

    [Fact]
    public async Task A_silent_answer_writes_no_session_cookie_so_a_refresh_cannot_undo_a_sign_out()
    {
        var alicesHint = await _browser.IdTokenForAsync(Alice, clientId: App);
        await _browser.SignInAsync(Bob, clientId: App);

        var response = await _browser.AuthorizeAsync(App, prompt: "none", idTokenHint: alicesHint);

        response.Headers.TryGetValues("Set-Cookie", out var cookies);
        (cookies ?? []).Should().NotContain(cookie => cookie.StartsWith(ZeeKayDaCookies.Session, StringComparison.Ordinal));
        (await _browser.SubjectAnsweredAsync(response)).Should().Be(Alice);
    }

    // ── max_age ───────────────────────────────────────────────────────────────────────────────────

    [Fact]
    public async Task Max_age_is_judged_against_the_account_the_hint_names_so_an_old_account_goes_to_the_login_page()
    {
        var alicesHint = await _browser.IdTokenForAsync(Alice);
        _host.Time.Advance(TimeSpan.FromMinutes(2));
        await _browser.SignInAsync(Bob);

        var response = await _browser.AuthorizeAsync(idTokenHint: alicesHint, maxAge: "60");

        ShouldHaveGoneTo(response, LoginPath);
    }

    [Fact]
    public async Task Max_age_is_judged_against_the_account_the_hint_names_so_a_fresh_account_is_answered_without_signing_in_again()
    {
        await _browser.SignInAsync(Alice);
        _host.Time.Advance(TimeSpan.FromMinutes(2));
        var bobsHint = await _browser.IdTokenForAsync(Bob);

        var response = await _browser.AuthorizeAsync(idTokenHint: bobsHint, maxAge: "60");

        (await _browser.SubjectAnsweredAsync(response)).Should().Be(Bob);
    }

    // ── prompt=select_account ─────────────────────────────────────────────────────────────────────

    [Fact]
    public async Task Prompt_select_account_on_a_server_without_a_picker_is_answered_account_selection_required()
    {
        await _browserWithoutPicker.SignInAsync(Alice);

        var response = await _browserWithoutPicker.AuthorizeAsync(prompt: "select_account");

        var query = QueryAtClient(response);
        query["error"].ToString().Should().Be(AuthorizeRequestErrors.AccountSelectionRequired);
        query.Should().NotContainKey("code");
    }

    [Fact]
    public async Task Prompt_select_account_with_accounts_held_sends_the_browser_to_the_picker()
    {
        await _browser.SignInAsync(Alice);
        await _browser.SignInAsync(Bob);

        var response = await _browser.AuthorizeAsync(prompt: "select_account");

        ShouldHaveGoneTo(response, SelectPath);
    }

    [Fact]
    public async Task Prompt_select_account_with_no_account_held_sends_the_browser_to_the_login_page()
    {
        var response = await _browser.AuthorizeAsync(prompt: "select_account");

        ShouldHaveGoneTo(response, LoginPath);
    }

    [Fact]
    public async Task Prompt_select_account_with_prompt_login_sends_the_browser_to_the_login_page_though_accounts_are_held()
    {
        await _browser.SignInAsync(Alice);

        var response = await _browser.AuthorizeAsync(prompt: "select_account login");

        ShouldHaveGoneTo(response, LoginPath);
    }

    [Fact]
    public async Task Prompt_select_account_with_the_hint_of_an_account_that_is_not_held_sends_the_browser_to_the_login_page()
    {
        var carolsHint = await new MultiAccountBrowser(_host.NewFlowClient()).IdTokenForAsync(Carol);
        await _browser.SignInAsync(Alice);

        var response = await _browser.AuthorizeAsync(prompt: "select_account", idTokenHint: carolsHint);

        ShouldHaveGoneTo(response, LoginPath);
    }

    [Fact]
    public async Task Prompt_select_account_with_the_hint_of_a_held_account_offers_the_picker_only_that_account()
    {
        var alicesHint = await _browser.IdTokenForAsync(Alice);
        await _browser.SignInAsync(Bob);

        var response = await _browser.AuthorizeAsync(prompt: "select_account", idTokenHint: alicesHint);

        ShouldHaveGoneTo(response, SelectPath);
        var page = await _browser.GetPageAsync(Location(response));
        page.GetProperty("accounts").EnumerateArray().Select(account => account.GetProperty("subject").GetString())
            .Should().Equal(Alice);
    }
}
