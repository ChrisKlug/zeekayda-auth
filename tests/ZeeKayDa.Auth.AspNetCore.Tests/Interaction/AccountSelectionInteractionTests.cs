using System.Text.Json;
using Microsoft.AspNetCore.WebUtilities;
using ZeeKayDa.Auth.AspNetCore.Interaction;
using ZeeKayDa.Auth.Authorization;
using static ZeeKayDa.Auth.AspNetCore.Tests.Interaction.MultiAccountBrowser;
using static ZeeKayDa.Auth.AspNetCore.Tests.Interaction.MultiAccountHost;

namespace ZeeKayDa.Auth.AspNetCore.Tests.Interaction;

/// <summary>
/// The host's account picker and what it can complete: the choice among the accounts the browser
/// holds, re-checked when posted so a forged or stale choice is refused (OIDC Core §3.1.2.1,
/// <c>prompt=select_account</c>).
/// </summary>
public sealed class AccountSelectionInteractionTests : IClassFixture<MultiAccountHostFixture>
{
    private readonly MultiAccountHostFixture _host;
    private readonly MultiAccountBrowser _browser;

    public AccountSelectionInteractionTests(MultiAccountHostFixture host)
    {
        host.Reset();
        _host = host;
        _browser = new MultiAccountBrowser(host.NewFlowClient());
    }

    private static Dictionary<string, string> Choice(string subject) => new() { ["sub"] = subject };

    /// <summary>Starts a <c>prompt=select_account</c> request and returns the URL of the picker it was sent to.</summary>
    private async Task<string> ReachPickerAsync(string? idTokenHint = null, string? maxAge = null)
    {
        var response = await _browser.AuthorizeAsync(prompt: "select_account", idTokenHint: idTokenHint, maxAge: maxAge);
        ShouldHaveGoneTo(response, SelectPath);

        return Location(response);
    }

    private static (string Subject, string LoginIdentifier)[] AccountsOffered(JsonElement page) =>
    [
        .. page.GetProperty("accounts").EnumerateArray()
            .Select(account => (account.GetProperty("subject").GetString()!, account.GetProperty("loginIdentifier").GetString()!)),
    ];

    private static string InteractionIdIn(string url) =>
        QueryHelpers.ParseQuery(url[url.IndexOf('?')..])[InteractionHandoff.InteractionIdParameter]!;

    /// <summary>A page's path, carrying the interaction identifier of the URL the browser was sent to.</summary>
    private static string With(string path, string url) =>
        QueryHelpers.AddQueryString(path, InteractionHandoff.InteractionIdParameter, InteractionIdIn(url));

    // ── What the picker shows ─────────────────────────────────────────────────────────────────────

    [Fact]
    public async Task GetRequestAsync_lists_the_selectable_accounts_with_their_login_identifier_or_the_subject_when_none_was_given()
    {
        await _browser.SignInAsync(Alice, loginIdentifier: "alice@example.com");
        await _browser.SignInAsync(Bob);
        var picker = await ReachPickerAsync();

        var page = await _browser.GetPageAsync(picker);

        AccountsOffered(page).Should().BeEquivalentTo([(Alice, "alice@example.com"), (Bob, Bob)]);
    }

    // ── Choosing ──────────────────────────────────────────────────────────────────────────────────

    [Fact]
    public async Task SelectAsync_continues_the_request_as_the_chosen_account()
    {
        await _browser.SignInAsync(Alice);
        await _browser.SignInAsync(Bob);
        var picker = await ReachPickerAsync();

        var response = await _browser.PostFormAsync(picker, Choice(Alice));

        (await _browser.SubjectAnsweredAsync(response)).Should().Be(Alice);
    }

    [Fact]
    public async Task A_request_with_no_hint_after_a_choice_is_answered_by_the_account_chosen()
    {
        await _browser.SignInAsync(Alice);
        await _browser.SignInAsync(Bob);
        await _browser.PostFormAsync(await ReachPickerAsync(), Choice(Alice));

        var response = await _browser.AuthorizeAsync(prompt: "none");

        (await _browser.SubjectAnsweredAsync(response)).Should().Be(Alice, "the client was last answered for bob before the choice");
    }

    [Fact]
    public async Task SelectAsync_refuses_a_subject_the_browser_does_not_hold()
    {
        await _browser.SignInAsync(Alice);
        var sessionBefore = await _browser.ReadSessionAsync();
        var picker = await ReachPickerAsync();

        var choose = async () => await _browser.PostFormAsync(picker, Choice("mallory"));

        await choose.Should().ThrowAsync<ZeeKayDaInteractionException>();
        (await _browser.ReadSessionAsync()).Should().BeEquivalentTo(sessionBefore);
    }

    [Fact]
    public async Task SelectAsync_refuses_an_account_that_max_age_rules_out()
    {
        await _browser.SignInAsync(Alice);
        _host.Time.Advance(TimeSpan.FromMinutes(2));
        await _browser.SignInAsync(Bob);
        var sessionBefore = await _browser.ReadSessionAsync();
        var picker = await ReachPickerAsync(maxAge: "60");
        AccountsOffered(await _browser.GetPageAsync(picker)).Select(account => account.Subject).Should().Equal(Bob);

        var choose = async () => await _browser.PostFormAsync(picker, Choice(Alice));

        await choose.Should().ThrowAsync<ZeeKayDaInteractionException>();
        (await _browser.ReadSessionAsync()).Should().BeEquivalentTo(sessionBefore);
    }

    [Fact]
    public async Task SelectAsync_refuses_an_account_that_the_id_token_hint_rules_out()
    {
        var alicesHint = await _browser.IdTokenForAsync(Alice);
        await _browser.SignInAsync(Bob);
        var sessionBefore = await _browser.ReadSessionAsync();
        var picker = await ReachPickerAsync(idTokenHint: alicesHint);

        var choose = async () => await _browser.PostFormAsync(picker, Choice(Bob));

        await choose.Should().ThrowAsync<ZeeKayDaInteractionException>();
        (await _browser.ReadSessionAsync()).Should().BeEquivalentTo(sessionBefore);
    }

    // ── The picker reached for the wrong request ──────────────────────────────────────────────────

    [Fact]
    public async Task TryGetRequestAsync_for_an_interaction_that_never_asked_for_select_account_returns_null()
    {
        await _browser.SignInAsync(Alice);
        var login = await _browser.AuthorizeAsync(prompt: "login");
        ShouldHaveGoneTo(login, LoginPath);

        var response = await _browser.Client.GetAsync(With(SelectPath + "/try", Location(login)), TestContext.Current.CancellationToken);

        response.StatusCode.Should().Be(System.Net.HttpStatusCode.NotFound);
    }

    [Fact]
    public async Task SelectAsync_for_an_interaction_that_never_asked_for_select_account_has_nothing_to_continue()
    {
        await _browser.SignInAsync(Alice);
        var login = await _browser.AuthorizeAsync(prompt: "login");

        var response = await _browser.PostFormAsync(With(SelectPath, Location(login)), Choice(Alice));

        await response.ShouldHaveFoundNothingToContinueAsync();
    }

    // ── The other ways out of the picker ──────────────────────────────────────────────────────────

    [Fact]
    public async Task UseAnotherAccountAsync_sends_the_user_to_the_login_page_for_the_same_request()
    {
        await _browser.SignInAsync(Alice);
        var picker = await ReachPickerAsync();

        var response = await _browser.PostFormAsync(With(SelectPath + "/another", picker));

        ShouldHaveGoneTo(response, LoginPath);
        InteractionIdFrom(response).Should().Be(InteractionIdIn(picker));
    }

    [Fact]
    public async Task DenyAsync_answers_the_client_access_denied()
    {
        await _browser.SignInAsync(Alice);
        var picker = await ReachPickerAsync();

        var response = await _browser.PostFormAsync(With(SelectPath + "/deny", picker));

        var query = QueryAtClient(response);
        query["error"].ToString().Should().Be(AuthorizeRequestErrors.AccessDenied);
        query.Should().NotContainKey("code");
    }

    [Fact]
    public async Task SelectAsync_from_a_GET_is_refused_and_chooses_nobody()
    {
        await _browser.SignInAsync(Alice);
        await _browser.SignInAsync(Bob);
        var sessionBefore = await _browser.ReadSessionAsync();
        var picker = await ReachPickerAsync();

        var byLink = async () => await _browser.Client.GetAsync(With(SelectPath + "/by-link", picker), TestContext.Current.CancellationToken);

        await byLink.Should().ThrowAsync<InvalidOperationException>();
        (await _browser.ReadSessionAsync()).Should().BeEquivalentTo(sessionBefore);
    }
}
