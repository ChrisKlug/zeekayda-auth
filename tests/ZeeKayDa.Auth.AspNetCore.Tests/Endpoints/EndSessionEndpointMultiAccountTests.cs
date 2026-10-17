using System.Net;
using Microsoft.AspNetCore.WebUtilities;
using ZeeKayDa.Auth.AspNetCore.Interaction;
using ZeeKayDa.Auth.AspNetCore.Tests.Interaction;
using static ZeeKayDa.Auth.AspNetCore.Tests.Interaction.MultiAccountBrowser;
using static ZeeKayDa.Auth.AspNetCore.Tests.Interaction.MultiAccountHost;

namespace ZeeKayDa.Auth.AspNetCore.Tests.Endpoints;

/// <summary>
/// Signing out of a browser that holds two accounts: only the account the request names or the client
/// owns ends, unless the logout page ends them all (OIDC RP-Initiated Logout 1.0).
/// </summary>
public sealed class EndSessionEndpointMultiAccountTests : IClassFixture<MultiAccountHostFixture>
{
    private readonly MultiAccountBrowser _browser;

    public EndSessionEndpointMultiAccountTests(MultiAccountHostFixture host)
    {
        host.Reset();
        _browser = new MultiAccountBrowser(host.NewFlowClient());
    }

    /// <summary>Alice signs in through <see cref="App"/>, then bob through <see cref="OtherApp"/>: bob is the newest, alice is <see cref="App"/>'s own.</summary>
    private async Task SignInTwoAccountsAsync()
    {
        await _browser.SignInAsync(Alice, clientId: App);
        await _browser.SignInAsync(Bob, clientId: OtherApp);
    }

    /// <summary>Asks the browser to sign out for <see cref="App"/>, and returns the logout page it was sent to.</summary>
    private async Task<string> AskAsync(string clientId = App)
    {
        var asked = await _browser.EndSessionAsync(new() { ["client_id"] = clientId });
        ShouldHaveGoneTo(asked, LogoutPath);

        return Location(asked);
    }

    private static string With(string path, string url) =>
        QueryHelpers.AddQueryString(path, InteractionHandoff.InteractionIdParameter, InteractionIdIn(url));

    private static string InteractionIdIn(string url) =>
        QueryHelpers.ParseQuery(url[url.IndexOf('?')..])[InteractionHandoff.InteractionIdParameter]!;

    // ── With an id_token_hint ─────────────────────────────────────────────────────────────────────

    [Fact]
    public async Task A_valid_hint_from_a_client_that_skips_the_question_ends_only_the_hinted_account()
    {
        var alicesHint = await _browser.IdTokenForAsync(Alice, clientId: TrustedApp);
        await _browser.SignInAsync(Bob, clientId: TrustedApp);

        var response = await _browser.EndSessionAsync(new()
        {
            ["id_token_hint"] = alicesHint,
            ["post_logout_redirect_uri"] = TrustedSignedOut,
        });

        response.Headers.Location!.OriginalString.Should().Be(TrustedSignedOut);
        (await _browser.ReadSessionAsync()).Subjects.Should().Equal(Bob);
    }

    // ── Without one ───────────────────────────────────────────────────────────────────────────────

    [Fact]
    public async Task The_logout_page_is_asked_about_the_clients_own_account_and_lists_every_account()
    {
        await SignInTwoAccountsAsync();
        var logout = await AskAsync();

        var page = await _browser.GetPageAsync(logout);

        page.GetProperty("subject").GetString().Should().Be(Alice);
        page.GetProperty("accounts").EnumerateArray().Select(account => account.GetProperty("subject").GetString())
            .Should().BeEquivalentTo([Alice, Bob]);
    }

    [Fact]
    public async Task SignOutAsync_ends_only_the_account_the_page_was_asked_about()
    {
        await SignInTwoAccountsAsync();
        var logout = await AskAsync();

        var response = await _browser.PostFormAsync(logout);

        response.StatusCode.Should().BeOneOf(HttpStatusCode.OK, HttpStatusCode.Redirect);
        (await _browser.ReadSessionAsync()).Subjects.Should().Equal(Bob);
    }

    [Fact]
    public async Task SignOutAllAsync_ends_every_account()
    {
        await SignInTwoAccountsAsync();
        var logout = await AskAsync();

        var response = await _browser.PostFormAsync(With(LogoutPath + "/all", logout));

        response.StatusCode.Should().BeOneOf(HttpStatusCode.OK, HttpStatusCode.Redirect);
        (await _browser.ReadSessionAsync()).Accounts.Should().BeEmpty();
    }

    [Fact]
    public async Task A_confirmation_is_refused_once_the_asked_account_was_signed_out_though_another_account_remains()
    {
        await _browser.SignInAsync(Alice, clientId: App);
        var logout = await AskAsync();
        await _browser.SignInAsync(Bob, add: false, clientId: OtherApp);
        (await _browser.ReadSessionAsync()).Subjects.Should().Equal(Bob);

        var response = await _browser.PostFormAsync(logout);

        response.StatusCode.Should().Be(HttpStatusCode.BadRequest);
        (await _browser.ReadSessionAsync()).Subjects.Should().Equal(Bob);
    }
}
