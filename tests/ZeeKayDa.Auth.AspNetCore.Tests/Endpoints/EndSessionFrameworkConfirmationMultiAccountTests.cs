using ZeeKayDa.Auth.AspNetCore.Tests.Interaction;
using static ZeeKayDa.Auth.AspNetCore.Tests.Interaction.MultiAccountBrowser;
using static ZeeKayDa.Auth.AspNetCore.Tests.Interaction.MultiAccountHost;

namespace ZeeKayDa.Auth.AspNetCore.Tests.Endpoints;

/// <summary>
/// The framework's own sign-out confirmation, for a host with no logout page, in a browser holding
/// more than one account: it ends the client's account, or every account when the user asks.
/// </summary>
public sealed class EndSessionFrameworkConfirmationMultiAccountTests : IClassFixture<MultiAccountFrameworkLogoutHostFixture>
{
    private const string ConfirmPath = "/connect/endsession/confirm";

    private readonly MultiAccountBrowser _browser;

    public EndSessionFrameworkConfirmationMultiAccountTests(MultiAccountFrameworkLogoutHostFixture host)
    {
        host.Reset();
        _browser = new MultiAccountBrowser(host.NewFlowClient());
    }

    /// <summary>Signs in the given accounts through <see cref="App"/>, then asks to sign out for it.</summary>
    private async Task<string> AskAsync(params string[] subjects)
    {
        foreach (var subject in subjects)
            await _browser.SignInAsync(subject);

        var asked = await _browser.EndSessionAsync(new() { ["client_id"] = App });
        ShouldHaveGoneTo(asked, ConfirmPath);

        return Location(asked);
    }

    [Fact]
    public async Task The_framework_confirmation_page_offers_to_end_every_account_when_more_than_one_is_signed_in()
    {
        var confirmation = await AskAsync(Alice, Bob);

        var page = await _browser.Client.GetStringAsync(confirmation, TestContext.Current.CancellationToken);

        page.Should().Contain("name=\"scope\" value=\"all\"");
    }

    [Fact]
    public async Task The_framework_confirmation_page_offers_no_every_account_button_for_one_account()
    {
        var confirmation = await AskAsync(Alice);

        var page = await _browser.Client.GetStringAsync(confirmation, TestContext.Current.CancellationToken);

        page.Should().NotContain("name=\"scope\"");
    }

    [Fact]
    public async Task The_framework_confirmation_page_ends_every_account_when_asked()
    {
        var confirmation = await AskAsync(Alice, Bob);

        await _browser.PostFormAsync(confirmation, new Dictionary<string, string> { ["scope"] = "all" });

        (await _browser.ReadSessionAsync()).Subjects.Should().BeEmpty();
    }

    [Fact]
    public async Task The_framework_confirmation_page_ends_only_the_clients_account_by_default()
    {
        var confirmation = await AskAsync(Alice, Bob);

        await _browser.PostFormAsync(confirmation);

        (await _browser.ReadSessionAsync()).Subjects.Should().Equal(Alice);
    }
}
