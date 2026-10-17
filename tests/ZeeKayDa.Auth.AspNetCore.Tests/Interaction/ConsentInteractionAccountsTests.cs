using static ZeeKayDa.Auth.AspNetCore.Tests.Interaction.MultiAccountBrowser;
using static ZeeKayDa.Auth.AspNetCore.Tests.Interaction.MultiAccountHost;

namespace ZeeKayDa.Auth.AspNetCore.Tests.Interaction;

/// <summary>
/// Consent is recorded by the account that authenticated the request, wherever that account sits
/// among those the browser holds, and by no other.
/// </summary>
public sealed class ConsentInteractionAccountsTests : IClassFixture<MultiAccountHostFixture>
{
    private readonly MultiAccountBrowser _browser;

    public ConsentInteractionAccountsTests(MultiAccountHostFixture host)
    {
        host.Reset();
        _browser = new MultiAccountBrowser(host.NewFlowClient());
    }

    /// <summary>Signs alice in for a client that asks for consent, and returns the consent page she was sent to.</summary>
    private async Task<string> ReachConsentAsLaterOldestAccountAsync()
    {
        var response = await _browser.SignInAsync(Alice, clientId: ConsentingApp);
        response.ShouldHaveReachedConsent();

        return Location(response);
    }

    [Fact]
    public async Task The_consent_page_works_when_the_account_that_authenticated_the_request_is_not_the_first_in_the_cookie()
    {
        var consent = await ReachConsentAsLaterOldestAccountAsync();
        await _browser.SignInAsync(Bob, add: true, clientId: OtherApp);
        (await _browser.ReadSessionAsync()).Subjects.Should().Equal(Bob, Alice);

        var page = await _browser.GetPageAsync(consent);
        var granted = await _browser.PostFormAsync(consent);

        page.GetProperty("subject").GetString().Should().Be(Alice);
        (await _browser.SubjectAnsweredAsync(granted, ConsentingApp)).Should().Be(Alice);
    }

    [Fact]
    public async Task The_consent_page_is_refused_once_the_account_that_authenticated_the_request_was_signed_out_though_another_remains()
    {
        var consent = await ReachConsentAsLaterOldestAccountAsync();
        await _browser.SignInAsync(Bob, add: false, clientId: OtherApp);
        (await _browser.ReadSessionAsync()).Subjects.Should().Equal(Bob);

        var granted = await _browser.PostFormAsync(consent);

        await granted.ShouldHaveFoundNothingToContinueAsync();
    }
}
