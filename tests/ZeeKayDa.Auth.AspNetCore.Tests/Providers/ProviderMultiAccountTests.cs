using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.WebUtilities;
using ZeeKayDa.Auth.AspNetCore.Interaction;
using ZeeKayDa.Auth.AspNetCore.Tests.Interaction;
using static ZeeKayDa.Auth.AspNetCore.Tests.Interaction.MultiAccountBrowser;
using static ZeeKayDa.Auth.AspNetCore.Tests.Interaction.MultiAccountHost;

namespace ZeeKayDa.Auth.AspNetCore.Tests.Providers;

/// <summary>
/// How an external sign-in joins the accounts a browser holds: the host's <c>OnProviderSignIn</c> hook
/// decides whether it adds or replaces and what identifier a <c>login_hint</c> will match, whether the
/// provider's return is promoted at once or parked for a linking page, and the hook that challenges
/// the provider is told which user the client named.
/// </summary>
public sealed class ProviderMultiAccountTests : IClassFixture<MultiAccountProviderHostFixture>
{
    private const string ProviderLoginId = "Provider.User@Example.com";
    private const string PageLoginId = "page.user@example.com";
    private const string Linked = "mapped-user";

    private static readonly string DerivedSubject = ExternalSubject.Derive("acme", ProviderTestHost.UpstreamSubject);

    private readonly MultiAccountProviderHostFixture _host;
    private readonly MultiAccountBrowser _browser;

    public ProviderMultiAccountTests(MultiAccountProviderHostFixture host)
    {
        host.Reset();
        _host = host;
        _browser = new MultiAccountBrowser(host.NewFlowClient());
    }

    /// <summary>Starts an authorization request that must sign in, and returns its interaction identifier.</summary>
    private async Task<string> StartAsync(string? idTokenHint = null) =>
        InteractionIdFrom(await _browser.AuthorizeAsync(prompt: idTokenHint is null ? "login" : null, idTokenHint: idTokenHint));

    /// <summary>Picks the provider for the interaction, completes its callback, and returns through resume.</summary>
    private async Task<HttpResponseMessage> ReturnFromProviderAsync(string interactionId)
    {
        var challenge = await _browser.PostFormAsync(
            ProviderTestHost.WithInteractionId(LoginPath, interactionId),
            new Dictionary<string, string> { ["provider"] = "acme" });
        var callback = new Dictionary<string, string?>
        {
            ["state"] = ProviderTestHost.RedirectQueryOf(challenge)["state"].ToString(),
            ["code"] = "acme-code",
        };
        var callbackResponse = await _browser.Client.GetAsync(
            QueryHelpers.AddQueryString("/connect/callback/acme", callback), TestContext.Current.CancellationToken);

        return await _browser.Client.GetAsync(callbackResponse.Headers.Location!.OriginalString, TestContext.Current.CancellationToken);
    }

    private async Task SignInWithProviderAsync()
    {
        var response = await ReturnFromProviderAsync(await StartAsync());
        response.ShouldHaveIssuedCodeTo(Redirect);
    }

    /// <summary>The hook parks the principal at the linking page; the page signs <see cref="Linked"/> in.</summary>
    private async Task<SessionView> LinkAsync(string? pageLoginIdentifier)
    {
        var parked = await ReturnFromProviderAsync(await StartAsync());
        parked.Headers.Location!.OriginalString.Should().StartWith(CollectMorePath);

        var fields = new Dictionary<string, string> { ["sub"] = Linked };
        if (pageLoginIdentifier is not null)
            fields["login_id"] = pageLoginIdentifier;
        var linked = await _browser.PostFormAsync(ProviderTestHost.WithInteractionId(CollectMorePath + "/link", InteractionIdFrom(parked)), fields);
        linked.ShouldHaveIssuedCodeTo(Redirect);

        return await _browser.ReadSessionAsync();
    }

    // ── A provider return promoted at once ────────────────────────────────────────────────────────

    [Fact]
    public async Task A_hook_that_sets_AddAccount_keeps_the_existing_account()
    {
        await _browser.SignInAsync(Alice, add: false);
        _host.OnProviderSignIn = context =>
        {
            context.AddAccount = true;
            return Task.CompletedTask;
        };

        await SignInWithProviderAsync();

        (await _browser.ReadSessionAsync()).Subjects.Should().Equal(DerivedSubject, Alice);
    }

    [Fact]
    public async Task An_external_sign_in_with_no_hook_decision_replaces_the_accounts_held()
    {
        await _browser.SignInAsync(Alice, add: false);

        await SignInWithProviderAsync();

        (await _browser.ReadSessionAsync()).Subjects.Should().Equal(DerivedSubject);
    }

    [Fact]
    public async Task A_login_identifier_the_hook_sets_is_matched_by_a_login_hint()
    {
        _host.OnProviderSignIn = context =>
        {
            context.AddAccount = true;
            context.LoginIdentifier = ProviderLoginId;
            return Task.CompletedTask;
        };
        await SignInWithProviderAsync();
        await _browser.SignInAsync(Alice, add: true);

        var response = await _browser.AuthorizeAsync(prompt: "none", loginHint: ProviderLoginId.ToUpperInvariant());

        (await _browser.SubjectAnsweredAsync(response)).Should().Be(DerivedSubject, "alice is the client's own account, so only the hint can have chosen the provider's user");
    }

    // ── A provider return parked for a linking page ───────────────────────────────────────────────

    [Fact]
    public async Task What_the_hook_sets_before_redirecting_reaches_the_linking_page_so_the_account_is_added_with_the_hooks_identifier()
    {
        await _browser.SignInAsync(Alice, add: false);
        _host.OnProviderSignIn = context =>
        {
            context.AddAccount = true;
            context.LoginIdentifier = ProviderLoginId;
            return context.RedirectToAsync(CollectMorePath);
        };

        var session = await LinkAsync(pageLoginIdentifier: null);

        session.Subjects.Should().Equal(Linked, Alice);
        session.Accounts[0].LoginId.Should().Be(ProviderLoginId);
    }

    [Fact]
    public async Task What_the_hook_sets_before_redirecting_also_reaches_a_page_that_lets_the_framework_sign_in_the_derived_subject()
    {
        await _browser.SignInAsync(Alice, add: false);
        _host.OnProviderSignIn = context =>
        {
            context.AddAccount = true;
            context.LoginIdentifier = ProviderLoginId;
            return context.RedirectToAsync(CollectMorePath);
        };
        var parked = await ReturnFromProviderAsync(await StartAsync());

        var signedIn = await _browser.PostFormAsync(ProviderTestHost.WithInteractionId(CollectMorePath, InteractionIdFrom(parked)));

        signedIn.ShouldHaveIssuedCodeTo(Redirect);
        var session = await _browser.ReadSessionAsync();
        session.Subjects.Should().Equal(DerivedSubject, Alice);
        session.Accounts[0].LoginId.Should().Be(ProviderLoginId);
    }

    [Fact]
    public async Task A_login_identifier_the_linking_page_passes_wins_over_the_one_the_hook_set()
    {
        _host.OnProviderSignIn = context =>
        {
            context.LoginIdentifier = ProviderLoginId;
            return context.RedirectToAsync(CollectMorePath);
        };

        var session = await LinkAsync(PageLoginId);

        session.Accounts.Should().ContainSingle().Which.LoginId.Should().Be(PageLoginId);
    }

    [Fact]
    public async Task A_hook_that_sets_nothing_before_redirecting_has_the_linking_page_replace_the_accounts_held()
    {
        await _browser.SignInAsync(Alice, add: false);
        _host.OnProviderSignIn = context => context.RedirectToAsync(CollectMorePath);

        var session = await LinkAsync(pageLoginIdentifier: null);

        session.Subjects.Should().Equal(Linked);
        session.Accounts[0].LoginId.Should().BeNull();
    }

    // ── The login identifier setter ───────────────────────────────────────────────────────────────

    public static TheoryData<string> RefusedLoginIdentifiers => LoginInteractionAccountsTests.RefusedLoginIdentifiers;

    [Theory]
    [MemberData(nameof(RefusedLoginIdentifiers))]
    public void The_LoginIdentifier_setter_refuses_a_value_a_login_hint_would_be_refused(string loginIdentifier)
    {
        var context = NewSignInContext();

        var set = () => context.LoginIdentifier = loginIdentifier;

        set.Should().Throw<ArgumentException>();
        context.LoginIdentifier.Should().BeNull("a refused value is not kept");
    }

    [Fact]
    public void The_LoginIdentifier_setter_accepts_null_to_use_the_subject()
    {
        var context = NewSignInContext();
        context.LoginIdentifier = ProviderLoginId;

        context.LoginIdentifier = null;

        context.LoginIdentifier.Should().BeNull();
    }

    private static ProviderSignInContext NewSignInContext() => new(
        new ExternalIdentity("https://acme.example.net", ProviderTestHost.UpstreamSubject),
        new System.Security.Claims.ClaimsPrincipal(),
        new ProviderDescriptor("acme", "Acme"),
        new ClientInformation(App, displayName: null),
        ["openid"],
        CancellationToken.None,
        (_, _) => Task.CompletedTask,
        () => Task.CompletedTask);

    // ── What the challenge hook is told ───────────────────────────────────────────────────────────

    [Fact]
    public async Task ProviderChallengeContext_RequiredSubject_carries_the_subject_the_id_token_hint_names()
    {
        var alicesHint = await new MultiAccountBrowser(_host.NewFlowClient()).IdTokenForAsync(Alice);
        ProviderChallengeContext? challenged = null;
        _host.OnProviderChallenge = context =>
        {
            challenged = context;
            return ProviderChallengeOutcome.Proceed;
        };

        await ReturnFromProviderAsync(await StartAsync(alicesHint));

        challenged.Should().NotBeNull();
        challenged!.RequiredSubject.Should().Be(Alice);
    }

    [Fact]
    public async Task ReauthenticationRequired_is_judged_against_the_account_the_hint_names_not_a_fresher_one_held()
    {
        var alicesHint = await new MultiAccountBrowser(_host.NewFlowClient()).IdTokenForAsync(Alice);
        await _browser.SignInAsync(Bob);
        ProviderChallengeContext? challenged = null;
        _host.OnProviderChallenge = context =>
        {
            challenged = context;
            return ProviderChallengeOutcome.Reauthenticating;
        };

        var started = await _browser.AuthorizeAsync(idTokenHint: alicesHint, maxAge: "3600");
        await ReturnFromProviderAsync(InteractionIdFrom(started));

        challenged.Should().NotBeNull();
        challenged!.ReauthenticationRequired.Should().BeTrue("this browser holds no session for alice, and bob's fresh one does not answer her hint");
    }

    [Fact]
    public async Task ProviderChallengeContext_RequiredSubject_is_null_when_the_request_carries_no_hint()
    {
        ProviderChallengeContext? challenged = null;
        _host.OnProviderChallenge = context =>
        {
            challenged = context;
            return ProviderChallengeOutcome.Reauthenticating;
        };

        await ReturnFromProviderAsync(await StartAsync());

        challenged.Should().NotBeNull();
        challenged!.RequiredSubject.Should().BeNull();
    }
}
