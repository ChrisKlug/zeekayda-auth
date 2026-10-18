using System.Buffers.Text;
using System.Net;
using System.Text.Json;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.WebUtilities;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Primitives;
using ZeeKayDa.Auth.AspNetCore.Interaction;
using ZeeKayDa.Auth.AspNetCore.Tests.Interaction;
using ZeeKayDa.Auth.Authorization;
using static ZeeKayDa.Auth.AspNetCore.Tests.Providers.ProviderTestHost;

namespace ZeeKayDa.Auth.AspNetCore.Tests.Providers;

/// <summary>
/// An <c>id_token_hint</c> names the only user who may answer the request (OIDC Core §3.1.2.2), and
/// that holds on the two ways an external sign-in finishes: the provider's return promoted
/// automatically through <c>/connect/resume</c>, and a host page linking the parked principal to
/// a local account. Each hint is a real ID token the host minted for the same client.
/// </summary>
public sealed class ProviderIdTokenHintTests
{
    private const string App = "hint-app";
    private const string Alice = "alice";
    private const string Bob = "bob";

    // RFC 7636 Appendix B.
    private const string Verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
    private const string Challenge = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM";

    private static CancellationToken Cancellation => TestContext.Current.CancellationToken;

    private static TestWebAppFactory NewFactory(bool parkAtCollectMore = false) =>
        new(
            configureBuilder: builder =>
            {
                builder.AddInMemoryClients(clients => clients.AddPublic(App, client =>
                {
                    client.RedirectUris.Add(RegisteredRedirect);
                    client.AllowedScopes.Add("openid");
                    client.RequireConsent = false;
                }));
                builder.WithProviders(
                    auth =>
                    {
                        auth.AddOAuth("acme", "Acme", ConfigureAcme);
                        AddHandWritten(auth);
                    },
                    options =>
                    {
                        if (parkAtCollectMore)
                            options.OnProviderSignIn = context => context.RedirectToAsync(CollectMorePath);
                    });
            },
            mapEndpoints: MapHostPages);

    // ── Provider return through /connect/resume ───────────────────────────────────────────────────

    [Fact]
    public async Task A_provider_return_as_another_user_than_the_hint_names_is_refused_with_login_required()
    {
        using var factory = NewFactory();
        using var minting = NewClient(factory);
        var acmeUsersHint = await IdTokenViaProviderAsync(minting, "acme");
        using var client = await NewBrowserSignedInAsLocalAsync(factory);
        var sessionBefore = await ReadSessionAsync(client);
        var interactionId = await StartAsync(client, acmeUsersHint);

        var response = await ReturnFromProviderAsync(client, interactionId, "hand");

        var query = ErrorAtClient(response);
        query["error"].ToString().Should().Be(AuthorizeRequestErrors.LoginRequired);
        query.Should().NotContainKey("code");
        (await ReadSessionAsync(client)).Should().Be(sessionBefore);
    }

    [Fact]
    public async Task A_provider_return_as_the_user_the_hint_names_issues_a_code_for_that_users_derived_subject()
    {
        using var factory = NewFactory();
        using var minting = NewClient(factory);
        var acmeUsersHint = await IdTokenViaProviderAsync(minting, "acme");
        using var client = await NewBrowserSignedInAsLocalAsync(factory);
        var interactionId = await StartAsync(client, acmeUsersHint);

        var response = await ReturnFromProviderAsync(client, interactionId, "acme");

        var idToken = await RedeemAsync(client, response.ShouldHaveIssuedCodeTo(RegisteredRedirect));
        SubjectOf(idToken).Should().Be(ExternalSubject.Derive(AcmeIssuer, UpstreamSubject));
    }

    // ── Linking page ──────────────────────────────────────────────────────────────────────────────

    [Fact]
    public async Task Linking_as_another_account_than_the_hint_names_is_refused_with_login_required()
    {
        using var factory = NewFactory(parkAtCollectMore: true);
        using var minting = NewClient(factory);
        var alicesHint = await IdTokenViaLocalLoginAsync(minting, Alice);
        using var client = await NewBrowserSignedInAsLocalAsync(factory);
        var sessionBefore = await ReadSessionAsync(client);
        var interactionId = await StartAsync(client, alicesHint);
        await ReturnFromProviderAsync(client, interactionId, "acme");

        var response = await client.PostAsync(WithInteractionId(CollectMorePath + "/link", interactionId), Form(), Cancellation);

        var query = ErrorAtClient(response);
        query["error"].ToString().Should().Be(AuthorizeRequestErrors.LoginRequired);
        query.Should().NotContainKey("code");
        (await ReadSessionAsync(client)).Should().Be(sessionBefore);
    }

    // ── Helpers ───────────────────────────────────────────────────────────────────────────────────

    private static async Task<HttpResponseMessage> AuthorizeAsync(HttpClient client, string? prompt = null, string? idTokenHint = null) =>
        await client.GetAsync(
            QueryHelpers.AddQueryString("/connect/authorize", new Dictionary<string, string?>
            {
                ["client_id"] = App,
                ["redirect_uri"] = RegisteredRedirect,
                ["response_type"] = "code",
                ["scope"] = "openid",
                ["nonce"] = "n-0S6_WzA2Mj",
                ["code_challenge"] = Challenge,
                ["code_challenge_method"] = "S256",
                ["prompt"] = prompt,
                ["id_token_hint"] = idTokenHint,
            }),
            Cancellation);

    /// <summary>
    /// A browser holding another user's session sends a request carrying the hint, which cannot be
    /// answered from that session: its interaction identifier.
    /// </summary>
    private static async Task<string> StartAsync(HttpClient client, string idTokenHint) =>
        InteractionIdFrom(await AuthorizeAsync(client, idTokenHint: idTokenHint));

    /// <summary>A browser signed in as a local account that is neither of the users under test.</summary>
    private static async Task<HttpClient> NewBrowserSignedInAsLocalAsync(TestWebAppFactory factory)
    {
        var browser = NewClient(factory);
        await IdTokenViaLocalLoginAsync(browser, Bob);

        return browser;
    }

    /// <summary>Picks the provider for the interaction, completes its callback, and returns through resume.</summary>
    private static async Task<HttpResponseMessage> ReturnFromProviderAsync(HttpClient client, string interactionId, string provider)
    {
        var challenge = await client.PostAsync(WithInteractionId(LoginPath, interactionId), Form(("provider", provider)), Cancellation);
        var callback = new Dictionary<string, string?> { ["state"] = RedirectQueryOf(challenge)["state"].ToString() };
        if (provider == "acme")
            callback["code"] = "acme-code";

        var callbackResponse = await client.GetAsync(QueryHelpers.AddQueryString($"/connect/callback/{provider}", callback), Cancellation);

        return await client.GetAsync(callbackResponse.Headers.Location!.OriginalString, Cancellation);
    }

    /// <summary>Signs the provider's user in with no hint and redeems the code: an ID token naming that user.</summary>
    private static async Task<string> IdTokenViaProviderAsync(HttpClient client, string provider)
    {
        var interactionId = InteractionIdFrom(await AuthorizeAsync(client));
        var response = await ReturnFromProviderAsync(client, interactionId, provider);

        return await RedeemAsync(client, response.ShouldHaveIssuedCodeTo(RegisteredRedirect));
    }

    /// <summary>Signs the local account in at the login page with no hint and redeems the code: an ID token naming it.</summary>
    private static async Task<string> IdTokenViaLocalLoginAsync(HttpClient client, string subject)
    {
        var interactionId = InteractionIdFrom(await AuthorizeAsync(client));
        var response = await client.PostAsync(WithInteractionId(LoginPath, interactionId), Form(("sub", subject)), Cancellation);

        return await RedeemAsync(client, response.ShouldHaveIssuedCodeTo(RegisteredRedirect));
    }

    private static async Task<string> RedeemAsync(HttpClient client, string code)
    {
        using var form = Form(
            ("grant_type", "authorization_code"),
            ("code", code),
            ("redirect_uri", RegisteredRedirect),
            ("client_id", App),
            ("code_verifier", Verifier));
        var response = await client.PostAsync("/connect/token", form, Cancellation);
        var body = await response.Content.ReadAsStringAsync(Cancellation);
        response.StatusCode.Should().Be(HttpStatusCode.OK, body);

        using var document = JsonDocument.Parse(body);
        return document.RootElement.GetProperty("id_token").GetString()!;
    }

    private static async Task<string> ReadSessionAsync(HttpClient client)
    {
        var response = await client.GetAsync("/test/session", Cancellation);
        response.StatusCode.Should().Be(HttpStatusCode.OK);

        return await response.Content.ReadAsStringAsync(Cancellation);
    }

    private static string SubjectOf(string idToken)
    {
        using var payload = JsonDocument.Parse(Base64Url.DecodeFromChars(idToken.Split('.')[1]));
        return payload.RootElement.GetProperty("sub").GetString()!;
    }

    /// <summary>The query of a redirect to the client's registered redirect URI.</summary>
    private static Dictionary<string, StringValues> ErrorAtClient(HttpResponseMessage response)
    {
        response.StatusCode.Should().Be(HttpStatusCode.Redirect);
        var location = response.Headers.Location!.OriginalString;
        location.Should().StartWith(RegisteredRedirect + "?");

        return QueryHelpers.ParseQuery(location[location.IndexOf('?')..]);
    }
}
