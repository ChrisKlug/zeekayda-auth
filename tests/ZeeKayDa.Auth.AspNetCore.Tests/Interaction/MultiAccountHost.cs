using System.Buffers.Text;
using System.Net;
using System.Security.Claims;
using System.Text.Json;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Routing;
using Microsoft.AspNetCore.WebUtilities;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Primitives;
using ZeeKayDa.Auth.AspNetCore.Interaction;
using ZeeKayDa.Auth.Authorization;
using ZeeKayDa.Auth.Clients;

namespace ZeeKayDa.Auth.AspNetCore.Tests.Interaction;

/// <summary>
/// What the multi-account tests share: the clients, the host's pages written as a real host would
/// write them (login with add or replace, account picker, consent, logout, and a linking page), and
/// a session probe that lists every account the cookie holds, which nothing else can observe.
/// </summary>
internal static class MultiAccountHost
{
    public const string Redirect = "https://test.example.com/callback";
    public const string LoginPath = "/account/login";
    public const string SelectPath = "/account/select";
    public const string ConsentPath = FlowAssertions.ConsentPath;
    public const string LogoutPath = "/account/logout";
    public const string CollectMorePath = "/collect-more";
    public const string SessionProbePath = "/test/session";

    public const string App = "app";
    public const string OtherApp = "other-app";
    public const string TrustedApp = "trusted-app";
    public const string ConsentingApp = "consenting-app";

    public const string AppSignedOut = "https://app.example.com/signed-out";
    public const string TrustedSignedOut = "https://trusted.example.com/signed-out";

    public const string Alice = "alice";
    public const string Bob = "bob";
    public const string Carol = "carol";

    public static void ConfigureOptions(AuthorizationServerOptions options, bool withPicker)
    {
        var interaction = options.AuthorizationEndpoint.Interaction;
        interaction.LoginPath = LoginPath;
        interaction.ConsentPath = ConsentPath;
        interaction.SelectAccountPath = withPicker ? SelectPath : null;
        options.EndSessionEndpoint.LogoutPath = LogoutPath;
    }

    /// <summary>Two ordinary clients, one that skips the sign-out question, and one that asks for consent.</summary>
    public static void AddClients(ZeeKayDaAuthBuilder builder) =>
        builder.AddInMemoryClients(clients => clients
            .AddPublic(App, client => Register(client, AppSignedOut))
            .AddPublic(OtherApp, client => Register(client, AppSignedOut))
            .AddPublic(TrustedApp, client =>
            {
                Register(client, TrustedSignedOut);
                client.SkipLogoutConfirmation = true;
            })
            .AddPublic(ConsentingApp, client =>
            {
                Register(client, AppSignedOut);
                client.RequireConsent = true;
            }));

    private static void Register(PublicClientOptions client, string postLogoutRedirect)
    {
        client.RedirectUris.Add(Redirect);
        client.PostLogoutRedirectUris.Add(postLogoutRedirect);
        client.AllowedScopes.Add("openid");
        client.RequireConsent = false;
    }

    public static void MapHostPages(IEndpointRouteBuilder endpoints)
    {
        MapLoginPage(endpoints);
        MapPickerPage(endpoints);
        MapConsentPage(endpoints);
        MapLogoutPage(endpoints);
        MapLinkingPage(endpoints);

        endpoints.MapGet(SessionProbePath, async (HttpContext context) =>
        {
            var result = await context.AuthenticateAsync(ZeeKayDaCookies.Session);
            var identities = result.Succeeded ? result.Principal!.Identities.ToArray() : [];

            return Results.Ok(new
            {
                accounts = identities
                    .Where(identity => identity.FindFirst(SsoSessionClaimTypes.SessionId) is not null)
                    .Select(identity => new
                    {
                        sub = identity.FindFirst("sub")?.Value,
                        sid = identity.FindFirst(SsoSessionClaimTypes.SessionId)?.Value,
                        loginId = identity.FindFirst(SsoSessionClaimTypes.LoginIdentifier)?.Value,
                    }),
                clients = identities.SelectMany(identity => identity.FindAll(SsoSessionClaimTypes.ClientAccount)).Select(claim => claim.Value),
            });
        });
    }

    /// <summary>
    /// The login page. The form says <c>mode=add</c> to add the account and nothing to replace the
    /// accounts held; <c>login_id</c> is passed as typed, and left out when the form has none.
    /// </summary>
    private static void MapLoginPage(IEndpointRouteBuilder endpoints)
    {
        endpoints.MapGet(LoginPath, async (HttpContext context, LoginInteraction login) =>
        {
            var request = await login.GetRequestAsync(context.RequestAborted);

            return Results.Ok(new
            {
                requiredSubject = request.RequiredSubject,
                loginHint = request.LoginHint,
                reauthenticationRequired = request.ReauthenticationRequired,
                accounts = request.SignedInAccounts.Select(account => new { account.Subject, account.LoginIdentifier }),
            });
        });

        endpoints.MapPost(LoginPath, async (HttpContext context, LoginInteraction login) =>
        {
            var form = await context.Request.ReadFormAsync(context.RequestAborted);

            if (form["provider"].FirstOrDefault() is { Length: > 0 } provider)
            {
                await login.ChallengeAsync(provider);
                return;
            }

            var subject = form["sub"].Single()!;
            string? loginIdentifier = form.TryGetValue("login_id", out var typed) ? typed.ToString() : null;

            if (form["mode"] == "add")
                await login.AddAccountAsync(subject, AuthenticationMethods.Password, loginIdentifier);
            else
                await login.SignInAsync(subject, AuthenticationMethods.Password, loginIdentifier);
        });
    }

    private static void MapPickerPage(IEndpointRouteBuilder endpoints)
    {
        endpoints.MapGet(SelectPath, async (HttpContext context, AccountSelectionInteraction picker) =>
        {
            var request = await picker.GetRequestAsync(context.RequestAborted);

            return Results.Ok(new
            {
                clientId = request.Client.ClientId,
                accounts = request.Accounts.Select(account => new { account.Subject, account.LoginIdentifier }),
            });
        });

        // The page a host writes when it tolerates being reached for the wrong request.
        endpoints.MapGet(SelectPath + "/try", async (HttpContext context, AccountSelectionInteraction picker) =>
            await picker.TryGetRequestAsync(context.RequestAborted) is null ? Results.NotFound() : Results.Ok());

        endpoints.MapPost(SelectPath, async (HttpContext context, AccountSelectionInteraction picker) =>
        {
            var form = await context.Request.ReadFormAsync(context.RequestAborted);
            await picker.SelectAsync(form["sub"].Single()!);
        });

        endpoints.MapPost(SelectPath + "/another", (AccountSelectionInteraction picker) => picker.UseAnotherAccountAsync());
        endpoints.MapPost(SelectPath + "/deny", (AccountSelectionInteraction picker) => picker.DenyAsync());

        // Wired the way the XML docs say not to: a terminal step taken from a GET.
        endpoints.MapGet(SelectPath + "/by-link", (AccountSelectionInteraction picker) => picker.SelectAsync(Alice));
    }

    private static void MapConsentPage(IEndpointRouteBuilder endpoints)
    {
        endpoints.MapGet(ConsentPath, async (HttpContext context, ConsentInteraction consent) =>
            Results.Ok(new { subject = (await consent.GetRequestAsync(context.RequestAborted)).Subject }));

        endpoints.MapPost(ConsentPath, (ConsentInteraction consent) => consent.GrantAsync(["openid"]));
    }

    private static void MapLogoutPage(IEndpointRouteBuilder endpoints)
    {
        endpoints.MapGet(LogoutPath, async (HttpContext context, LogoutInteraction logout) =>
        {
            var request = await logout.GetRequestAsync(context.RequestAborted);

            return Results.Ok(new
            {
                subject = request.Subject,
                accounts = request.SignedInAccounts.Select(account => new { account.Subject, account.LoginIdentifier }),
            });
        });

        endpoints.MapPost(LogoutPath, (LogoutInteraction logout) => logout.SignOutAsync());
        endpoints.MapPost(LogoutPath + "/all", (LogoutInteraction logout) => logout.SignOutAllAsync());
    }

    /// <summary>
    /// The pages a provider's hook parks the principal at: one signs in a local account in the
    /// provider's place, naming a login identifier only when the form has one; the other lets the
    /// framework sign in the provider's derived subject.
    /// </summary>
    private static void MapLinkingPage(IEndpointRouteBuilder endpoints)
    {
        endpoints.MapPost(CollectMorePath + "/link", async (HttpContext context, ProviderSignInInteraction linking) =>
        {
            var form = await context.Request.ReadFormAsync(context.RequestAborted);
            string? loginIdentifier = form.TryGetValue("login_id", out var typed) ? typed.ToString() : null;

            await linking.SignInWithReplacedAccountAsync(form["sub"].Single()!, AuthenticationMethods.Password, loginIdentifier);
        });

        // The page that asks for nothing more: the framework signs in the provider's derived subject.
        endpoints.MapPost(CollectMorePath, (ProviderSignInInteraction linking) => linking.SignInAsync());
    }
}

/// <summary>One account in the session cookie, as the probe reports it.</summary>
internal sealed record AccountView(string Sub, string Sid, string? LoginId);

/// <summary>Everything the session cookie holds: the accounts, newest first, and the client-to-account notes.</summary>
internal sealed record SessionView(IReadOnlyList<AccountView> Accounts, IReadOnlyList<string> Clients)
{
    public string[] Subjects => [.. Accounts.Select(account => account.Sub)];
}

/// <summary>
/// One browser against a multi-account host: it signs users in and out and sends authorization
/// requests, with the cookie jar of the <see cref="HttpClient"/> it wraps.
/// </summary>
internal sealed class MultiAccountBrowser(HttpClient client)
{
    // RFC 7636 Appendix B.
    private const string Verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
    private const string Challenge = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM";

    private static CancellationToken Cancellation => TestContext.Current.CancellationToken;

    public HttpClient Client { get; } = client;

    public Task<HttpResponseMessage> AuthorizeAsync(
        string clientId = MultiAccountHost.App,
        string? prompt = null,
        string? idTokenHint = null,
        string? loginHint = null,
        string? maxAge = null) =>
        Client.GetAsync(
            QueryHelpers.AddQueryString("/connect/authorize", new Dictionary<string, string?>
            {
                ["client_id"] = clientId,
                ["redirect_uri"] = MultiAccountHost.Redirect,
                ["response_type"] = "code",
                ["scope"] = "openid",
                ["nonce"] = "n-0S6_WzA2Mj",
                ["code_challenge"] = Challenge,
                ["code_challenge_method"] = "S256",
                ["prompt"] = prompt,
                ["id_token_hint"] = idTokenHint,
                ["login_hint"] = loginHint,
                ["max_age"] = maxAge,
            }),
            Cancellation);

    /// <summary>
    /// Signs <paramref name="subject"/> in through an authorization request of <paramref name="clientId"/>
    /// that demands a login, beside the accounts held or in place of them. Returns the response of
    /// the login page's post: the code, or the consent page for a client that asks.
    /// </summary>
    public async Task<HttpResponseMessage> SignInAsync(
        string subject,
        bool add = true,
        string? loginIdentifier = null,
        string clientId = MultiAccountHost.App)
    {
        var authorize = await AuthorizeAsync(clientId, prompt: "login");
        authorize.StatusCode.Should().Be(HttpStatusCode.Redirect);

        return await PostLoginAsync(Location(authorize), subject, add, loginIdentifier);
    }

    public Task<HttpResponseMessage> PostLoginAsync(string loginUrl, string subject, bool add = true, string? loginIdentifier = null)
    {
        var fields = new Dictionary<string, string> { ["sub"] = subject };
        if (add)
            fields["mode"] = "add";
        if (loginIdentifier is not null)
            fields["login_id"] = loginIdentifier;

        return PostFormAsync(loginUrl, fields);
    }

    public async Task<HttpResponseMessage> PostFormAsync(string url, IReadOnlyDictionary<string, string>? fields = null)
    {
        using var form = new FormUrlEncodedContent(fields ?? new Dictionary<string, string>());
        return await Client.PostAsync(url, form, Cancellation);
    }

    /// <summary>Signs in as <paramref name="subject"/> and redeems the code: an ID token to send as a hint.</summary>
    public async Task<string> IdTokenForAsync(
        string subject,
        bool add = true,
        string? loginIdentifier = null,
        string clientId = MultiAccountHost.App) =>
        await RedeemAsync((await SignInAsync(subject, add, loginIdentifier, clientId)).ShouldHaveIssuedCodeTo(MultiAccountHost.Redirect), clientId);

    /// <summary>Redeems the code the response issued, and returns the subject of the ID token.</summary>
    public async Task<string> SubjectAnsweredAsync(HttpResponseMessage response, string clientId = MultiAccountHost.App) =>
        SubjectOf(await RedeemAsync(response.ShouldHaveIssuedCodeTo(MultiAccountHost.Redirect), clientId));

    public async Task<string> RedeemAsync(string code, string clientId = MultiAccountHost.App)
    {
        var response = await PostFormAsync("/connect/token", new Dictionary<string, string>
        {
            ["grant_type"] = "authorization_code",
            ["code"] = code,
            ["redirect_uri"] = MultiAccountHost.Redirect,
            ["client_id"] = clientId,
            ["code_verifier"] = Verifier,
        });
        var body = await response.Content.ReadAsStringAsync(Cancellation);
        response.StatusCode.Should().Be(HttpStatusCode.OK, body);

        using var document = JsonDocument.Parse(body);
        return document.RootElement.GetProperty("id_token").GetString()!;
    }

    public async Task<SessionView> ReadSessionAsync()
    {
        var json = await Client.GetStringAsync(MultiAccountHost.SessionProbePath, Cancellation);

        return JsonSerializer.Deserialize<SessionView>(json, JsonSerializerOptions.Web)!;
    }

    public async Task<JsonElement> GetPageAsync(string url)
    {
        var response = await Client.GetAsync(url, Cancellation);
        response.StatusCode.Should().Be(HttpStatusCode.OK, await response.Content.ReadAsStringAsync(Cancellation));

        return JsonDocument.Parse(await response.Content.ReadAsStringAsync(Cancellation)).RootElement;
    }

    public Task<HttpResponseMessage> EndSessionAsync(Dictionary<string, string?> parameters) =>
        Client.GetAsync(QueryHelpers.AddQueryString("/connect/endsession", parameters), Cancellation);

    public static string SubjectOf(string idToken)
    {
        using var payload = JsonDocument.Parse(Base64Url.DecodeFromChars(idToken.Split('.')[1]));
        return payload.RootElement.GetProperty("sub").GetString()!;
    }

    public static string Location(HttpResponseMessage response) => response.Headers.Location!.OriginalString;

    /// <summary>The interaction identifier the framework put on a redirect to a host page.</summary>
    public static string InteractionIdFrom(HttpResponseMessage response)
    {
        var location = Location(response);
        return QueryHelpers.ParseQuery(location[location.IndexOf('?')..])[InteractionHandoff.InteractionIdParameter]!;
    }

    /// <summary>The query of a redirect to the client's registered redirect URI.</summary>
    public static Dictionary<string, StringValues> QueryAtClient(HttpResponseMessage response)
    {
        response.StatusCode.Should().Be(HttpStatusCode.Redirect);
        var location = Location(response);
        location.Should().StartWith(MultiAccountHost.Redirect + "?");

        return QueryHelpers.ParseQuery(location[location.IndexOf('?')..]);
    }

    /// <summary>The response sent the browser to <paramref name="path"/> with an interaction identifier.</summary>
    public static void ShouldHaveGoneTo(HttpResponseMessage response, string path)
    {
        response.StatusCode.Should().Be(HttpStatusCode.Redirect);
        Location(response).Should().StartWith($"{path}?{InteractionHandoff.InteractionIdParameter}=");
    }
}
