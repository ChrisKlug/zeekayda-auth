using System.Security.Claims;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Routing;
using Microsoft.AspNetCore.WebUtilities;
using Microsoft.Extensions.DependencyInjection;
using ZeeKayDa.Auth.AspNetCore.Interaction;
using ZeeKayDa.Auth.Authorization;
using ZeeKayDa.Auth.Clients;
using static ZeeKayDa.Auth.AspNetCore.Tests.Providers.ProviderTestHost;

namespace ZeeKayDa.Auth.AspNetCore.Tests.Interaction;

/// <summary>
/// The <c>zkd_error</c> sub-code on an <c>access_denied</c> authorization response: one per refusal,
/// for a client registered with <c>EnableZkdErrorCodes</c>, and nothing for one without.
/// </summary>
public sealed class ZkdErrorCodeTests
{
    private const string Flagged = "flagged-client";
    private const string Plain = "plain-client";
    private const string ConsentPath = "/account/consent";
    private const string Pkce = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM";

    private static CancellationToken Cancellation => TestContext.Current.CancellationToken;

    /// <summary>A host with a login page, a consent page and one provider whose sign-in the host refuses.</summary>
    private static TestWebAppFactory NewHost() => new(
        configureOptions: options => options.AuthorizationEndpoint.Interaction.ConsentPath = ConsentPath,
        configureBuilder: builder =>
        {
            builder.AddInMemoryClients(clients => clients.Add(Registration(Flagged, enabled: true)).Add(Registration(Plain, enabled: false)));
            builder.WithProviders(
                auth => auth.AddOAuth("acme", "Acme", ConfigureAcme),
                options => options.OnProviderSignIn = context => context.DenyAsync());
        },
        mapEndpoints: MapPages);

    /// <summary>A host whose one provider is challenged straight from the authorization endpoint.</summary>
    private static TestWebAppFactory NewSingleProviderHost() => new(
        configureOptions: options =>
        {
            options.AuthorizationEndpoint.Interaction.LoginPath = null;
            options.AuthorizationEndpoint.Interaction.SupportsLocalSignIn = false;
        },
        configureBuilder: builder =>
        {
            builder.AddInMemoryClients(clients => clients.Add(Registration(Flagged, enabled: true)).Add(Registration(Plain, enabled: false)));
            builder.WithProviders(auth => auth.AddOAuth("acme", "Acme", ConfigureAcme));
        });

    private static Client Registration(string clientId, bool enabled) =>
        Client.CreatePublic(clientId, [RegisteredRedirect], [], ["openid"]) with { EnableZkdErrorCodes = enabled };

    private static void MapPages(IEndpointRouteBuilder endpoints)
    {
        endpoints.MapPost(LoginPath, async (HttpContext context, LoginInteraction login) =>
        {
            var form = await context.Request.ReadFormAsync(context.RequestAborted);
            if (form["provider"].FirstOrDefault() is { Length: > 0 } provider)
            {
                await login.ChallengeAsync(provider);
                return;
            }

            await login.SignInAsync(new ClaimsPrincipal(new ClaimsIdentity([new Claim("sub", "user-1")], "test")), AuthenticationMethods.Password);
        });

        endpoints.MapPost(LoginPath + "/cancel", (LoginInteraction login) => login.DenyAsync());
        endpoints.MapPost(ConsentPath, (ConsentInteraction consent) => consent.DenyAsync());
    }

    private static string AuthorizeUrl(string clientId) => QueryHelpers.AddQueryString("/connect/authorize", new Dictionary<string, string?>
    {
        ["client_id"] = clientId,
        ["redirect_uri"] = RegisteredRedirect,
        ["response_type"] = "code",
        ["scope"] = "openid",
        ["nonce"] = "n-0S6_WzA2Mj",
        ["code_challenge"] = Pkce,
        ["code_challenge_method"] = "S256",
    });

    private static async Task<string> ToLoginPageAsync(HttpClient client, string clientId) =>
        InteractionIdFrom(await client.GetAsync(AuthorizeUrl(clientId), Cancellation));

    private static string CallbackUrlOf(HttpResponseMessage challenge, string? error = null)
    {
        var query = new Dictionary<string, string?> { ["state"] = RedirectQueryOf(challenge)["state"].ToString() };
        if (error is null)
            query["code"] = "acme-code";
        else
            query["error"] = error;

        return QueryHelpers.AddQueryString("/connect/callback/acme", query);
    }

    /// <summary>The refusal reached the client as access_denied, with <paramref name="expected"/> as its sub-code, or none.</summary>
    private static void ShouldBeDeniedWith(HttpResponseMessage response, string? expected)
    {
        DestinationOf(response).Should().Be(RegisteredRedirect);
        var query = RedirectQueryOf(response);
        query["error"].ToString().Should().Be("access_denied");

        if (expected is null)
            query.Should().NotContainKey("zkd_error", "a client that did not opt in receives the standard response only");
        else
            query["zkd_error"].ToString().Should().Be(expected);
    }

    [Theory]
    [InlineData(Flagged, "login_cancelled")]
    [InlineData(Plain, null)]
    public async Task A_cancel_at_the_login_page_carries_login_cancelled_only_for_a_client_that_opted_in(string clientId, string? expected)
    {
        using var host = NewHost();
        using var client = NewClient(host);
        var interactionId = await ToLoginPageAsync(client, clientId);

        var cancel = await client.PostAsync(WithInteractionId(LoginPath + "/cancel", interactionId), Form(), Cancellation);

        ShouldBeDeniedWith(cancel, expected);
    }

    [Theory]
    [InlineData(Flagged, "consent_declined")]
    [InlineData(Plain, null)]
    public async Task A_decline_at_the_consent_page_carries_consent_declined_only_for_a_client_that_opted_in(string clientId, string? expected)
    {
        using var host = NewHost();
        using var client = NewClient(host);
        var interactionId = await ToLoginPageAsync(client, clientId);
        await client.PostAsync(WithInteractionId(LoginPath, interactionId), Form(("sub", "user-1")), Cancellation);

        var decline = await client.PostAsync(WithInteractionId(ConsentPath, interactionId), Form(), Cancellation);

        ShouldBeDeniedWith(decline, expected);
    }

    [Theory]
    [InlineData(Flagged, "account_refused")]
    [InlineData(Plain, null)]
    public async Task A_host_refusing_the_external_account_carries_account_refused_only_for_a_client_that_opted_in(string clientId, string? expected)
    {
        using var host = NewHost();
        using var client = NewClient(host);
        var interactionId = await ToLoginPageAsync(client, clientId);
        var challenge = await client.PostAsync(WithInteractionId(LoginPath, interactionId), Form(("provider", "acme")), Cancellation);
        var callback = await client.GetAsync(CallbackUrlOf(challenge), Cancellation);

        var resume = await client.GetAsync(callback.Headers.Location!.OriginalString, Cancellation);

        ShouldBeDeniedWith(resume, expected);
    }

    [Theory]
    [InlineData(Flagged, "provider_declined")]
    [InlineData(Plain, null)]
    public async Task A_refusal_at_the_only_provider_carries_provider_declined_only_for_a_client_that_opted_in(string clientId, string? expected)
    {
        using var host = NewSingleProviderHost();
        using var client = NewClient(host);
        var challenge = await client.GetAsync(AuthorizeUrl(clientId), Cancellation);

        var callback = await client.GetAsync(CallbackUrlOf(challenge, error: "access_denied"), Cancellation);

        ShouldBeDeniedWith(callback, expected);
    }

    [Theory]
    [InlineData(Flagged)]
    [InlineData(Plain)]
    public async Task The_description_names_the_stage_for_every_client_whether_or_not_it_opted_in(string clientId)
    {
        // The stage is not a secret: the flag buys a stable value to branch on, not the information.
        using var host = NewHost();
        using var client = NewClient(host);
        var interactionId = await ToLoginPageAsync(client, clientId);

        var cancel = await client.PostAsync(WithInteractionId(LoginPath + "/cancel", interactionId), Form(), Cancellation);

        RedirectQueryOf(cancel)["error_description"].ToString().Should().Be("The user cancelled the request at the sign-in page.");
    }
}
