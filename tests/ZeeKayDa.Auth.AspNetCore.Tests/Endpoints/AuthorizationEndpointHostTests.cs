using System.Net;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.AspNetCore.WebUtilities;
using Microsoft.Extensions.DependencyInjection;
using ZeeKayDa.Auth.Authorization;
using ZeeKayDa.Auth.Stores;

namespace ZeeKayDa.Auth.AspNetCore.Tests.Endpoints;

/// <summary>
/// The parts of <c>/connect/authorize</c> (#83) that only a real host can answer: whether the route
/// is mapped at all, and whether a host-wide authorization fallback policy is bypassed by the
/// framework's own login handoff. The two-phase error model itself — status codes, redirects,
/// cookies — is covered host-free in <see cref="AuthorizationEndpointTests"/>.
/// </summary>
[Collection(DefaultHostCollection.Name)]
public sealed class AuthorizationEndpointHostTests(FallbackPolicyHostFixture fallback)
{
    private const string RegisteredRedirect = "https://test.example.com/callback";
    private const string Challenge = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM";

    private static CancellationToken Cancellation => TestContext.Current.CancellationToken;

    private static Dictionary<string, string?> ValidQuery(
        string clientId = "test-client",
        string redirectUri = RegisteredRedirect) => new()
        {
            ["client_id"] = clientId,
            ["redirect_uri"] = redirectUri,
            ["response_type"] = "code",
            ["scope"] = "openid",
            ["nonce"] = "n-0S6_WzA2Mj",
            ["code_challenge"] = Challenge,
            ["code_challenge_method"] = "S256",
        };

    private static string AuthorizeUrl(Dictionary<string, string?> query) =>
        QueryHelpers.AddQueryString("/connect/authorize", query);

    // ── Anonymous access ──────────────────────────────────────────────────────────────────────

    [Fact]
    public async Task The_authorize_endpoint_is_reachable_under_a_host_fallback_authorization_policy()
    {
        // The user arriving here is not signed in yet, so a host-wide RequireAuthenticatedUser
        // fallback must not challenge the request before the framework's own handoff runs. The
        // request is deliberately invalid, so the framework's local error proves who answered.
        var client = fallback.Client;

        var canary = await client.GetAsync("/host-route", Cancellation);
        var response = await client.GetAsync(AuthorizeUrl(ValidQuery(clientId: "no-such-client")), Cancellation);

        canary.StatusCode.Should().Be(HttpStatusCode.Unauthorized, "the fallback policy is in force on the host's own routes");
        response.StatusCode.Should().Be(HttpStatusCode.BadRequest, "the framework answered, not the host's authentication challenge");
    }

    // ── A host without the code grant ────────────────────────────────────────────────────────

    [Fact]
    public async Task Authorize_is_not_served_on_a_host_without_the_code_grant()
    {
        // GrantTypesSupported is the declaration that the interactive machinery is unused. Before,
        // such a host accepted response_type=code, wrote an interaction context and answered
        // server_error while its metadata said the grant was unsupported.
        using var factory = new TestWebAppFactory(opts => opts.GrantTypesSupported = [GrantType.ClientCredentials]);
        using var client = factory.CreateClient(new WebApplicationFactoryClientOptions
        {
            BaseAddress = new Uri("https://test.example.com"),
            AllowAutoRedirect = false,
        });

        var response = await client.GetAsync(AuthorizeUrl(ValidQuery()), Cancellation);

        response.StatusCode.Should().Be(HttpStatusCode.NotFound);
        response.Headers.TryGetValues("Set-Cookie", out var cookies);
        (cookies ?? []).Should().BeEmpty("no binding was issued");
        ((InMemoryInteractionBackingStore)factory.Services.GetRequiredService<IInteractionBackingStore>()).Count
            .Should().Be(0, "nothing was written to the interaction store");
    }
}
