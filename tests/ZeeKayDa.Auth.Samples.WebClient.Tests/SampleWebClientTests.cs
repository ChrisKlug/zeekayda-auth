extern alias IdentityServer;

using Microsoft.AspNetCore.Authentication.OpenIdConnect;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.DependencyInjection;

namespace ZeeKayDa.Auth.Samples.WebClient.Tests;

/// <summary>
/// End-to-end tests that host the sample identity server and the sample web client exactly as
/// they ship, and drive a browser between them. Microsoft's OpenID Connect handler does the
/// client's side — discovery, the code exchange, ID token validation, and at_hash validation when
/// the claim is present — so these fail if the server stops producing what an ordinary .NET
/// relying party accepts. The handler accepts an ID token with no at_hash at all; that the server
/// emits one is proven by the identity server sample's own tests.
/// </summary>
public sealed class SampleWebClientTests : IDisposable
{
    private static readonly Uri IdentityServerOrigin = new("https://localhost:5443");
    private static readonly Uri WebClientOrigin = new("https://localhost:5002");

    private const string AliceSubject = "a1ice000000000000000000000000001";

    private readonly WebApplicationFactory<IdentityServer::Program> _identityServer = new();
    private readonly WebApplicationFactory<Program> _webClient;
    private readonly TwoSiteBrowser _browser;

    public SampleWebClientTests()
    {
        // The handler's server-to-server calls (discovery, keys, token) go to the in-process
        // identity server. Configure, not PostConfigure: the handler builds its backchannel in its
        // own post-configure step, which has to see this handler.
        _webClient = new WebApplicationFactory<Program>().WithWebHostBuilder(host => host.ConfigureTestServices(services =>
            services.Configure<OpenIdConnectOptions>(OpenIdConnectDefaults.AuthenticationScheme, options =>
                options.BackchannelHttpHandler = _identityServer.Server.CreateHandler())));

        _browser = new TwoSiteBrowser(new Dictionary<Uri, HttpMessageHandler>
        {
            [IdentityServerOrigin] = _identityServer.Server.CreateHandler(),
            [WebClientOrigin] = _webClient.Server.CreateHandler(),
        });
    }

    private static CancellationToken Cancellation => TestContext.Current.CancellationToken;

    [Fact]
    public async Task Opening_the_profile_page_signs_alice_in_at_the_identity_server_and_shows_her_claims()
    {
        var profile = await SignInAliceAsync();

        profile.Url.Should().Be(new Uri(WebClientOrigin, "/profile"));
        profile.Html.Should().Contain("Hello, Alice Example").And.Contain(AliceSubject);
    }

    [Fact]
    public async Task Signing_out_ends_the_session_at_the_identity_server_and_returns_to_the_client()
    {
        await SignInAliceAsync();
        var home = await _browser.GetAsync(WebClientOrigin, Cancellation);

        var confirmation = await _browser.SubmitAsync(home, [], Cancellation);
        var signedOut = await _browser.SubmitAsync(confirmation, [], Cancellation);

        signedOut.Url.Should().Be(new Uri(WebClientOrigin, "/"));
        signedOut.Html.Should().Contain("You are not signed in");
        _browser.Visited.Should().Contain(url =>
            url.AbsolutePath == "/connect/endsession" && url.Query.Contains("id_token_hint=", StringComparison.Ordinal));
        _browser.Visited.Should().Contain(url => url.AbsolutePath == "/signout-callback-oidc");
    }

    [Fact]
    public async Task After_signing_out_opening_the_profile_page_asks_alice_to_sign_in_again()
    {
        await SignInAliceAsync();
        var home = await _browser.GetAsync(WebClientOrigin, Cancellation);
        var confirmation = await _browser.SubmitAsync(home, [], Cancellation);
        await _browser.SubmitAsync(confirmation, [], Cancellation);

        var page = await _browser.GetAsync(new Uri(WebClientOrigin, "/profile"), Cancellation);

        page.Url.GetLeftPart(UriPartial.Path).Should().Be(new Uri(IdentityServerOrigin, "/login").ToString());
    }

    public void Dispose()
    {
        _browser.Dispose();
        _webClient.Dispose();
        _identityServer.Dispose();
    }

    /// <summary>Signs alice in through the client's protected page, login and consent.</summary>
    private async Task<Page> SignInAliceAsync()
    {
        var login = await _browser.GetAsync(new Uri(WebClientOrigin, "/profile"), Cancellation);
        var consent = await _browser.SubmitAsync(login, new()
        {
            ["username"] = "alice",
            ["password"] = "alice-password",
            ["action"] = "login",
        }, Cancellation);

        return await _browser.SubmitAsync(consent, new() { ["action"] = "allow" }, Cancellation);
    }
}
