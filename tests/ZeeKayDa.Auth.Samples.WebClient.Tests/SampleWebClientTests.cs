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
    private readonly WebApplicationFactory<Program> _webClientHost = new();
    private readonly WebApplicationFactory<Program> _webClient;
    private readonly TwoSiteBrowser _browser;

    public SampleWebClientTests()
    {
        // The handler's server-to-server calls (discovery, keys, token) go to the in-process
        // identity server. Configure, not PostConfigure: the handler builds its backchannel in its
        // own post-configure step, which has to see this handler.
        _webClient = _webClientHost.WithWebHostBuilder(host => host.ConfigureTestServices(services =>
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

    [Fact]
    public async Task A_consent_submitted_twice_starts_a_new_sign_in_at_the_client_instead_of_failing()
    {
        // The double click: the first submission completed the sign-in, so the second has nothing
        // to continue. The server sends the browser to the client's initiate_login_uri, the client
        // starts again, and the user — still signed in at the server — is simply asked again.
        var login = await _browser.GetAsync(new Uri(WebClientOrigin, "/profile"), Cancellation);
        var consent = await _browser.SubmitAsync(login, AliceCredentials(), Cancellation);
        await _browser.SubmitAsync(consent, new() { ["action"] = "allow" }, Cancellation);

        var again = await _browser.SubmitAsync(consent, new() { ["action"] = "allow" }, Cancellation);

        _browser.Visited.Should().Contain(url =>
            url.GetLeftPart(UriPartial.Path) == new Uri(WebClientOrigin, "/initiate-login").ToString()
            && url.Query == "?iss=https%3A%2F%2Flocalhost%3A5443");
        again.Url.AbsolutePath.Should().Be("/consent");
        again.Html.Should().Contain("Allow access?");
    }

    [Fact]
    public async Task A_sign_out_confirmed_twice_ends_on_the_signed_out_page()
    {
        await SignInAliceAsync();
        var home = await _browser.GetAsync(WebClientOrigin, Cancellation);
        var confirmation = await _browser.SubmitAsync(home, [], Cancellation);
        await _browser.SubmitAsync(confirmation, [], Cancellation);

        var again = await _browser.SubmitAsync(confirmation, [], Cancellation);

        again.Url.Should().Be(new Uri(IdentityServerOrigin, "/signed-out"));
    }

    [Fact]
    public async Task The_client_starts_no_sign_in_for_an_issuer_it_does_not_trust()
    {
        using var client = _webClient.CreateClient(new WebApplicationFactoryClientOptions
        {
            BaseAddress = WebClientOrigin,
            AllowAutoRedirect = false,
        });

        using var response = await client.GetAsync("/initiate-login?iss=https%3A%2F%2Fattacker.example.net", Cancellation);

        response.StatusCode.Should().Be(System.Net.HttpStatusCode.BadRequest);
    }

    [Fact]
    public async Task The_client_starts_a_sign_in_from_a_form_post_naming_its_issuer()
    {
        using var client = _webClient.CreateClient(new WebApplicationFactoryClientOptions
        {
            BaseAddress = WebClientOrigin,
            AllowAutoRedirect = false,
        });
        using var form = new FormUrlEncodedContent([KeyValuePair.Create("iss", IdentityServerOrigin.GetLeftPart(UriPartial.Authority))]);

        using var response = await client.PostAsync("/initiate-login", form, Cancellation);

        response.StatusCode.Should().Be(System.Net.HttpStatusCode.Redirect);
        response.Headers.Location!.GetLeftPart(UriPartial.Path).Should().Be(new Uri(IdentityServerOrigin, "/connect/authorize").ToString());
    }

    [Fact]
    public async Task The_client_refuses_to_be_framed()
    {
        using var client = _webClient.CreateClient(new WebApplicationFactoryClientOptions { BaseAddress = WebClientOrigin });

        using var response = await client.GetAsync("/", Cancellation);

        response.Headers.GetValues("X-Frame-Options").Should().Equal("DENY");
        response.Headers.GetValues("Content-Security-Policy").Should().Equal("frame-ancestors 'none'");
    }

    public void Dispose()
    {
        _browser.Dispose();
        _webClient.Dispose();
        _webClientHost.Dispose();
        _identityServer.Dispose();
    }

    /// <summary>Signs alice in through the client's protected page, login and consent.</summary>
    private async Task<Page> SignInAliceAsync()
    {
        var login = await _browser.GetAsync(new Uri(WebClientOrigin, "/profile"), Cancellation);
        var consent = await _browser.SubmitAsync(login, AliceCredentials(), Cancellation);

        return await _browser.SubmitAsync(consent, new() { ["action"] = "allow" }, Cancellation);
    }

    private static Dictionary<string, string> AliceCredentials() => new()
    {
        ["username"] = "alice",
        ["password"] = "alice-password",
        ["action"] = "login",
    };
}
