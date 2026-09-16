using System.Net;
using System.Net.Http.Json;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.AspNetCore.WebUtilities;

namespace ZeeKayDa.Auth.Samples.IdentityServer.Tests;

/// <summary>
/// Smoke tests that host the sample exactly as it ships and drive it as a browser and client
/// would: they fail if the sample's registration, pages or seeded data stop producing a working
/// sign-in. On the Windows runner they also prove the generated signing key passes the
/// framework's owner-only file check.
/// </summary>
public sealed partial class SampleIdentityServerTests : IClassFixture<WebApplicationFactory<Program>>
{
    private const string Issuer = "https://localhost:5443";
    private const string ClientId = "sample-public-client";
    private const string RedirectUri = "https://localhost:5002/signin-oidc";
    private const string PostLogoutRedirectUri = "https://localhost:5002/signout-callback-oidc";
    private const string ConformanceClientId = "conformance-client";
    private const string ConformanceRedirectUri = "https://localhost.emobix.co.uk:8443/test/a/zeekayda/callback";

    private readonly WebApplicationFactory<Program> _factory;

    public SampleIdentityServerTests(WebApplicationFactory<Program> factory) => _factory = factory;

    private static CancellationToken Cancellation => TestContext.Current.CancellationToken;

    private HttpClient NewBrowser() => NewBrowser(_factory);

    private static HttpClient NewBrowser(WebApplicationFactory<Program> factory) => factory.CreateClient(new WebApplicationFactoryClientOptions
    {
        BaseAddress = new Uri(Issuer),
        AllowAutoRedirect = false,
        HandleCookies = true,
    });

    [Theory]
    [InlineData("/.well-known/openid-configuration")]
    [InlineData("/.well-known/oauth-authorization-server")]
    public async Task Discovery_is_served_for_the_configured_issuer(string path)
    {
        using var browser = NewBrowser();

        var document = await browser.GetFromJsonAsync<JsonElement>(path, Cancellation);

        document.GetProperty("issuer").GetString().Should().Be(Issuer);
    }

    [Fact]
    public async Task Alice_signs_in_through_login_and_consent_and_receives_an_id_token_with_her_claims()
    {
        using var browser = NewBrowser();
        var (verifier, challenge) = NewPkcePair();

        var loginPage = await FollowAuthorizeAsync(browser, challenge);
        var consentPage = await PostFormAsync(browser, loginPage, new()
        {
            ["username"] = "alice",
            ["password"] = "alice-password",
            ["action"] = "login",
        });
        var callback = await PostFormAsync(browser, consentPage, new() { ["action"] = "allow" });
        var tokens = await RedeemAsync(browser, CodeFrom(callback), verifier);

        var claims = PayloadOf(tokens.GetProperty("id_token").GetString()!);
        claims.GetProperty("sub").GetString().Should().Be("a1ice000000000000000000000000001");
        claims.GetProperty("name").GetString().Should().Be("Alice Example");
        claims.GetProperty("nonce").GetString().Should().Be("sample-nonce");
        claims.GetProperty("amr").EnumerateArray().Select(method => method.GetString()).Should().Equal("pwd");
        claims.GetProperty("at_hash").GetString().Should().Be(AtHashOf(tokens.GetProperty("access_token").GetString()!));
    }

    [Fact]
    public async Task A_user_who_registers_during_a_sign_in_can_complete_it_as_themselves()
    {
        using var browser = NewBrowser();
        var (verifier, challenge) = NewPkcePair();
        var loginPage = await FollowAuthorizeAsync(browser, challenge);

        // The login page's "Create an account" link carries its query string, so the sign-in continues.
        // Taken from the string: the Location is relative, and Uri would read it as a file path.
        var backToLogin = await PostFormAsync(browser, "/register" + loginPage[loginPage.IndexOf('?', StringComparison.Ordinal)..], new()
        {
            ["username"] = "bob",
            ["password"] = "bob-password",
            ["name"] = "Bob Registered",
            ["email"] = "bob@example.com",
        });
        var consentPage = await PostFormAsync(browser, backToLogin, new()
        {
            ["username"] = "bob",
            ["password"] = "bob-password",
            ["action"] = "login",
        });
        var callback = await PostFormAsync(browser, consentPage, new() { ["action"] = "allow" });
        var tokens = await RedeemAsync(browser, CodeFrom(callback), verifier);

        var claims = PayloadOf(tokens.GetProperty("id_token").GetString()!);
        claims.GetProperty("name").GetString().Should().Be("Bob Registered");
        claims.GetProperty("preferred_username").GetString().Should().Be("bob");
    }

    [Fact]
    public async Task A_wrong_password_shows_the_login_page_again_and_signs_no_one_in()
    {
        using var browser = NewBrowser();
        var (_, challenge) = NewPkcePair();
        var loginPage = await FollowAuthorizeAsync(browser, challenge);

        using var response = await SubmitFormAsync(browser, loginPage, new()
        {
            ["username"] = "alice",
            ["password"] = "not-her-password",
            ["action"] = "login",
        });

        response.StatusCode.Should().Be(HttpStatusCode.OK);
        (await response.Content.ReadAsStringAsync(Cancellation)).Should().Contain("The username or password is incorrect.");
    }

    [Fact]
    public async Task A_client_that_skips_consent_goes_from_the_login_page_straight_back_to_the_client()
    {
        using var factory = _factory.WithWebHostBuilder(host => host.UseEnvironment("Conformance"));
        using var browser = NewBrowser(factory);
        var (_, challenge) = NewPkcePair();

        var loginPage = await FollowAuthorizeAsync(browser, challenge, ConformanceClientId, ConformanceRedirectUri);
        var callback = await PostFormAsync(browser, loginPage, AliceLogin());

        callback.Should().StartWith(ConformanceRedirectUri + "?",
            because: "a conformance client is registered with RequireConsent off, so no consent page comes between");
        QueryHelpers.ParseQuery(new Uri(callback).Query)["code"].ToString().Should().NotBeEmpty();
    }

    [Fact]
    public async Task A_client_initiated_sign_out_is_confirmed_on_the_logout_page_and_returns_to_the_client_with_its_state()
    {
        using var browser = NewBrowser();
        await SignInAliceAsync(browser);

        var logoutPage = await RedirectOfAsync(browser, QueryHelpers.AddQueryString("/connect/endsession", new Dictionary<string, string?>
        {
            ["client_id"] = ClientId,
            ["post_logout_redirect_uri"] = PostLogoutRedirectUri,
            ["state"] = "logout-state",
        }));
        var page = await browser.GetStringAsync(logoutPage, Cancellation);
        var backAtClient = await PostFormAsync(browser, logoutPage, new());

        logoutPage.Should().StartWith("/logout?");
        page.Should().Contain("Sign out alice?").And.Contain(ClientId);
        backAtClient.Should().Be(PostLogoutRedirectUri + "?state=logout-state");
        (await FollowAuthorizeAsync(browser, NewPkcePair().Challenge)).Should().StartWith("/login?",
            because: "the session ended, so a new sign-in asks for the password again");
    }

    [Fact]
    public async Task A_sign_out_from_the_home_page_is_confirmed_and_lands_on_the_signed_out_page()
    {
        using var browser = NewBrowser();
        await SignInAliceAsync(browser);

        var home = await browser.GetStringAsync("/", Cancellation);
        var logoutPage = await RedirectOfAsync(browser, "/connect/endsession");
        var signedOut = await PostFormAsync(browser, logoutPage, new());

        home.Should().Contain("href=\"/connect/endsession\"");
        signedOut.Should().Be("/signed-out");
        (await browser.GetStringAsync(signedOut, Cancellation)).Should().Contain("You have been signed out");
    }

    [Fact]
    public async Task An_absolute_signing_key_path_is_used_as_given_rather_than_joined_to_the_content_root()
    {
        var keyDirectory = Path.Join(Path.GetTempPath(), "zkd-sample-" + Guid.NewGuid().ToString("N"));
        var keyPath = Path.Join(keyDirectory, "signing.pem");
        try
        {
            using var factory = _factory.WithWebHostBuilder(host => host.UseSetting("IdentityServer:SigningKeyPath", keyPath));
            using var browser = factory.CreateClient(new WebApplicationFactoryClientOptions { BaseAddress = new Uri(Issuer) });

            using var response = await browser.GetAsync("/.well-known/openid-configuration", Cancellation);

            response.StatusCode.Should().Be(HttpStatusCode.OK);
            File.Exists(keyPath).Should().BeTrue(
                because: "an operator's absolute key path is where the key is created and read, not a path under the app folder");
        }
        finally
        {
            if (Directory.Exists(keyDirectory))
                Directory.Delete(keyDirectory, recursive: true);
        }
    }

    // ── Driving the flow ─────────────────────────────────────────────────────────────────────────

    private static Dictionary<string, string> AliceLogin() => new()
    {
        ["username"] = "alice",
        ["password"] = "alice-password",
        ["action"] = "login",
    };

    /// <summary>Signs alice in to the sample client, through login and consent.</summary>
    private static async Task SignInAliceAsync(HttpClient browser)
    {
        var loginPage = await FollowAuthorizeAsync(browser, NewPkcePair().Challenge);
        var consentPage = await PostFormAsync(browser, loginPage, AliceLogin());
        var callback = await PostFormAsync(browser, consentPage, new() { ["action"] = "allow" });
        callback.Should().StartWith(RedirectUri);
    }

    /// <summary>Starts an authorization request and returns the page URL it lands on.</summary>
    private static Task<string> FollowAuthorizeAsync(HttpClient browser, string challenge) =>
        FollowAuthorizeAsync(browser, challenge, ClientId, RedirectUri);

    private static Task<string> FollowAuthorizeAsync(HttpClient browser, string challenge, string clientId, string redirectUri) =>
        RedirectOfAsync(browser, QueryHelpers.AddQueryString("/connect/authorize", new Dictionary<string, string?>
        {
            ["client_id"] = clientId,
            ["redirect_uri"] = redirectUri,
            ["response_type"] = "code",
            ["scope"] = "openid profile",
            ["nonce"] = "sample-nonce",
            ["state"] = "sample-state",
            ["code_challenge"] = challenge,
            ["code_challenge_method"] = "S256",
        }));

    /// <summary>Requests a URL the server answers with a redirect, and returns where it points.</summary>
    private static async Task<string> RedirectOfAsync(HttpClient browser, string url)
    {
        using var response = await browser.GetAsync(url, Cancellation);
        response.StatusCode.Should().Be(HttpStatusCode.Redirect);
        return response.Headers.Location!.ToString();
    }

    /// <summary>Submits a page's form and returns where the framework redirected the browser.</summary>
    private static async Task<string> PostFormAsync(HttpClient browser, string pageUrl, Dictionary<string, string> fields)
    {
        using var response = await SubmitFormAsync(browser, pageUrl, fields);

        // The host runs in Development, so a failure's body is the developer exception page — put it
        // in the assertion message, where it says why instead of only that the status was wrong.
        if (response.StatusCode != HttpStatusCode.Redirect)
        {
            var body = await response.Content.ReadAsStringAsync(Cancellation);
            response.StatusCode.Should().Be(HttpStatusCode.Redirect, because: body[..Math.Min(body.Length, 3000)]);
        }

        return response.Headers.Location!.ToString();
    }

    /// <summary>Loads a page for its antiforgery token, then posts its form back to the same URL.</summary>
    private static async Task<HttpResponseMessage> SubmitFormAsync(HttpClient browser, string pageUrl, Dictionary<string, string> fields)
    {
        var html = await browser.GetStringAsync(pageUrl, Cancellation);
        fields["__RequestVerificationToken"] = AntiforgeryToken().Match(html).Groups[1].Value;

        using var form = new FormUrlEncodedContent(fields);
        return await browser.PostAsync(pageUrl, form, Cancellation);
    }

    private static string CodeFrom(string callback)
    {
        callback.Should().StartWith(RedirectUri);
        return QueryHelpers.ParseQuery(new Uri(callback).Query)["code"].ToString();
    }

    private static async Task<JsonElement> RedeemAsync(HttpClient client, string code, string verifier)
    {
        using var form = new FormUrlEncodedContent(new Dictionary<string, string>
        {
            ["grant_type"] = "authorization_code",
            ["code"] = code,
            ["redirect_uri"] = RedirectUri,
            ["client_id"] = ClientId,
            ["code_verifier"] = verifier,
        });

        using var response = await client.PostAsync("/connect/token", form, Cancellation);
        response.StatusCode.Should().Be(HttpStatusCode.OK);
        return await response.Content.ReadFromJsonAsync<JsonElement>(Cancellation);
    }

    private static (string Verifier, string Challenge) NewPkcePair()
    {
        var verifier = Base64UrlEncode(RandomNumberGenerator.GetBytes(32));
        return (verifier, Base64UrlEncode(SHA256.HashData(Encoding.ASCII.GetBytes(verifier))));
    }

    private static JsonElement PayloadOf(string jwt)
    {
        var payload = jwt.Split('.')[1];
        return JsonDocument.Parse(Convert.FromBase64String(
            payload.Replace('-', '+').Replace('_', '/').PadRight(payload.Length + ((4 - (payload.Length % 4)) % 4), '='))).RootElement;
    }

    // OIDC Core §3.1.3.6: the left half of the SHA-256 hash of the access token, for an RS256 ID token.
    private static string AtHashOf(string accessToken) =>
        Base64UrlEncode(SHA256.HashData(Encoding.ASCII.GetBytes(accessToken))[..16]);

    private static string Base64UrlEncode(byte[] bytes) =>
        Convert.ToBase64String(bytes).TrimEnd('=').Replace('+', '-').Replace('/', '_');

    [GeneratedRegex("name=\"__RequestVerificationToken\" type=\"hidden\" value=\"([^\"]+)\"")]
    private static partial Regex AntiforgeryToken();
}
