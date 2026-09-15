using System.Net;
using System.Net.Http.Json;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;
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

    private readonly WebApplicationFactory<Program> _factory;

    public SampleIdentityServerTests(WebApplicationFactory<Program> factory) => _factory = factory;

    private static CancellationToken Cancellation => TestContext.Current.CancellationToken;

    private HttpClient NewBrowser() => _factory.CreateClient(new WebApplicationFactoryClientOptions
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

    // ── Driving the flow ─────────────────────────────────────────────────────────────────────────

    /// <summary>Starts an authorization request and returns the login page URL it lands on.</summary>
    private static async Task<string> FollowAuthorizeAsync(HttpClient browser, string challenge)
    {
        var authorize = QueryHelpers.AddQueryString("/connect/authorize", new Dictionary<string, string?>
        {
            ["client_id"] = ClientId,
            ["redirect_uri"] = RedirectUri,
            ["response_type"] = "code",
            ["scope"] = "openid profile",
            ["nonce"] = "sample-nonce",
            ["state"] = "sample-state",
            ["code_challenge"] = challenge,
            ["code_challenge_method"] = "S256",
        });

        using var response = await browser.GetAsync(authorize, Cancellation);
        response.StatusCode.Should().Be(HttpStatusCode.Redirect);
        return response.Headers.Location!.ToString();
    }

    /// <summary>Submits a page's form and returns where the framework redirected the browser.</summary>
    private static async Task<string> PostFormAsync(HttpClient browser, string pageUrl, Dictionary<string, string> fields)
    {
        using var response = await SubmitFormAsync(browser, pageUrl, fields);
        response.StatusCode.Should().Be(HttpStatusCode.Redirect);
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

    private static string Base64UrlEncode(byte[] bytes) =>
        Convert.ToBase64String(bytes).TrimEnd('=').Replace('+', '-').Replace('/', '_');

    [GeneratedRegex("name=\"__RequestVerificationToken\" type=\"hidden\" value=\"([^\"]+)\"")]
    private static partial Regex AntiforgeryToken();
}
