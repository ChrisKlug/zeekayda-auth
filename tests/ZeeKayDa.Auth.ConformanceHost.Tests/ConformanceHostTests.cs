using System.Net;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.AspNetCore.WebUtilities;

namespace ZeeKayDa.Auth.ConformanceHost.Tests;

/// <summary>
/// Smoke tests that host the conformance host in the Conformance environment the suite runs it in,
/// and drive it as the suite's browser and clients would: they fail if a registration the suite
/// depends on stops behaving the way its plans expect, before a full suite run would say so.
/// </summary>
public sealed partial class ConformanceHostTests : IDisposable
{
    // The Conformance environment issues on a hostname rather than localhost, so that the suite's
    // containers and a browser on the same machine can both reach one issuer URL. The framework
    // constrains its endpoints to the issuer's host, so a browser has to address it by that name or
    // every endpoint answers 404.
    private const string Issuer = "https://zeekayda.localtest.me:5443";
    private const string PublicClientId = "sample-public-client";
    private const string PublicRedirectUri = "https://localhost:5002/signin-oidc";
    private const string ConformanceClientId = "conformance-client";
    // The conformance suite's oidcc-server-client-secret-post module authenticates with the secret
    // in the request body, and most servers let a client use one method only, so the suite config's
    // client_secret_post block names a client of its own rather than reusing the one above.
    private const string ConformancePostClientId = "conformance-client-post";
    private const string ConformancePostClientSecret = "conformance-client-post-secret";
    private const string ConformanceRedirectUri = "https://localhost.emobix.co.uk:8443/test/a/zeekayda/callback";

    // A field rather than a class fixture: the host's entry point is internal, and a public test
    // class cannot name an internal fixture type.
    private readonly ConformanceHostFactory _factory = new();

    public void Dispose() => _factory.Dispose();

    private static CancellationToken Cancellation => TestContext.Current.CancellationToken;

    private HttpClient NewBrowser() => _factory.CreateClient(new WebApplicationFactoryClientOptions
    {
        BaseAddress = new Uri(Issuer),
        AllowAutoRedirect = false,
        HandleCookies = true,
    });

    private sealed class ConformanceHostFactory : WebApplicationFactory<Program>
    {
        protected override void ConfigureWebHost(IWebHostBuilder builder) => builder.UseEnvironment("Conformance");
    }

    [Fact]
    public async Task Discovery_advertises_client_secret_post_beside_the_default_methods()
    {
        using var browser = NewBrowser();

        var document = await browser.GetFromJsonAsync<JsonElement>("/.well-known/openid-configuration", Cancellation);

        document.GetProperty("token_endpoint_auth_methods_supported").EnumerateArray()
            .Select(method => method.GetString())
            .Should().BeEquivalentTo(["client_secret_basic", "none", "client_secret_post"]);
    }

    [Fact]
    public async Task A_client_that_skips_consent_goes_from_the_login_page_straight_back_to_the_client()
    {
        using var browser = NewBrowser();
        var (_, challenge) = NewPkcePair();

        var loginPage = await FollowAuthorizeAsync(browser, challenge, ConformanceClientId, ConformanceRedirectUri);
        var callback = await PostFormAsync(browser, loginPage, AliceLogin());

        callback.Should().StartWith(ConformanceRedirectUri + "?",
            because: "a conformance client is registered with RequireConsent off, so no consent page comes between");
        QueryHelpers.ParseQuery(new Uri(callback).Query)["code"].ToString().Should().NotBeEmpty();
    }

    [Fact]
    public async Task A_conformance_client_is_issued_a_code_for_a_request_with_a_nonce_and_no_code_challenge()
    {
        // The certification plan's modules send no PKCE, so the conformance clients are registered
        // with RequirePkce off; this proves the host's settings wiring actually applies it, which
        // a request carrying PKCE cannot tell apart from the default.
        using var browser = NewBrowser();

        var loginPage = await AuthorizeWithoutPkceAsync(browser, ConformanceClientId, ConformanceRedirectUri);
        loginPage.Should().StartWith("/login?",
            because: "a confidential client permitted to rely on its nonce is not refused for omitting code_challenge");
        var callback = await PostFormAsync(browser, loginPage, AliceLogin());

        callback.Should().StartWith(ConformanceRedirectUri + "?");
        QueryHelpers.ParseQuery(new Uri(callback).Query)["code"].ToString().Should().NotBeEmpty();
    }

    [Fact]
    public async Task A_public_client_is_still_refused_without_a_code_challenge()
    {
        // The opt-out is applied per registration, not to the environment: the public client in the
        // same settings file has no secret and never gets it.
        using var browser = NewBrowser();

        var response = await AuthorizeWithoutPkceAsync(browser, PublicClientId, PublicRedirectUri);

        response.Should().StartWith(PublicRedirectUri + "?");
        QueryHelpers.ParseQuery(new Uri(response).Query)["error"].ToString().Should().Be("invalid_request");
    }

    [Fact]
    public async Task The_conformance_post_client_redeems_its_code_with_the_secret_in_the_request_body()
    {
        // What oidcc-server-client-secret-post does: it copies the suite config's client_secret_post
        // block over 'client' and runs the happy flow, sending client_id and client_secret as form
        // fields instead of an Authorization header. The registration has client_secret_post as its
        // only permitted method, so this fails unless both the server advertises the method and the
        // host's settings wiring applies the client's list.
        using var browser = NewBrowser();

        var loginPage = await AuthorizeWithoutPkceAsync(browser, ConformancePostClientId, ConformanceRedirectUri);
        var callback = await PostFormAsync(browser, loginPage, AliceLogin());
        callback.Should().StartWith(ConformanceRedirectUri + "?");
        var code = QueryHelpers.ParseQuery(new Uri(callback).Query)["code"].ToString();

        var tokens = await RedeemWithSecretInBodyAsync(browser, code);

        PayloadOf(tokens.GetProperty("id_token").GetString()!)
            .GetProperty("sub").GetString().Should().Be("a1ice000000000000000000000000001");
    }

    [Fact]
    public async Task The_conformance_post_client_is_refused_when_it_sends_its_secret_as_basic_auth()
    {
        // The settings list replaces the framework default rather than adding to it, so this client
        // may use client_secret_post and nothing else. Without that, the same credentials would
        // also be accepted in an Authorization header and the registration would say one thing
        // while permitting two — which the happy-path test above cannot tell apart.
        using var browser = NewBrowser();

        var loginPage = await AuthorizeWithoutPkceAsync(browser, ConformancePostClientId, ConformanceRedirectUri);
        var callback = await PostFormAsync(browser, loginPage, AliceLogin());
        var code = QueryHelpers.ParseQuery(new Uri(callback).Query)["code"].ToString();

        using var response = await RedeemWithBasicAuthAsync(browser, code);

        response.StatusCode.Should().Be(HttpStatusCode.Unauthorized);
        var error = await response.Content.ReadFromJsonAsync<JsonElement>(Cancellation);
        error.GetProperty("error").GetString().Should().Be("invalid_client");
    }

    [Fact]
    public async Task An_absolute_signing_key_path_is_used_as_given_rather_than_joined_to_the_content_root()
    {
        var keyDirectory = Path.Join(Path.GetTempPath(), "zkd-conformance-host-" + Guid.NewGuid().ToString("N"));
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

    private static Task<string> AuthorizeWithoutPkceAsync(HttpClient browser, string clientId, string redirectUri) =>
        RedirectOfAsync(browser, QueryHelpers.AddQueryString("/connect/authorize", new Dictionary<string, string?>
        {
            ["client_id"] = clientId,
            ["redirect_uri"] = redirectUri,
            ["response_type"] = "code",
            ["scope"] = "openid profile",
            ["nonce"] = "sample-nonce",
            ["state"] = "sample-state",
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

        // A failure's body goes in the assertion message, where it says why instead of only that the
        // status was wrong.
        if (response.StatusCode != HttpStatusCode.Redirect)
        {
            var body = await response.Content.ReadAsStringAsync(Cancellation);
            response.StatusCode.Should().Be(HttpStatusCode.Redirect, because: body[..Math.Min(body.Length, 3000)]);
        }

        return response.Headers.Location!.ToString();
    }

    /// <summary>
    /// Loads a page for its hidden inputs, then posts its form where a browser would: to the
    /// form's action, or back to the page's own URL when it has none. A page whose action drops
    /// the zkd_i parameter therefore fails here, as it would in a browser.
    /// </summary>
    private static async Task<HttpResponseMessage> SubmitFormAsync(HttpClient browser, string pageUrl, Dictionary<string, string> fields)
    {
        var html = await browser.GetStringAsync(pageUrl, Cancellation);
        var posted = HiddenInputs(html).Where(hidden => !fields.ContainsKey(hidden.Key)).Concat(fields);

        using var form = new FormUrlEncodedContent(posted);
        return await browser.PostAsync(FormTarget(browser, html, pageUrl), form, Cancellation);
    }

    // An absent or empty action posts to the page's own URL; any other is resolved against it.
    // Relative URLs resolve against the browser's own base address: posting a form back to a host
    // the page did not come from loses the antiforgery cookie with it.
    private static Uri FormTarget(HttpClient browser, string html, string pageUrl)
    {
        var page = new Uri(browser.BaseAddress!, pageUrl);
        var action = WebUtility.HtmlDecode(FormAction().Match(html).Groups["action"].Value);
        return action.Length == 0 ? page : new Uri(page, action);
    }

    /// <summary>Redeems a code with client_secret_post: the credentials are form fields, not a header.</summary>
    private static async Task<JsonElement> RedeemWithSecretInBodyAsync(HttpClient client, string code)
    {
        using var form = new FormUrlEncodedContent(new Dictionary<string, string>
        {
            ["grant_type"] = "authorization_code",
            ["code"] = code,
            ["redirect_uri"] = ConformanceRedirectUri,
            ["client_id"] = ConformancePostClientId,
            ["client_secret"] = ConformancePostClientSecret,
        });

        using var response = await client.PostAsync("/connect/token", form, Cancellation);
        if (response.StatusCode != HttpStatusCode.OK)
        {
            var body = await response.Content.ReadAsStringAsync(Cancellation);
            response.StatusCode.Should().Be(HttpStatusCode.OK, because: body[..Math.Min(body.Length, 3000)]);
        }

        return await response.Content.ReadFromJsonAsync<JsonElement>(Cancellation);
    }

    /// <summary>Redeems a code with client_secret_basic: the credentials are an Authorization header.</summary>
    private static async Task<HttpResponseMessage> RedeemWithBasicAuthAsync(HttpClient client, string code)
    {
        using var form = new FormUrlEncodedContent(new Dictionary<string, string>
        {
            ["grant_type"] = "authorization_code",
            ["code"] = code,
            ["redirect_uri"] = ConformanceRedirectUri,
        });

        using var request = new HttpRequestMessage(HttpMethod.Post, "/connect/token") { Content = form };
        var credentials = $"{Uri.EscapeDataString(ConformancePostClientId)}:{Uri.EscapeDataString(ConformancePostClientSecret)}";
        request.Headers.Authorization = new AuthenticationHeaderValue(
            "Basic", Convert.ToBase64String(Encoding.UTF8.GetBytes(credentials)));

        return await client.SendAsync(request, Cancellation);
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

    /// <summary>The name and value of every hidden input on the page, in document order, as a browser posts them.</summary>
    private static IEnumerable<KeyValuePair<string, string>> HiddenInputs(string html) =>
        InputTag().Matches(html)
            .Select(input => (Type: Attribute(input.Value, "type"), Name: Attribute(input.Value, "name"), Value: Attribute(input.Value, "value")))
            .Where(input => string.Equals(input.Type, "hidden", StringComparison.OrdinalIgnoreCase) && input.Name is not null)
            .Select(input => KeyValuePair.Create(input.Name!, WebUtility.HtmlDecode(input.Value ?? string.Empty)));

    private static string? Attribute(string tag, string name)
    {
        var match = Regex.Match(tag, $@"\s{name}\s*=\s*""([^""]*)""", RegexOptions.IgnoreCase);
        return match.Success ? match.Groups[1].Value : null;
    }

    [GeneratedRegex("<input\\b[^>]*>", RegexOptions.IgnoreCase)]
    private static partial Regex InputTag();

    // HTML attribute names are case-insensitive, and a value may be double-, single- or unquoted.
    [GeneratedRegex("""<form\b[^>]*\saction\s*=\s*(?:"(?<action>[^"]*)"|'(?<action>[^']*)'|(?<action>[^\s>"']+))""", RegexOptions.IgnoreCase)]
    private static partial Regex FormAction();
}
