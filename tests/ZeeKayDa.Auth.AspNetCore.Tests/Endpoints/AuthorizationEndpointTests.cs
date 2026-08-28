using System.Net;
using Microsoft.AspNetCore.WebUtilities;
using ZeeKayDa.Auth.AspNetCore.Interaction;

namespace ZeeKayDa.Auth.AspNetCore.Tests.Endpoints;

/// <summary>
/// Integration tests for <c>/connect/authorize</c> request validation (#83): the two-phase error
/// model over real HTTP. The default test host registers the public client <c>test-client</c>
/// with redirect URI <c>https://test.example.com/callback</c> and allowed scope <c>openid</c>.
/// </summary>
public sealed class AuthorizationEndpointTests : IDisposable
{
    private const string RegisteredRedirect = "https://test.example.com/callback";
    private const string Challenge = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM";

    private readonly TestWebAppFactory _factory;
    private readonly HttpClient _client;

    public AuthorizationEndpointTests()
    {
        _factory = new TestWebAppFactory();
        _client = _factory.CreateClient(new()
        {
            BaseAddress = new Uri("https://test.example.com"),
            AllowAutoRedirect = false,
        });
    }

    public void Dispose()
    {
        _client.Dispose();
        _factory.Dispose();
    }

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

    // ── Valid requests ────────────────────────────────────────────────────────────────────────

    [Fact]
    public async Task Valid_GET_request_passes_validation_and_reaches_the_unbuilt_stage()
    {
        var response = await _client.GetAsync(AuthorizeUrl(ValidQuery()), TestContext.Current.CancellationToken);

        response.StatusCode.Should().Be(HttpStatusCode.NotImplemented,
            "validation passed; interaction and code issuance are the next slices (#85–#87)");
    }

    [Fact]
    public async Task Valid_POST_form_request_passes_validation()
    {
        using var content = new FormUrlEncodedContent(
            ValidQuery().Where(kv => kv.Value is not null).Select(kv => KeyValuePair.Create(kv.Key, kv.Value!)));

        var response = await _client.PostAsync("/connect/authorize", content, TestContext.Current.CancellationToken);

        response.StatusCode.Should().Be(HttpStatusCode.NotImplemented);
    }

    [Fact]
    public async Task POST_without_form_content_type_is_a_local_error()
    {
        using var content = new StringContent("""{"client_id":"test-client"}""", System.Text.Encoding.UTF8, "application/json");

        var response = await _client.PostAsync("/connect/authorize", content, TestContext.Current.CancellationToken);

        response.StatusCode.Should().Be(HttpStatusCode.BadRequest);
    }

    // ── Phase 1: local errors ─────────────────────────────────────────────────────────────────

    [Theory]
    [InlineData("unknown-client", RegisteredRedirect)]
    [InlineData("test-client", "https://evil.example.com/callback")]
    public async Task Phase1_failures_render_a_local_400_and_never_redirect(string clientId, string redirectUri)
    {
        var response = await _client.GetAsync(
            AuthorizeUrl(ValidQuery(clientId, redirectUri)), TestContext.Current.CancellationToken);

        response.StatusCode.Should().Be(HttpStatusCode.BadRequest);
        response.Headers.Location.Should().BeNull("a phase-1 error must never redirect (open-redirect defence)");
        response.Content.Headers.ContentType!.MediaType.Should().Be("text/html");
    }

    [Fact]
    public async Task Phase1_error_page_never_echoes_request_values()
    {
        var response = await _client.GetAsync(
            AuthorizeUrl(ValidQuery(redirectUri: "https://evil.example.com/callback")),
            TestContext.Current.CancellationToken);

        var body = await response.Content.ReadAsStringAsync(TestContext.Current.CancellationToken);
        body.Should().NotContain("evil.example.com").And.NotContain("test-client");
    }

    // ── Phase 2: redirect errors ──────────────────────────────────────────────────────────────

    [Fact]
    public async Task Phase2_error_redirects_to_the_client_with_error_state_and_iss()
    {
        var query = ValidQuery();
        query.Remove("code_challenge");
        query["state"] = "opaque-client-state";

        var response = await _client.GetAsync(AuthorizeUrl(query), TestContext.Current.CancellationToken);

        response.StatusCode.Should().Be(HttpStatusCode.Redirect);
        var location = response.Headers.Location!;
        location.GetLeftPart(UriPartial.Path).Should().Be(RegisteredRedirect);

        var parameters = QueryHelpers.ParseQuery(location.Query);
        parameters["error"].ToString().Should().Be("invalid_request");
        parameters["state"].ToString().Should().Be("opaque-client-state");
        parameters["iss"].ToString().Should().Be("https://test.example.com",
            "iss is required on every authorization response (RFC 9207)");
    }

    [Fact]
    public async Task Phase2_error_without_state_omits_the_state_parameter()
    {
        var query = ValidQuery();
        query["response_type"] = "token";

        var response = await _client.GetAsync(AuthorizeUrl(query), TestContext.Current.CancellationToken);

        var parameters = QueryHelpers.ParseQuery(response.Headers.Location!.Query);
        parameters.Should().NotContainKey("state");
        parameters["error"].ToString().Should().Be("unsupported_response_type");
    }

    [Fact]
    public async Task Authorize_responses_are_never_cacheable()
    {
        var response = await _client.GetAsync(AuthorizeUrl(ValidQuery()), TestContext.Current.CancellationToken);

        response.Headers.CacheControl!.NoStore.Should().BeTrue();
    }

    // ── ErrorPath handoff ─────────────────────────────────────────────────────────────────────

    [Fact]
    public async Task Phase1_failure_with_configured_ErrorPath_redirects_with_an_opaque_id_only()
    {
        using var factory = new TestWebAppFactory(opts =>
            opts.AuthorizationEndpoint.Interaction.ErrorPath = "/auth-error");
        using var client = factory.CreateClient(new()
        {
            BaseAddress = new Uri("https://test.example.com"),
            AllowAutoRedirect = false,
        });

        var response = await client.GetAsync(
            AuthorizeUrl(ValidQuery(clientId: "unknown-client")), TestContext.Current.CancellationToken);

        response.StatusCode.Should().Be(HttpStatusCode.Redirect);
        var location = response.Headers.Location!;
        location.OriginalString.Should().StartWith("/auth-error");

        var parameters = QueryHelpers.ParseQuery(new Uri(new Uri("https://test.example.com"), location).Query);
        // The redirect must carry only the opaque id — error details in a URL leak into proxy
        // logs and browser history.
        parameters.Keys.Should().Equal(AuthorizeErrorTransport.QueryParameterName);

        response.Headers.GetValues("Set-Cookie").Should().ContainSingle(c =>
            c.StartsWith(AuthorizeErrorTransport.CookieName + "=") && c.Contains("httponly"));
    }
}
