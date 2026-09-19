using System.Net;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Security.Claims;
using System.Text.Json;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Routing;
using Microsoft.AspNetCore.WebUtilities;
using Microsoft.Extensions.DependencyInjection;
using ZeeKayDa.Auth.AspNetCore.Endpoints;
using ZeeKayDa.Auth.AspNetCore.Interaction;
using ZeeKayDa.Auth.AspNetCore.Tests.Interaction;
using ZeeKayDa.Auth.Authorization;
using ZeeKayDa.Auth.Clients;

namespace ZeeKayDa.Auth.AspNetCore.Tests.Endpoints;

/// <summary>
/// The parts of userinfo that only a real host can answer: dispatch by method and by host, where the
/// route is registered (and when it is not, per <see cref="UserInfoEndpoint.Map"/>), and what a real
/// authorize-then-token exchange's tokens do here. The handler's own behaviour — the claims, the
/// bearer transports, the refusals it writes itself — is covered host-free in
/// <see cref="UserInfoEndpointTests"/>.
/// </summary>
public sealed class UserInfoEndpointHostTests(DefaultHostFixture host, TenantIssuerHostFixture tenant)
    : IClassFixture<DefaultHostFixture>,
      IClassFixture<TenantIssuerHostFixture>
{
    private const string UserInfoPath = "/connect/userinfo";
    private const string TokenPath = "/connect/token";
    private const string Issuer = "https://test.example.com";
    private const string Redirect = "https://test.example.com/callback";
    private const string LoginPath = "/account/login";
    private const string App = "app";
    private const string Subject = "user-1";

    // RFC 7636 Appendix B.
    private const string Verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
    private const string CodeChallenge = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM";

    private static CancellationToken Cancellation => TestContext.Current.CancellationToken;

    // ── Method and host dispatch ──────────────────────────────────────────────────────────────
    //
    // Decided by routing before the handler runs, so the Authorization header's content plays no
    // part: a placeholder value is enough to prove which status these bring back.

    [Fact]
    public async Task A_GET_is_answered_and_a_DELETE_is_405()
    {
        using var request = new HttpRequestMessage(HttpMethod.Delete, UserInfoPath);
        request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", "placeholder");

        var response = await host.Client.SendAsync(request, Cancellation);

        response.StatusCode.Should().Be(HttpStatusCode.MethodNotAllowed);
    }

    [Fact]
    public async Task The_endpoint_is_404_on_a_host_that_is_not_the_issuer()
    {
        var client = host.ClientFor("https://other.example.com");
        using var request = new HttpRequestMessage(HttpMethod.Get, UserInfoPath);
        request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", "placeholder");

        var response = await client.SendAsync(request, Cancellation);

        response.StatusCode.Should().Be(HttpStatusCode.NotFound);
    }

    // ── Two Authorization headers ─────────────────────────────────────────────────────────────
    //
    // TestRequest.WithHeader (the host-free harness) joins a repeated header into one comma-separated
    // string, which StringValues reports as a single value — it cannot reproduce two genuinely
    // separate Authorization header lines (StringValues.Count == 2), which is what RFC 9110 §11.6.2
    // and the endpoint's own Count > 1 check are about. Only a real request over the wire, built with
    // two calls to TryAddWithoutValidation, produces that.

    [Fact]
    public async Task Two_authorization_headers_are_invalid_request()
    {
        using var request = new HttpRequestMessage(HttpMethod.Get, UserInfoPath);
        request.Headers.TryAddWithoutValidation("Authorization", "Bearer placeholder");
        request.Headers.TryAddWithoutValidation("Authorization", "Bearer placeholder");

        var response = await host.Client.SendAsync(request, Cancellation);

        response.StatusCode.Should().Be(HttpStatusCode.BadRequest);
        Challenge(response).Should().Contain("error=\"invalid_request\"");
    }

    [Fact]
    public async Task Two_authorization_headers_are_invalid_request_whatever_scheme_they_name()
    {
        using var request = new HttpRequestMessage(HttpMethod.Get, UserInfoPath);
        request.Headers.TryAddWithoutValidation("Authorization", "Basic dXNlcjpwYXNz");
        request.Headers.TryAddWithoutValidation("Authorization", "Basic dXNlcjpwYXNz");

        var response = await host.Client.SendAsync(request, Cancellation);

        response.StatusCode.Should().Be(HttpStatusCode.BadRequest,
            "RFC 9110 §11.6.2 allows one Authorization header; two is malformed however they read");
        Challenge(response).Should().Contain("error=\"invalid_request\"");
    }

    // ── A real token pair ─────────────────────────────────────────────────────────────────────

    [Fact]
    public async Task The_id_token_issued_alongside_is_not_spendable_here()
    {
        // Refused on two independent counts — its typ is JWT, and its aud is the client rather
        // than this server. AccessTokenValidatorTests isolates each; this proves the refusal
        // reaches the wire for a real token pair, which only a genuine authorize-then-token
        // exchange produces. That exchange's interaction handoff rides on a cookie between the
        // authorize redirect and the login post, so it cannot move to the host-free harness.
        using var factory = new TestWebAppFactory(
            configureBuilder: builder => builder.AddInMemoryClients(clients => clients
                .Add(ClientRegistration.CreatePublic(App, [Redirect], [], ["openid", "profile"]) with { RequireConsent = false })),
            mapEndpoints: MapLoginPage);
        using var client = factory.CreateClient(new() { BaseAddress = new Uri(Issuer), AllowAutoRedirect = false, HandleCookies = true });

        var tokens = await ExchangeAsync(client, "openid profile");

        using var request = new HttpRequestMessage(HttpMethod.Get, UserInfoPath);
        request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", tokens.GetProperty("id_token").GetString());
        var response = await client.SendAsync(request, Cancellation);

        response.StatusCode.Should().Be(HttpStatusCode.Unauthorized);
    }

    // ── Discovery and mapping ─────────────────────────────────────────────────────────────────

    [Fact]
    public async Task Discovery_publishes_the_endpoint_this_host_actually_serves()
    {
        var document = await host.Client.GetFromJsonAsync<JsonElement>(
            "/.well-known/openid-configuration", Cancellation);

        document.GetProperty("userinfo_endpoint").GetString().Should().Be(Issuer + UserInfoPath);
    }

    [Fact]
    public async Task A_host_serving_no_code_grant_publishes_no_userinfo_endpoint_and_serves_none()
    {
        using var factory = new TestWebAppFactory(opts =>
        {
            // client_credentials needs a non-"none" method advertised; "none" stays for the
            // default public test client the factory registers.
            opts.GrantTypesSupported = [GrantType.ClientCredentials];
        });
        using var client = factory.CreateClient(new() { BaseAddress = new Uri(Issuer) });

        var document = await client.GetFromJsonAsync<JsonElement>("/.well-known/openid-configuration", Cancellation);
        var response = await client.GetAsync(UserInfoPath, Cancellation);

        document.TryGetProperty("userinfo_endpoint", out _).Should().BeFalse(
            "no grant here issues an access token for an end user");
        response.StatusCode.Should().Be(HttpStatusCode.NotFound, "the metadata and the route must never disagree");
    }

    [Fact]
    public async Task A_path_bearing_issuer_serves_userinfo_under_its_path()
    {
        var response = await tenant.Client.GetAsync("/tenant1" + UserInfoPath, Cancellation);

        response.StatusCode.Should().Be(HttpStatusCode.Unauthorized, "the route exists; it just got no token");
    }

    // ── Driving the flow ──────────────────────────────────────────────────────────────────────

    private static void MapLoginPage(IEndpointRouteBuilder endpoints) =>
        endpoints.MapPost(LoginPath, async (HttpContext context, ILoginInteraction login) =>
            await login.SignInAsync(
                new ClaimsPrincipal(new ClaimsIdentity([new Claim("sub", Subject)], "test")),
                AuthenticationMethods.Password));

    private static async Task<JsonElement> ExchangeAsync(HttpClient client, string scope)
    {
        var url = QueryHelpers.AddQueryString("/connect/authorize", new Dictionary<string, string?>
        {
            ["client_id"] = App,
            ["redirect_uri"] = Redirect,
            ["response_type"] = "code",
            ["scope"] = scope,
            ["nonce"] = "n-0S6_WzA2Mj",
            ["code_challenge"] = CodeChallenge,
            ["code_challenge_method"] = "S256",
        });

        var response = await client.GetAsync(url, Cancellation);
        response.StatusCode.Should().Be(HttpStatusCode.Redirect);

        if (response.Headers.Location!.OriginalString.StartsWith(LoginPath, StringComparison.Ordinal))
        {
            var location = response.Headers.Location!.OriginalString;
            var interactionId = QueryHelpers.ParseQuery(location[location.IndexOf('?')..])[InteractionHandoff.InteractionIdParameter].ToString();
            using var login = new FormUrlEncodedContent([]);
            response = await client.PostAsync(
                QueryHelpers.AddQueryString(LoginPath, InteractionHandoff.InteractionIdParameter, interactionId), login, Cancellation);
        }

        var code = response.ShouldHaveIssuedCodeTo(Redirect);

        using var form = new FormUrlEncodedContent(new Dictionary<string, string>
        {
            ["grant_type"] = "authorization_code",
            ["code"] = code,
            ["redirect_uri"] = Redirect,
            ["client_id"] = App,
            ["code_verifier"] = Verifier,
        });

        var tokens = await client.PostAsync(TokenPath, form, Cancellation);
        tokens.StatusCode.Should().Be(HttpStatusCode.OK, await tokens.Content.ReadAsStringAsync(Cancellation));

        return JsonDocument.Parse(await tokens.Content.ReadAsStringAsync(Cancellation)).RootElement.Clone();
    }

    private static string Challenge(HttpResponseMessage response) =>
        response.Headers.WwwAuthenticate.Should().ContainSingle().Subject.ToString();
}
