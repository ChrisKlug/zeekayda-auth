using System.Net;
using Microsoft.AspNetCore.WebUtilities;
using Microsoft.Extensions.DependencyInjection;
using ZeeKayDa.Auth.AspNetCore.Endpoints;
using ZeeKayDa.Auth.AspNetCore.Interaction;
using ZeeKayDa.Auth.Stores;

namespace ZeeKayDa.Auth.AspNetCore.Tests.Endpoints;

/// <summary>
/// Host-free tests for <c>/connect/authorize</c> request validation (#83): the two-phase error
/// model, invoked directly on the handler. The default test host registers the public client
/// <c>test-client</c> with redirect URI <c>https://test.example.com/callback</c> and allowed scope
/// <c>openid</c>. Whether the route is mapped at all, and whether a host-wide authorization
/// fallback policy is bypassed, need a real host and live in
/// <see cref="AuthorizationEndpointHostTests"/>.
/// </summary>
public sealed class AuthorizationEndpointTests
{
    private const string RegisteredRedirect = "https://test.example.com/callback";
    private const string Challenge = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM";

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

    private static Task<HttpResponseMessage> GetAsync(EndpointHost host, Dictionary<string, string?> query) =>
        host.InvokeAsync<AuthorizationEndpoint>(e => e.Handle, host.Get(AuthorizeUrl(query)));

    // ── Valid requests ────────────────────────────────────────────────────────────────────────

    [Fact]
    public async Task Valid_GET_request_passes_validation_and_hands_off_to_the_login_page()
    {
        using var host = new EndpointHost();

        using var response = await GetAsync(host, ValidQuery());

        response.StatusCode.Should().Be(HttpStatusCode.Redirect,
            "validation passed and no session exists, so the user is sent to the host's login page");
        response.Headers.Location!.OriginalString.Should().StartWith("/account/login?");
    }

    [Fact]
    public async Task Valid_POST_form_request_passes_validation()
    {
        using var host = new EndpointHost();
        var request = host.Post("/connect/authorize").WithForm(
            ValidQuery().Where(kv => kv.Value is not null).Select(kv => KeyValuePair.Create(kv.Key, kv.Value!)));

        using var response = await host.InvokeAsync<AuthorizationEndpoint>(e => e.Handle, request);

        response.StatusCode.Should().Be(HttpStatusCode.Redirect);
        response.Headers.Location!.OriginalString.Should().StartWith("/account/login?");
    }

    [Fact]
    public async Task POST_without_form_content_type_is_a_local_error()
    {
        var request = EndpointHost.Default.Post("/connect/authorize")
            .WithBody("""{"client_id":"test-client"}""", "application/json");

        using var response = await EndpointHost.Default.InvokeAsync<AuthorizationEndpoint>(e => e.Handle, request);

        response.StatusCode.Should().Be(HttpStatusCode.BadRequest);
    }

    // ── Phase 1: local errors ─────────────────────────────────────────────────────────────────

    [Theory]
    [InlineData("unknown-client", RegisteredRedirect)]
    [InlineData("test-client", "https://evil.example.com/callback")]
    public async Task Phase1_failures_render_a_local_400_and_never_redirect(string clientId, string redirectUri)
    {
        using var response = await GetAsync(EndpointHost.Default, ValidQuery(clientId, redirectUri));

        response.StatusCode.Should().Be(HttpStatusCode.BadRequest);
        response.Headers.Location.Should().BeNull("a phase-1 error must never redirect (open-redirect defence)");
        response.Content.Headers.ContentType!.MediaType.Should().Be("text/html");
    }

    [Fact]
    public async Task Phase1_error_page_never_echoes_request_values()
    {
        using var response = await GetAsync(
            EndpointHost.Default, ValidQuery(redirectUri: "https://evil.example.com/callback"));

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

        using var response = await GetAsync(EndpointHost.Default, query);

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

        using var response = await GetAsync(EndpointHost.Default, query);

        var parameters = QueryHelpers.ParseQuery(response.Headers.Location!.Query);
        parameters.Should().NotContainKey("state");
        parameters["error"].ToString().Should().Be("unsupported_response_type");
    }

    // ── Interaction context ───────────────────────────────────────────────────────────────────

    [Fact]
    public async Task Authorize_responses_are_never_cacheable()
    {
        using var host = new EndpointHost();

        using var response = await GetAsync(host, ValidQuery());

        response.Headers.CacheControl!.NoStore.Should().BeTrue();
    }

    [Fact]
    public async Task Valid_request_writes_a_binding_cookie_named_for_its_interaction()
    {
        using var host = new EndpointHost();

        using var response = await GetAsync(host, ValidQuery());

        var interactionId = InteractionIdFrom(response);
        response.Headers.GetValues("Set-Cookie").Should().Contain(c =>
            c.StartsWith(InteractionBindingCookie.NamePrefix + interactionId + "=") && c.Contains("httponly"));
    }

    [Fact]
    public async Task Binding_cookie_never_carries_request_values_in_the_clear()
    {
        using var host = new EndpointHost();
        var query = ValidQuery();
        query["state"] = "client-state-value";

        using var response = await GetAsync(host, query);

        var cookie = response.Headers.GetValues("Set-Cookie")
            .Single(c => c.StartsWith(InteractionBindingCookie.NamePrefix));
        cookie.Should().NotContain("client-state-value").And.NotContain(RegisteredRedirect);
    }

    [Fact]
    public async Task A_request_with_a_state_larger_than_any_header_could_carry_is_accepted()
    {
        // state is deliberately not length-capped; the store's cap is 16 KB by default, far above
        // the 3 KB the cookie transport could carry.
        using var host = new EndpointHost();
        var form = ValidQuery();
        form["state"] = new string('s', 10_000);
        var request = host.Post("/connect/authorize").WithForm(
            form.Where(kv => kv.Value is not null).Select(kv => KeyValuePair.Create(kv.Key, kv.Value!)));

        using var response = await host.InvokeAsync<AuthorizationEndpoint>(e => e.Handle, request);

        response.StatusCode.Should().Be(HttpStatusCode.Redirect);
        response.Headers.Location!.OriginalString.Should().StartWith("/account/login?");
    }

    [Fact]
    public async Task A_request_over_the_store_cap_renders_locally_and_stores_nothing()
    {
        // An authorize request needs no authentication and is stored for 30 minutes, so what one
        // may make the store hold is bounded. Rendered locally rather than redirected: echoing an
        // oversized state builds a Location the client's server may not accept.
        using var host = new EndpointHost();
        var form = ValidQuery();
        form["state"] = new string('s', 20_000);
        var request = host.Post("/connect/authorize").WithForm(
            form.Where(kv => kv.Value is not null).Select(kv => KeyValuePair.Create(kv.Key, kv.Value!)));

        using var response = await host.InvokeAsync<AuthorizationEndpoint>(e => e.Handle, request);

        response.StatusCode.Should().Be(HttpStatusCode.BadRequest);
        response.Headers.Location.Should().BeNull();
        response.Headers.TryGetValues("Set-Cookie", out var cookies);
        (cookies ?? []).Should().NotContain(c => c.StartsWith(InteractionBindingCookie.NamePrefix), "nothing was stored, so nothing is bound");
    }

    [Fact]
    public async Task A_failed_request_leaves_an_interaction_in_flight_in_another_tab_alone()
    {
        // Concurrent tabs share nothing: a request that fails validation never wrote an
        // interaction of its own, and must not end the one another tab is completing.
        using var host = new EndpointHost();
        using var first = await GetAsync(host, ValidQuery());
        var firstInteraction = InteractionIdFrom(first);
        var query = ValidQuery();
        query["response_type"] = "token";

        using var failed = await GetAsync(host, query);

        failed.Headers.TryGetValues("Set-Cookie", out var cookies);
        (cookies ?? []).Should().NotContain(c => c.StartsWith(InteractionBindingCookie.NamePrefix + firstInteraction + "="));
    }

    [Fact]
    public async Task A_request_refused_after_it_was_stored_leaves_no_entry_behind()
    {
        // prompt=none with no session is accepted, stored, and then refused in the same request.
        // The browser never saw the binding cookie, so the request itself must still be able to
        // remove what it wrote — otherwise every such request would cost the store an entry for
        // 30 minutes.
        var interactions = new InMemoryInteractionBackingStore(TimeProvider.System);
        using var host = new EndpointHost(configureBuilder: builder =>
        {
            builder.AddInMemoryAuthorizationCodeStore(allowOutsideDevelopment: true)
                .AddInMemoryRefreshTokenStore(allowOutsideDevelopment: true);
            builder.Services.AddSingleton<IInteractionBackingStore>(interactions);
        });
        var query = ValidQuery();
        query["prompt"] = "none";

        using var response = await GetAsync(host, query);

        response.StatusCode.Should().Be(HttpStatusCode.Redirect);
        response.Headers.Location!.OriginalString.Should().Contain("error=login_required");
        interactions.Count.Should().Be(0, "the refused request removed the entry it had just stored");
    }

    /// <summary>The interaction identifier the framework put on a redirect to a host page.</summary>
    private static string InteractionIdFrom(HttpResponseMessage response)
    {
        var location = response.Headers.Location!.OriginalString;
        return QueryHelpers.ParseQuery(location[location.IndexOf('?')..])[InteractionHandoff.InteractionIdParameter]!;
    }

    // ── ErrorPath handoff ─────────────────────────────────────────────────────────────────────

    [Fact]
    public async Task Phase1_failure_with_configured_ErrorPath_redirects_with_an_opaque_id_only()
    {
        using var host = new EndpointHost(opts =>
            opts.AuthorizationEndpoint.Interaction.ErrorPath = "/auth-error");

        using var response = await GetAsync(host, ValidQuery(clientId: "unknown-client"));

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
