using System.Net;
using System.Text.Encodings.Web;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.WebUtilities;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using ZeeKayDa.Auth.AspNetCore.Interaction;
using static ZeeKayDa.Auth.AspNetCore.Tests.Providers.ProviderTestHost;

namespace ZeeKayDa.Auth.AspNetCore.Tests.Providers;

/// <summary>
/// The external round trip: the challenge the login page starts, the provider's callback served
/// by the framework, and the return through <c>/connect/resume</c> that promotes the provider's
/// principal into the SSO session — with every way a stray, replayed or failed callback is kept
/// from completing or cancelling a live authorization request.
/// </summary>
public sealed class ProviderRoundTripTests
{
    private static CancellationToken Cancellation => TestContext.Current.CancellationToken;

    private static TestWebAppFactory NewFactory(
        Action<AuthorizationServerOptions>? configureOptions = null,
        Action<ZeeKayDaAuthBuilder>? configureBuilder = null) =>
        new(
            configureOptions,
            configureBuilder ?? (builder => builder.WithProviders(auth => auth.AddOAuth("acme", "Acme", ConfigureAcme))),
            MapHostPages);

    /// <summary>Authorize, land on the login page, pick a provider: the challenge response.</summary>
    private static async Task<(string InteractionId, HttpResponseMessage Challenge)> ChallengeAsync(
        HttpClient client,
        string provider = "acme",
        string? state = null)
    {
        var handoff = await client.GetAsync(AuthorizeUrl(state), Cancellation);
        var interactionId = InteractionIdFrom(handoff);
        var challenge = await client.PostAsync(WithInteractionId(LoginPath, interactionId), Form(("provider", provider)), Cancellation);

        return (interactionId, challenge);
    }

    /// <summary>The callback the provider would send the browser to, carrying the challenge's state.</summary>
    private static string CallbackUrlOf(HttpResponseMessage challenge, string provider = "acme", string? error = null)
    {
        var query = new Dictionary<string, string?> { ["state"] = RedirectQueryOf(challenge)["state"].ToString() };
        if (error is null)
            query["code"] = "acme-code";
        else
            query["error"] = error;

        return QueryHelpers.AddQueryString($"/connect/callback/{provider}", query);
    }

    /// <summary>Challenge, callback, and the return through resume: the resume response.</summary>
    private static async Task<HttpResponseMessage> RoundTripAsync(HttpClient client, string provider = "acme")
    {
        var (_, challenge) = await ChallengeAsync(client, provider);
        var callback = await client.GetAsync(CallbackUrlOf(challenge, provider), Cancellation);

        return await client.GetAsync(callback.Headers.Location!.OriginalString, Cancellation);
    }

    private static async Task<System.Text.Json.JsonElement?> ReadSessionAsync(HttpClient client)
    {
        var response = await client.GetAsync("/test/session", Cancellation);
        if (response.StatusCode == HttpStatusCode.NotFound)
            return null;

        var body = await response.Content.ReadAsStringAsync(Cancellation);
        return System.Text.Json.JsonDocument.Parse(body).RootElement.Clone();
    }

    private static string CorrelationCookieOf(HttpResponseMessage challenge) => challenge.Headers
        .GetValues("Set-Cookie")
        .Single(cookie => cookie.StartsWith(".AspNetCore.Correlation.", StringComparison.Ordinal))
        .Split(';')[0];

    // ── The challenge ─────────────────────────────────────────────────────────────────────────

    [Fact]
    public async Task The_challenge_sends_the_user_to_the_provider_with_the_pinned_callback()
    {
        using var factory = NewFactory();
        using var client = NewClient(factory);

        var (_, challenge) = await ChallengeAsync(client);

        challenge.StatusCode.Should().Be(HttpStatusCode.Redirect);
        DestinationOf(challenge).Should().Be("https://acme.example.net/authorize");
        RedirectQueryOf(challenge)["redirect_uri"].ToString().Should().Be("https://test.example.com/connect/callback/acme");
    }

    [Fact]
    public async Task A_single_provider_with_no_login_page_and_local_sign_in_off_is_challenged_directly()
    {
        using var factory = NewFactory(configureOptions: options =>
        {
            options.AuthorizationEndpoint.Interaction.LoginPath = null;
            options.AuthorizationEndpoint.Interaction.SupportsLocalSignIn = false;
        });
        using var client = NewClient(factory);

        var response = await client.GetAsync(AuthorizeUrl(), Cancellation);

        response.StatusCode.Should().Be(HttpStatusCode.Redirect, "the framework can choose, so no page of the host's is shown");
        DestinationOf(response).Should().Be("https://acme.example.net/authorize");
    }

    [Fact]
    public async Task ChallengeAsync_with_a_provider_that_is_not_registered_is_refused()
    {
        using var factory = NewFactory();
        using var client = NewClient(factory);

        var challenge = async () => await ChallengeAsync(client, provider: "not-registered");

        await challenge.Should().ThrowAsync<ZeeKayDaInteractionException>();
    }

    [Fact]
    public async Task ChallengeAsync_without_an_interaction_id_is_refused()
    {
        using var factory = NewFactory();
        using var client = NewClient(factory);
        await client.GetAsync(AuthorizeUrl(), Cancellation);

        var challenge = async () => await client.PostAsync(LoginPath, Form(("provider", "acme")), Cancellation);

        await challenge.Should().ThrowAsync<ZeeKayDaInteractionException>();
    }

    // ── The callback and the return ───────────────────────────────────────────────────────────

    [Fact]
    public async Task The_provider_callback_signs_in_and_returns_through_resume_carrying_the_interaction_id()
    {
        using var factory = NewFactory();
        using var client = NewClient(factory);
        var (interactionId, challenge) = await ChallengeAsync(client);

        var callback = await client.GetAsync(CallbackUrlOf(challenge), Cancellation);

        callback.StatusCode.Should().Be(HttpStatusCode.Redirect);
        callback.Headers.Location!.OriginalString.Should().Be($"/connect/resume?zkd_i={interactionId}");
        callback.Headers.GetValues("Set-Cookie").Should().Contain(cookie => cookie.StartsWith("zkd.external="));
    }

    [Fact]
    public async Task Resume_promotes_the_provider_principal_into_the_session_under_a_derived_subject()
    {
        using var factory = NewFactory();
        using var client = NewClient(factory);

        var resume = await RoundTripAsync(client);

        resume.StatusCode.Should().Be(HttpStatusCode.NotImplemented, "consent and code issuance are not built");
        var session = (await ReadSessionAsync(client))!.Value;
        session.GetProperty("sub").GetString().Should().Be(ExternalSubject.Derive("acme", "acme", UpstreamSubject),
            "the upstream subject is never used verbatim");
        session.GetProperty("name").GetString().Should().Be("Upstream User", "the provider's other claims are kept");
        session.GetProperty("sid").GetString().Should().NotBeNullOrEmpty();
        session.GetProperty("amr").GetArrayLength().Should().Be(0, "the framework was told nothing about how the user authenticated");
    }

    [Fact]
    public async Task Resume_consumes_the_external_ticket()
    {
        using var factory = NewFactory();
        using var client = NewClient(factory);
        var (_, challenge) = await ChallengeAsync(client);
        var callback = await client.GetAsync(CallbackUrlOf(challenge), Cancellation);

        var resume = await client.GetAsync(callback.Headers.Location!.OriginalString, Cancellation);

        resume.Headers.GetValues("Set-Cookie").Should().Contain(cookie =>
            cookie.StartsWith("zkd.external=") && cookie.Contains("expires=Thu, 01 Jan 1970"));
    }

    [Fact]
    public async Task Two_providers_returning_the_same_upstream_subject_get_different_session_subjects()
    {
        using var factory = NewFactory(configureBuilder: builder => builder.WithProviders(auth =>
        {
            auth.AddOAuth("acme", ConfigureAcme);
            auth.AddOAuth("globex", ConfigureAcme);
        }));
        using var throughAcme = NewClient(factory);
        using var throughGlobex = NewClient(factory);

        await RoundTripAsync(throughAcme, "acme");
        await RoundTripAsync(throughGlobex, "globex");

        var acmeSubject = (await ReadSessionAsync(throughAcme))!.Value.GetProperty("sub").GetString();
        var globexSubject = (await ReadSessionAsync(throughGlobex))!.Value.GetProperty("sub").GetString();
        acmeSubject.Should().NotBe(globexSubject);
    }

    [Fact]
    public async Task The_round_trip_completes_under_a_path_based_issuer()
    {
        using var factory = NewFactory(configureOptions: options => options.Issuer = "https://test.example.com/id");
        using var client = NewClient(factory);
        var handoff = await client.GetAsync("/id" + AuthorizeUrl(), Cancellation);
        var interactionId = InteractionIdFrom(handoff);
        var challenge = await client.PostAsync(WithInteractionId(LoginPath, interactionId), Form(("provider", "acme")), Cancellation);

        RedirectQueryOf(challenge)["redirect_uri"].ToString().Should().Be("https://test.example.com/id/connect/callback/acme");
        var callbackUrl = CallbackUrlOf(challenge).Replace("/connect/callback/acme", "/id/connect/callback/acme", StringComparison.Ordinal);
        var callback = await client.GetAsync(callbackUrl, Cancellation);

        callback.Headers.Location!.OriginalString.Should().Be($"/id/connect/resume?zkd_i={interactionId}");
        var resume = await client.GetAsync(callback.Headers.Location.OriginalString, Cancellation);
        resume.StatusCode.Should().Be(HttpStatusCode.NotImplemented);
    }

    // ── Refusal at the provider ───────────────────────────────────────────────────────────────

    [Fact]
    public async Task A_refusal_by_the_user_at_the_provider_reaches_the_client_as_access_denied()
    {
        using var factory = NewFactory();
        using var client = NewClient(factory);
        var (_, challenge) = await ChallengeAsync(client, state: "client-state");

        var callback = await client.GetAsync(CallbackUrlOf(challenge, error: "access_denied"), Cancellation);

        callback.StatusCode.Should().Be(HttpStatusCode.Redirect);
        DestinationOf(callback).Should().Be(RegisteredRedirect);
        var query = RedirectQueryOf(callback);
        query["error"].ToString().Should().Be("access_denied");
        query["error_description"].ToString().Should().Contain("declined");
        query["state"].ToString().Should().Be("client-state");
        query["iss"].ToString().Should().Be("https://test.example.com");
    }

    [Fact]
    public async Task A_refusal_at_the_provider_discards_the_interaction()
    {
        using var factory = NewFactory();
        using var client = NewClient(factory);
        var (interactionId, challenge) = await ChallengeAsync(client);
        await client.GetAsync(CallbackUrlOf(challenge, error: "access_denied"), Cancellation);

        var signIn = async () => await client.PostAsync(WithInteractionId(LoginPath, interactionId), Form(("sub", "user-1")), Cancellation);

        await signIn.Should().ThrowAsync<ZeeKayDaInteractionException>("a refused request cannot be picked back up");
    }

    [Fact]
    public async Task A_refusal_without_the_interaction_cookie_renders_locally_and_reaches_no_client()
    {
        // The correlation cookie alone, as a form_post callback — a cross-site POST the Lax
        // interaction cookie does not accompany — would carry it.
        using var factory = NewFactory();
        using var browser = NewClient(factory);
        var (_, challenge) = await ChallengeAsync(browser);
        using var crossSite = factory.CreateClient(new() { BaseAddress = new Uri("https://test.example.com"), AllowAutoRedirect = false, HandleCookies = false });
        using var request = new HttpRequestMessage(HttpMethod.Get, CallbackUrlOf(challenge, error: "access_denied"));
        request.Headers.Add("Cookie", CorrelationCookieOf(challenge));

        var callback = await crossSite.SendAsync(request, Cancellation);

        callback.StatusCode.Should().Be(HttpStatusCode.BadRequest);
        (await callback.Content.ReadAsStringAsync(Cancellation)).Should().Contain("access_denied");
    }

    // ── Every other failure renders locally and leaves the interaction alive ──────────────────

    [Fact]
    public async Task A_provider_outage_renders_locally_and_the_user_can_still_sign_in()
    {
        using var factory = NewFactory(configureBuilder: builder =>
            builder.WithProviders(auth => auth.AddOAuth("broken", ConfigureBroken)));
        using var client = NewClient(factory);
        var (interactionId, challenge) = await ChallengeAsync(client, "broken");

        var callback = await client.GetAsync(CallbackUrlOf(challenge, "broken"), Cancellation);

        callback.StatusCode.Should().Be(HttpStatusCode.BadRequest);
        (await callback.Content.ReadAsStringAsync(Cancellation)).Should().Contain("server_error").And.NotContain("upstream outage");
        var signIn = await client.PostAsync(WithInteractionId(LoginPath, interactionId), Form(("sub", "user-1")), Cancellation);
        signIn.StatusCode.Should().Be(HttpStatusCode.NotImplemented, "the interaction survived the failed callback");
    }

    [Fact]
    public async Task A_replayed_callback_neither_completes_nor_cancels_the_live_request()
    {
        using var factory = NewFactory();
        using var client = NewClient(factory);
        var (_, challenge) = await ChallengeAsync(client);
        var callback = await client.GetAsync(CallbackUrlOf(challenge), Cancellation);

        var replay = await client.GetAsync(CallbackUrlOf(challenge), Cancellation);

        replay.StatusCode.Should().Be(HttpStatusCode.BadRequest, "the correlation cookie was consumed by the first callback");
        var resume = await client.GetAsync(callback.Headers.Location!.OriginalString, Cancellation);
        resume.StatusCode.Should().Be(HttpStatusCode.NotImplemented, "the first callback's return still completes");
    }

    [Fact]
    public async Task A_callback_with_no_correlation_cookie_renders_locally()
    {
        using var factory = NewFactory();
        using var browser = NewClient(factory);
        var (_, challenge) = await ChallengeAsync(browser);
        using var stranger = factory.CreateClient(new() { BaseAddress = new Uri("https://test.example.com"), AllowAutoRedirect = false, HandleCookies = false });

        var callback = await stranger.GetAsync(CallbackUrlOf(challenge), Cancellation);

        callback.StatusCode.Should().Be(HttpStatusCode.BadRequest);
        callback.Headers.Location.Should().BeNull("nothing reaches the client from a callback that failed");
    }

    // ── The callback endpoint's own outcomes ──────────────────────────────────────────────────

    [Fact]
    public async Task A_handler_that_fails_to_initialise_renders_locally_and_leaves_the_interaction_alive()
    {
        using var factory = NewFactory(configureBuilder: builder => builder.WithProviders(auth =>
            AddHandWritten(auth, options => options.ThrowOnInitialize = true)));
        using var client = NewClient(factory);
        var handoff = await client.GetAsync(AuthorizeUrl(), Cancellation);
        var interactionId = InteractionIdFrom(handoff);

        // The challenge activates the handler too, so the callback is reached directly here.
        var callback = await client.GetAsync("/connect/callback/hand?state=anything", Cancellation);

        callback.StatusCode.Should().Be(HttpStatusCode.BadRequest);
        (await callback.Content.ReadAsStringAsync(Cancellation)).Should().Contain("server_error").And.NotContain("secret-value");
        var signIn = await client.PostAsync(WithInteractionId(LoginPath, interactionId), Form(("sub", "user-1")), Cancellation);
        signIn.StatusCode.Should().Be(HttpStatusCode.NotImplemented);
    }

    [Fact]
    public async Task A_handler_that_declines_its_own_callback_answers_404()
    {
        using var factory = NewFactory(configureBuilder: builder => builder.WithProviders(auth =>
            AddHandWritten(auth, options => options.DeclineCallback = true)));
        using var client = NewClient(factory);
        var (_, challenge) = await ChallengeAsync(client, "hand");

        var callback = await client.GetAsync(CallbackUrlOf(challenge, "hand"), Cancellation);

        callback.StatusCode.Should().Be(HttpStatusCode.NotFound);
        (await callback.Content.ReadAsStringAsync(Cancellation)).Should().BeEmpty();
    }

    [Fact]
    public async Task A_handler_that_does_not_handle_requests_answers_404_at_its_callback()
    {
        using var factory = NewFactory(configureBuilder: builder => builder.WithProviders(auth =>
            auth.AddScheme<AuthenticationSchemeOptions, PlainHandler>("plain", "Plain", _ => { })));
        using var client = NewClient(factory);

        var callback = await client.GetAsync("/connect/callback/plain", Cancellation);

        callback.StatusCode.Should().Be(HttpStatusCode.NotFound);
    }

    [Fact]
    public async Task The_callback_and_resume_routes_stay_anonymous_under_a_host_fallback_policy()
    {
        using var factory = new TestWebAppFactoryWithFallbackAuthorizationPolicy(
            builder => builder.WithProviders(auth => auth.AddOAuth("acme", ConfigureAcme)));
        using var client = factory.CreateClient(new() { BaseAddress = new Uri("https://test.example.com"), AllowAutoRedirect = false });

        var canary = await client.GetAsync("/host-route", Cancellation);
        var callback = await client.GetAsync("/connect/callback/acme", Cancellation);
        var resume = await client.GetAsync("/connect/resume", Cancellation);

        canary.StatusCode.Should().Be(HttpStatusCode.Unauthorized, "the fallback policy is in force");
        callback.StatusCode.Should().Be(HttpStatusCode.BadRequest, "the handler failed the callback rather than the policy refusing it");
        resume.StatusCode.Should().Be(HttpStatusCode.BadRequest);
    }

    [Fact]
    public async Task A_host_with_no_providers_serves_no_resume_route()
    {
        using var factory = new TestWebAppFactory(mapEndpoints: MapHostPages);
        using var client = NewClient(factory);

        var resume = await client.GetAsync("/connect/resume", Cancellation);

        resume.StatusCode.Should().Be(HttpStatusCode.NotFound);
    }

    // ── A handler outside the remote base class ───────────────────────────────────────────────

    [Fact]
    public async Task A_hand_written_handler_completes_the_round_trip()
    {
        using var factory = NewFactory(configureBuilder: builder => builder.WithProviders(auth =>
            AddHandWritten(auth)));
        using var client = NewClient(factory);

        var resume = await RoundTripAsync(client, "hand");

        resume.StatusCode.Should().Be(HttpStatusCode.NotImplemented);
        (await ReadSessionAsync(client))!.Value.GetProperty("sub").GetString()
            .Should().Be(ExternalSubject.Derive("hand", HandWrittenIssuer, HandWrittenSubject));
    }

    [Fact]
    public async Task A_hand_written_handler_that_drops_its_properties_is_refused_at_resume()
    {
        using var factory = NewFactory(configureBuilder: builder => builder.WithProviders(auth =>
            AddHandWritten(auth, options => options.DropProperties = true)));
        using var client = NewClient(factory);

        var resume = await RoundTripAsync(client, "hand");

        resume.StatusCode.Should().Be(HttpStatusCode.BadRequest, "the ticket names no interaction");
        (await ReadSessionAsync(client)).Should().BeNull();
    }

    [Fact]
    public async Task A_handler_that_stamps_another_scheme_into_its_ticket_is_refused_at_resume()
    {
        // The provider is what the callback route recorded; what the handler stamped is only a
        // cross-check, and a handler contradicting the route cannot pass as another provider.
        using var factory = NewFactory(configureBuilder: builder => builder.WithProviders(auth =>
            AddHandWritten(auth, options => options.StampAnotherScheme = true)));
        using var client = NewClient(factory);

        var resume = await RoundTripAsync(client, "hand");

        resume.StatusCode.Should().Be(HttpStatusCode.BadRequest);
        (await ReadSessionAsync(client)).Should().BeNull();
    }

    [Fact]
    public async Task A_handler_the_container_does_not_know_is_activated_by_constructor_injection()
    {
        using var factory = NewFactory(configureBuilder: builder => builder.WithProviders(auth =>
            AddHandWritten(auth, registerHandler: false)));
        using var client = NewClient(factory);

        var resume = await RoundTripAsync(client, "hand");

        resume.StatusCode.Should().Be(HttpStatusCode.NotImplemented);
    }

    [Fact]
    public async Task A_subject_claim_without_an_issuer_is_refused_at_promotion()
    {
        using var factory = NewFactory(configureBuilder: builder => builder.WithProviders(auth =>
            AddHandWritten(auth, options => options.SubjectWithoutIssuer = true)));
        using var client = NewClient(factory);

        var resume = await RoundTripAsync(client, "hand");

        resume.StatusCode.Should().Be(HttpStatusCode.BadRequest, "a handler bug renders locally, like a callback failure");
        (await resume.Content.ReadAsStringAsync(Cancellation)).Should().Contain("server_error");
        (await ReadSessionAsync(client)).Should().BeNull();
    }

    [Fact]
    public async Task A_handler_that_signs_in_and_then_fails_leaves_no_ticket_to_resume()
    {
        using var factory = NewFactory(configureBuilder: builder => builder.WithProviders(auth =>
            AddHandWritten(auth, options => options.ThrowAfterSignIn = true)));
        using var client = NewClient(factory);
        var (interactionId, challenge) = await ChallengeAsync(client, "hand");

        var callback = await client.GetAsync(CallbackUrlOf(challenge, "hand"), Cancellation);

        callback.StatusCode.Should().Be(HttpStatusCode.BadRequest);
        var resume = await client.GetAsync(WithInteractionId("/connect/resume", interactionId), Cancellation);
        resume.StatusCode.Should().Be(HttpStatusCode.BadRequest, "the ticket the handler wrote was discarded with the failure");
        (await ReadSessionAsync(client)).Should().BeNull();
    }

    [Fact]
    public async Task A_callback_carried_to_another_providers_route_is_refused_at_resume()
    {
        // Two custom handlers sharing a state format: the state the first was challenged with
        // unprotects at the second's route. The route records the second provider, the challenge
        // named the first, and resume refuses the mismatch.
        using var factory = NewFactory(configureBuilder: builder => builder.WithProviders(auth =>
        {
            AddHandWritten(auth, name: "hand");
            AddHandWritten(auth, name: "hand2");
        }));
        using var client = NewClient(factory);
        var (_, challenge) = await ChallengeAsync(client, "hand");

        var callback = await client.GetAsync(CallbackUrlOf(challenge, "hand2"), Cancellation);
        var resume = await client.GetAsync(callback.Headers.Location!.OriginalString, Cancellation);

        resume.StatusCode.Should().Be(HttpStatusCode.BadRequest);
        (await ReadSessionAsync(client)).Should().BeNull();
    }

    // ── Resume refusals ───────────────────────────────────────────────────────────────────────

    [Fact]
    public async Task Resume_naming_an_interaction_the_ticket_was_not_issued_for_is_refused()
    {
        using var factory = NewFactory();
        using var client = NewClient(factory);
        var (_, challenge) = await ChallengeAsync(client);
        await client.GetAsync(CallbackUrlOf(challenge), Cancellation);

        var resume = await client.GetAsync(WithInteractionId("/connect/resume", "another-interaction"), Cancellation);

        resume.StatusCode.Should().Be(HttpStatusCode.BadRequest);
        (await ReadSessionAsync(client)).Should().BeNull();
    }

    [Fact]
    public async Task Resume_after_the_interaction_was_replaced_by_another_tab_is_refused()
    {
        using var factory = NewFactory();
        using var client = NewClient(factory);
        var (_, challenge) = await ChallengeAsync(client);
        var callback = await client.GetAsync(CallbackUrlOf(challenge), Cancellation);
        await client.GetAsync(AuthorizeUrl(), Cancellation);

        var resume = await client.GetAsync(callback.Headers.Location!.OriginalString, Cancellation);

        resume.StatusCode.Should().Be(HttpStatusCode.BadRequest, "the browser now carries a different interaction");
        (await ReadSessionAsync(client)).Should().BeNull();
    }

    [Fact]
    public async Task Resume_without_an_external_ticket_is_refused()
    {
        using var factory = NewFactory();
        using var client = NewClient(factory);
        var handoff = await client.GetAsync(AuthorizeUrl(), Cancellation);

        var resume = await client.GetAsync(WithInteractionId("/connect/resume", InteractionIdFrom(handoff)), Cancellation);

        resume.StatusCode.Should().Be(HttpStatusCode.BadRequest);
    }

    [Fact]
    public async Task A_host_page_cannot_sign_into_the_external_scheme()
    {
        using var factory = NewFactory();
        using var client = NewClient(factory);

        var signIn = async () => await client.GetAsync("/test/sign-in-external", Cancellation);

        await signIn.Should().ThrowAsync<InvalidOperationException>().WithMessage("*callback endpoint*");
    }

    /// <summary>A handler outside the request-handler contract: nothing to serve at its callback.</summary>
    private sealed class PlainHandler(
        IOptionsMonitor<AuthenticationSchemeOptions> options,
        ILoggerFactory logger,
        UrlEncoder encoder)
        : AuthenticationHandler<AuthenticationSchemeOptions>(options, logger, encoder)
    {
        protected override Task<AuthenticateResult> HandleAuthenticateAsync()
            => Task.FromResult(AuthenticateResult.NoResult());
    }
}
