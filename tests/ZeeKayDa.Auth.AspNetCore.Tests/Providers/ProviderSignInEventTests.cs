using System.Net;
using Microsoft.AspNetCore.WebUtilities;
using Microsoft.Extensions.DependencyInjection;
using ZeeKayDa.Auth.AspNetCore.Interaction;
using static ZeeKayDa.Auth.AspNetCore.Tests.Providers.ProviderTestHost;

namespace ZeeKayDa.Auth.AspNetCore.Tests.Providers;

/// <summary>
/// The host's say in an external sign-in: <c>OnProviderSignIn</c> at <c>/connect/resume</c>, the
/// parked principal a redirect leaves behind, and the page that reads it back and finishes.
/// </summary>
public sealed class ProviderSignInEventTests
{
    private static CancellationToken Cancellation => TestContext.Current.CancellationToken;

    private static TestWebAppFactory NewFactory(Func<ProviderSignInContext, Task>? onProviderSignIn) =>
        new(
            configureBuilder: builder => builder.WithProviders(
                auth => auth.AddOAuth("acme", "Acme", ConfigureAcme),
                options => options.OnProviderSignIn = onProviderSignIn),
            mapEndpoints: MapHostPages);

    /// <summary>Authorize, pick the provider, complete the callback, and return through resume.</summary>
    private static async Task<(string InteractionId, HttpResponseMessage Resume)> ResumeAsync(HttpClient client)
    {
        var handoff = await client.GetAsync(AuthorizeUrl(), Cancellation);
        var interactionId = InteractionIdFrom(handoff);
        var challenge = await client.PostAsync(WithInteractionId(LoginPath, interactionId), Form(("provider", "acme")), Cancellation);
        var callbackUrl = QueryHelpers.AddQueryString("/connect/callback/acme", new Dictionary<string, string?>
        {
            ["code"] = "acme-code",
            ["state"] = RedirectQueryOf(challenge)["state"].ToString(),
        });
        var callback = await client.GetAsync(callbackUrl, Cancellation);

        return (interactionId, await client.GetAsync(callback.Headers.Location!.OriginalString, Cancellation));
    }

    private static async Task<System.Text.Json.JsonElement?> ReadJsonAsync(HttpClient client, string url)
    {
        var response = await client.GetAsync(url, Cancellation);
        if (response.StatusCode == HttpStatusCode.NotFound)
            return null;

        var body = await response.Content.ReadAsStringAsync(Cancellation);
        return System.Text.Json.JsonDocument.Parse(body).RootElement.Clone();
    }

    // ── What the handler sees ─────────────────────────────────────────────────────────────────

    [Fact]
    public async Task The_handler_sees_the_provider_principal_the_provider_the_client_and_the_effective_scopes()
    {
        ProviderSignInContext? seen = null;
        using var factory = NewFactory(context =>
        {
            seen = context;
            return Task.CompletedTask;
        });
        using var client = NewClient(factory);

        await ResumeAsync(client);

        seen.Should().NotBeNull();
        seen!.Principal.FindFirst("sub")!.Value.Should().Be(UpstreamSubject);
        seen.Principal.Claims.Should().NotContain(claim => claim.Type.StartsWith("zkd:"));
        seen.Provider.Id.Should().Be("acme");
        seen.Provider.DisplayName.Should().Be("Acme");
        seen.Client.ClientId.Should().Be("test-client");
        seen.EffectiveScopes.Should().Equal("openid");
    }

    [Fact]
    public async Task A_handler_that_calls_neither_terminal_method_lets_the_framework_promote()
    {
        using var factory = NewFactory(_ => Task.CompletedTask);
        using var client = NewClient(factory);

        var (_, resume) = await ResumeAsync(client);

        resume.StatusCode.Should().Be(HttpStatusCode.NotImplemented);
        (await ReadJsonAsync(client, "/test/session")).Should().NotBeNull();
    }

    // ── RedirectToAsync and the parked principal ──────────────────────────────────────────────

    [Fact]
    public async Task RedirectToAsync_parks_the_principal_and_sends_the_user_to_the_host_page_with_the_interaction_id()
    {
        using var factory = NewFactory(context => context.RedirectToAsync(CollectMorePath));
        using var client = NewClient(factory);

        var (interactionId, resume) = await ResumeAsync(client);

        resume.StatusCode.Should().Be(HttpStatusCode.Redirect);
        resume.Headers.Location!.OriginalString.Should().Be($"{CollectMorePath}?zkd_i={interactionId}");
        resume.Headers.GetValues("Set-Cookie").Should().Contain(cookie => cookie.StartsWith("zkd.pending="));
        (await ReadJsonAsync(client, "/test/session")).Should().BeNull("nothing is promoted until the page signs in");
    }

    [Fact]
    public async Task The_host_page_reads_the_parked_principal_back_without_the_framework_claims()
    {
        using var factory = NewFactory(context => context.RedirectToAsync(CollectMorePath));
        using var client = NewClient(factory);
        var (_, resume) = await ResumeAsync(client);

        var pending = (await ReadJsonAsync(client, resume.Headers.Location!.OriginalString))!.Value;

        pending.GetProperty("sub").GetString().Should().Be(UpstreamSubject);
        pending.GetProperty("provider").GetString().Should().Be("acme");
        pending.GetProperty("reservedClaims").GetInt32().Should().Be(0);
    }

    [Fact]
    public async Task SignInAsync_on_the_host_page_promotes_its_own_principal_and_consumes_the_parked_one()
    {
        using var factory = NewFactory(context => context.RedirectToAsync(CollectMorePath));
        using var client = NewClient(factory);
        var (_, resume) = await ResumeAsync(client);
        var collectMore = resume.Headers.Location!.OriginalString;

        var signIn = await client.PostAsync(collectMore, Form(), Cancellation);

        signIn.StatusCode.Should().Be(HttpStatusCode.NotImplemented);
        (await ReadJsonAsync(client, "/test/session"))!.Value.GetProperty("sub").GetString().Should().Be("mapped-" + UpstreamSubject);
        signIn.Headers.GetValues("Set-Cookie").Should().Contain(cookie =>
            cookie.StartsWith("zkd.pending=") && cookie.Contains("expires=Thu, 01 Jan 1970"));
        (await ReadJsonAsync(client, collectMore)).Should().BeNull("the parked principal is single-use");
    }

    [Fact]
    public async Task A_parked_principal_bound_to_another_interaction_is_refused()
    {
        using var factory = NewFactory(context => context.RedirectToAsync(CollectMorePath));
        using var client = NewClient(factory);
        await ResumeAsync(client);
        var secondTab = await client.GetAsync(AuthorizeUrl(), Cancellation);

        var pending = await ReadJsonAsync(client, WithInteractionId(CollectMorePath, InteractionIdFrom(secondTab)));

        pending.Should().BeNull();
    }

    [Fact]
    public async Task GetPendingPrincipalAsync_without_an_interaction_id_is_refused()
    {
        using var factory = NewFactory(context => context.RedirectToAsync(CollectMorePath));
        using var client = NewClient(factory);
        await ResumeAsync(client);

        var read = async () => await client.GetAsync(CollectMorePath, Cancellation);

        await read.Should().ThrowAsync<ZeeKayDaInteractionException>();
    }

    [Fact]
    public async Task Cancelling_at_the_host_page_discards_the_parked_principal()
    {
        using var factory = NewFactory(context => context.RedirectToAsync(CollectMorePath));
        using var client = NewClient(factory);
        var (interactionId, resume) = await ResumeAsync(client);

        var cancel = await client.PostAsync(WithInteractionId("/account/login/cancel", interactionId), Form(), Cancellation);

        cancel.StatusCode.Should().Be(HttpStatusCode.Redirect);
        cancel.Headers.GetValues("Set-Cookie").Should().Contain(cookie =>
            cookie.StartsWith("zkd.pending=") && cookie.Contains("expires=Thu, 01 Jan 1970"));
    }

    [Fact]
    public async Task RedirectToAsync_refuses_a_path_outside_the_host()
    {
        using var factory = NewFactory(context => context.RedirectToAsync("//attacker.example.net/collect"));
        using var client = NewClient(factory);

        var resume = async () => await ResumeAsync(client);

        await resume.Should().ThrowAsync<ArgumentException>();
    }

    [Fact]
    public async Task Calling_a_second_terminal_method_fails()
    {
        using var factory = NewFactory(async context =>
        {
            await context.RedirectToAsync(CollectMorePath);
            await context.DenyAsync();
        });
        using var client = NewClient(factory);

        var resume = async () => await ResumeAsync(client);

        await resume.Should().ThrowAsync<InvalidOperationException>();
    }

    // ── DenyAsync ─────────────────────────────────────────────────────────────────────────────

    [Fact]
    public async Task DenyAsync_answers_the_client_with_access_denied_naming_the_provider_stage()
    {
        using var factory = NewFactory(context => context.DenyAsync());
        using var client = NewClient(factory);

        var (_, resume) = await ResumeAsync(client);

        resume.StatusCode.Should().Be(HttpStatusCode.Redirect);
        DestinationOf(resume).Should().Be(RegisteredRedirect);
        var query = RedirectQueryOf(resume);
        query["error"].ToString().Should().Be("access_denied");
        query["error_description"].ToString().Should().Contain("external identity provider");
        query["iss"].ToString().Should().Be("https://test.example.com");
        (await ReadJsonAsync(client, "/test/session")).Should().BeNull();
    }

    [Fact]
    public async Task DenyAsync_discards_the_interaction()
    {
        using var factory = NewFactory(context => context.DenyAsync());
        using var client = NewClient(factory);
        var (interactionId, _) = await ResumeAsync(client);

        var signIn = async () => await client.PostAsync(WithInteractionId(LoginPath, interactionId), Form(("sub", "user-1")), Cancellation);

        await signIn.Should().ThrowAsync<ZeeKayDaInteractionException>();
    }
}
