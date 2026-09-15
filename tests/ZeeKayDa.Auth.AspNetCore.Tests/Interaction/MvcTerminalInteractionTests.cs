using System.Net;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Mvc.Infrastructure;
using Microsoft.AspNetCore.WebUtilities;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Primitives;
using ZeeKayDa.Auth.AspNetCore.Interaction;
using ZeeKayDa.Auth.AspNetCore.Tests.Pages;

namespace ZeeKayDa.Auth.AspNetCore.Tests.Interaction;

/// <summary>
/// Host pages written for MVC — a Razor Pages page and a controller — ending after a terminal
/// interaction call with a plain <c>await</c>. Without the framework's result filter the page
/// handler would go on to render against a response that is already committed, and throw.
/// </summary>
public sealed class MvcTerminalInteractionTests : IDisposable
{
    private const string RegisteredRedirect = "https://test.example.com/callback";
    private const string ConsentPath = "/account/consent";

    private readonly TestWebAppFactory _factory;
    private readonly HttpClient _client;

    public MvcTerminalInteractionTests()
    {
        _factory = new TestWebAppFactory(
            configureBuilder: builder =>
            {
                builder.Services.AddRazorPages();
                builder.Services.AddControllers();
            },
            mapEndpoints: endpoints =>
            {
                endpoints.MapRazorPages();
                endpoints.MapControllers();
            });

        _client = _factory.CreateClient(new()
        {
            BaseAddress = new Uri("https://test.example.com"),
            AllowAutoRedirect = false,
            HandleCookies = true,
        });
    }

    public void Dispose()
    {
        _client.Dispose();
        _factory.Dispose();
    }

    [Theory]
    [InlineData("/TerminalCall?handler=SignIn")]
    [InlineData("/mvc/login/sign-in")]
    public async Task A_handler_ending_with_a_plain_await_after_signing_in_continues_the_flow(string path)
    {
        // The default test client requires consent, so a completed sign-in goes on to the consent page.
        var response = await PostToInteractionAsync(path);

        response.StatusCode.Should().Be(HttpStatusCode.Redirect);
        response.Headers.Location!.OriginalString.Should().StartWith(ConsentPath + "?");
    }

    [Theory]
    [InlineData("/TerminalCall?handler=Cancel")]
    [InlineData("/mvc/login/cancel")]
    public async Task A_handler_ending_with_a_plain_await_after_denying_answers_the_client(string path)
    {
        var response = await PostToInteractionAsync(path);

        response.Headers.Location!.OriginalString.Should().StartWith(RegisteredRedirect + "?");
        RedirectQueryOf(response)["error"].ToString().Should().Be("access_denied");
    }

    [Theory]
    [InlineData("/TerminalCall?handler=SignInThenRedirect", ConsentPath)]
    [InlineData("/TerminalCall?handler=CancelThenRedirect", RegisteredRedirect)]
    public async Task A_result_a_page_returns_after_a_terminal_call_is_skipped_rather_than_sent(string path, string destination)
    {
        var response = await PostToInteractionAsync(path);

        response.StatusCode.Should().Be(HttpStatusCode.Redirect);
        response.Headers.Location!.OriginalString.Should().StartWith(destination + "?")
            .And.NotContain(TerminalCallModel.HijackTarget);
    }

    [Fact]
    public async Task A_page_that_makes_no_terminal_call_executes_its_own_result()
    {
        using var content = new FormUrlEncodedContent([]);

        var response = await _client.PostAsync("/TerminalCall?handler=Render", content, TestContext.Current.CancellationToken);

        response.StatusCode.Should().Be(HttpStatusCode.OK);
        (await response.Content.ReadAsStringAsync(TestContext.Current.CancellationToken))
            .Should().Contain(TerminalCallModel.RenderedText);
    }

    [Fact]
    public void AddZeeKayDaAuth_does_not_bring_MVC_into_a_host_without_it()
    {
        var services = new ServiceCollection();

        services.AddZeeKayDaAuth(options => options.Issuer = "https://test.example.com");

        services.Should().NotContain(descriptor => descriptor.ServiceType == typeof(IActionInvokerFactory));
    }

    /// <summary>Starts an authorization request, then posts to <paramref name="path"/> for the interaction it handed off.</summary>
    private async Task<HttpResponseMessage> PostToInteractionAsync(string path)
    {
        var handoff = await _client.GetAsync(
            QueryHelpers.AddQueryString("/connect/authorize", new Dictionary<string, string?>
            {
                ["client_id"] = "test-client",
                ["redirect_uri"] = RegisteredRedirect,
                ["response_type"] = "code",
                ["scope"] = "openid",
                ["nonce"] = "n-0S6_WzA2Mj",
                ["code_challenge"] = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM",
                ["code_challenge_method"] = "S256",
            }),
            TestContext.Current.CancellationToken);

        handoff.Headers.Location!.OriginalString.Should().StartWith("/account/login?", "the authorize request must hand off to the login page");

        using var content = new FormUrlEncodedContent([]);
        return await _client.PostAsync(
            QueryHelpers.AddQueryString(path, InteractionHandoff.InteractionIdParameter, InteractionIdFrom(handoff)),
            content,
            TestContext.Current.CancellationToken);
    }

    private static string InteractionIdFrom(HttpResponseMessage response) =>
        RedirectQueryOf(response)[InteractionHandoff.InteractionIdParameter]!;

    private static Dictionary<string, StringValues> RedirectQueryOf(HttpResponseMessage response)
    {
        var location = response.Headers.Location!.OriginalString;
        return QueryHelpers.ParseQuery(location[location.IndexOf('?')..]);
    }
}
