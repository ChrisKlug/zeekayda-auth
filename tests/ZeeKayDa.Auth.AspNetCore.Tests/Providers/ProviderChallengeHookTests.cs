using System.Net;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authentication.OAuth;
using Microsoft.AspNetCore.WebUtilities;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Microsoft.Extensions.Time.Testing;
using ZeeKayDa.Auth.AspNetCore.Interaction;
using ZeeKayDa.Auth.AspNetCore.Tests.Interaction;
using ZeeKayDa.Auth.Authorization;
using static ZeeKayDa.Auth.AspNetCore.Tests.Providers.ProviderTestHost;

namespace ZeeKayDa.Auth.AspNetCore.Tests.Providers;

/// <summary>
/// <c>OnProviderChallenge</c>: what a challenge to an external provider forwards of the client's
/// re-authentication demand, and the <c>login_required</c> the client receives when nothing does.
/// </summary>
public sealed class ProviderChallengeHookTests
{
    private static CancellationToken Cancellation => TestContext.Current.CancellationToken;

    /// <summary>A host with the acme provider, the hook under test, and the challenge properties the handler was given.</summary>
    private sealed class Host : IDisposable
    {
        public Host(
            Func<ProviderChallengeContext, ProviderChallengeOutcome>? onProviderChallenge,
            bool singleProvider = false,
            TimeProvider? time = null)
        {
            Factory = new TestWebAppFactory(
                configureOptions: singleProvider ? NoLoginPage : null,
                configureBuilder: builder =>
                {
                    builder.WithProviders(
                        auth => auth.AddOAuth("acme", "Acme", ConfigureCapturingAcme),
                        options => options.OnProviderChallenge = onProviderChallenge);
                    builder.Services.AddLogging(logging => logging.AddProvider(Logs));
                    if (time is not null)
                        builder.Services.AddSingleton(time);
                },
                mapEndpoints: MapHostPages);
            Client = NewClient(Factory);
        }

        public TestWebAppFactory Factory { get; }

        public HttpClient Client { get; }

        public CapturingLoggerProvider Logs { get; } = new();

        /// <summary>The properties the provider's handler was challenged with, or <see langword="null"/> when it never was.</summary>
        public AuthenticationProperties? Challenged { get; private set; }

        public void Dispose()
        {
            Client.Dispose();
            Factory.Dispose();
        }

        private static void NoLoginPage(AuthorizationServerOptions options)
        {
            options.AuthorizationEndpoint.Interaction.LoginPath = null;
            options.AuthorizationEndpoint.Interaction.SupportsLocalSignIn = false;
        }

        private void ConfigureCapturingAcme(OAuthOptions options)
        {
            ConfigureAcme(options);
            options.Events.OnRedirectToAuthorizationEndpoint = context =>
            {
                Challenged = context.Properties;
                context.Response.Redirect(context.RedirectUri);
                return Task.CompletedTask;
            };
        }
    }

    private static string AuthorizeUrl(params (string Name, string Value)[] extra) =>
        QueryHelpers.AddQueryString(
            ProviderTestHost.AuthorizeUrl("client-state"),
            extra.Select(parameter => KeyValuePair.Create(parameter.Name, (string?)parameter.Value)));

    /// <summary>Authorize through the login page and pick the provider: the response to that choice.</summary>
    private static async Task<HttpResponseMessage> ChooseProviderAsync(HttpClient client, params (string Name, string Value)[] extra)
    {
        var handoff = await client.GetAsync(AuthorizeUrl(extra), Cancellation);

        return await client.PostAsync(WithInteractionId(LoginPath, InteractionIdFrom(handoff)), Form(("provider", "acme")), Cancellation);
    }

    /// <summary>Complete the provider's callback for a challenge and return through resume.</summary>
    private static async Task<HttpResponseMessage> ReturnThroughResumeAsync(HttpClient client, HttpResponseMessage challenge)
    {
        var callback = await CallBackAsync(client, challenge);

        return await client.GetAsync(callback.Headers.Location!.OriginalString, Cancellation);
    }

    /// <summary>Complete the provider's callback for a challenge: the response that writes the external cookie.</summary>
    private static Task<HttpResponseMessage> CallBackAsync(HttpClient client, HttpResponseMessage challenge)
    {
        var callbackUrl = QueryHelpers.AddQueryString("/connect/callback/acme", new Dictionary<string, string?>
        {
            ["code"] = "acme-code",
            ["state"] = RedirectQueryOf(challenge)["state"].ToString(),
        });

        return client.GetAsync(callbackUrl, Cancellation);
    }

    /// <summary>The ticket in the external cookie <paramref name="callback"/> wrote, unprotected as its scheme reads it.</summary>
    private static AuthenticationTicket ExternalTicketOf(TestWebAppFactory factory, HttpResponseMessage callback)
    {
        var prefix = ZeeKayDaCookies.External + "=";
        var value = callback.Headers.GetValues("Set-Cookie")
            .Single(cookie => cookie.StartsWith(prefix, StringComparison.Ordinal))
            .Split(';')[0][prefix.Length..];
        var format = factory.Services.GetRequiredService<IOptionsMonitor<CookieAuthenticationOptions>>()
            .Get(ZeeKayDaCookies.External)
            .TicketDataFormat;

        return format.Unprotect(Uri.UnescapeDataString(value))!;
    }

    private static void ShouldHaveAnsweredTheClientWith(HttpResponseMessage response, string error)
    {
        response.StatusCode.Should().Be(HttpStatusCode.Redirect);
        DestinationOf(response).Should().Be(RegisteredRedirect);
        var query = RedirectQueryOf(response);
        query["error"].ToString().Should().Be(error);
        query["state"].ToString().Should().Be("client-state");
    }

    // ── A re-authentication demand ────────────────────────────────────────────────────────────

    [Fact]
    public async Task Prompt_login_challenges_with_what_the_hook_set_when_it_returns_Reauthenticating()
    {
        using var host = new Host(context =>
        {
            context.Properties.SetParameter("prompt", "login");
            context.Properties.SetParameter("max_age", context.MaxAge);
            return ProviderChallengeOutcome.Reauthenticating;
        });

        var challenge = await ChooseProviderAsync(host.Client, ("prompt", "login"), ("max_age", "300"));

        DestinationOf(challenge).Should().Be("https://acme.example.net/authorize");
        host.Challenged!.GetParameter<string>("prompt").Should().Be("login");
        host.Challenged.GetParameter<TimeSpan?>("max_age").Should().Be(TimeSpan.FromMinutes(5));
    }

    [Fact]
    public async Task Prompt_login_with_no_hook_answers_the_client_with_login_required_and_challenges_nothing()
    {
        using var host = new Host(onProviderChallenge: null, singleProvider: true);

        var response = await host.Client.GetAsync(AuthorizeUrl(("prompt", "login")), Cancellation);

        ShouldHaveAnsweredTheClientWith(response, AuthorizeRequestErrors.LoginRequired);
        host.Challenged.Should().BeNull();
    }

    [Fact]
    public async Task Prompt_login_with_no_hook_from_the_login_page_answers_the_client_with_login_required_and_challenges_nothing()
    {
        using var host = new Host(onProviderChallenge: null);

        var response = await ChooseProviderAsync(host.Client, ("prompt", "login"));

        ShouldHaveAnsweredTheClientWith(response, AuthorizeRequestErrors.LoginRequired);
        host.Challenged.Should().BeNull();
    }

    [Fact]
    public async Task An_exceeded_max_age_with_a_hook_returning_Proceed_answers_the_client_with_login_required()
    {
        // Near real time: the correlation cookie of the first round trip expires against the real clock.
        var time = new FakeTimeProvider(DateTimeOffset.UtcNow);
        using var host = new Host(_ => ProviderChallengeOutcome.Proceed, singleProvider: true, time: time);
        var firstChallenge = await host.Client.GetAsync(AuthorizeUrl(), Cancellation);
        await ReturnThroughResumeAsync(host.Client, firstChallenge);
        time.Advance(TimeSpan.FromMinutes(5));

        var response = await host.Client.GetAsync(AuthorizeUrl(("max_age", "60")), Cancellation);

        ShouldHaveAnsweredTheClientWith(response, AuthorizeRequestErrors.LoginRequired);
    }

    [Fact]
    public async Task Max_age_with_no_session_and_no_hook_answers_the_client_with_login_required_and_challenges_nothing()
    {
        using var host = new Host(onProviderChallenge: null, singleProvider: true);

        var response = await host.Client.GetAsync(AuthorizeUrl(("max_age", "300")), Cancellation);

        ShouldHaveAnsweredTheClientWith(response, AuthorizeRequestErrors.LoginRequired);
        host.Challenged.Should().BeNull();
    }

    [Fact]
    public async Task Max_age_with_no_session_is_a_reauthentication_demand_the_hook_can_answer_with_Reauthenticating()
    {
        ProviderChallengeContext? seen = null;
        using var host = new Host(context =>
        {
            seen = context;
            return ProviderChallengeOutcome.Reauthenticating;
        }, singleProvider: true);

        var challenge = await host.Client.GetAsync(AuthorizeUrl(("max_age", "300")), Cancellation);

        DestinationOf(challenge).Should().Be("https://acme.example.net/authorize");
        seen!.ReauthenticationRequired.Should().BeTrue("with no session the authentication time cannot be within max_age");
    }

    [Fact]
    public async Task Prompt_login_with_a_hook_returning_Proceed_from_the_login_page_answers_the_client_with_login_required()
    {
        using var host = new Host(_ => ProviderChallengeOutcome.Proceed);

        var response = await ChooseProviderAsync(host.Client, ("prompt", "login"));

        ShouldHaveAnsweredTheClientWith(response, AuthorizeRequestErrors.LoginRequired);
        host.Challenged.Should().BeNull();
    }

    // ── No demand ─────────────────────────────────────────────────────────────────────────────

    [Fact]
    public async Task With_no_demand_and_no_hook_the_challenge_proceeds_unchanged()
    {
        using var host = new Host(onProviderChallenge: null);

        var challenge = await ChooseProviderAsync(host.Client);

        DestinationOf(challenge).Should().Be("https://acme.example.net/authorize");
        host.Challenged!.Parameters.Should().BeEmpty();
    }

    [Fact]
    public async Task The_hook_sees_the_request_the_provider_and_no_demand_when_none_was_made()
    {
        ProviderChallengeContext? seen = null;
        using var host = new Host(context =>
        {
            seen = context;
            return ProviderChallengeOutcome.Proceed;
        });

        await ChooseProviderAsync(host.Client, ("login_hint", "alice@example.com"), ("prompt", "consent"));

        seen!.Provider.Id.Should().Be("acme");
        seen.Prompts.Should().BeEquivalentTo([PromptValue.Consent]);
        seen.MaxAge.Should().BeNull();
        seen.LoginHint.Should().Be("alice@example.com");
        seen.ReauthenticationRequired.Should().BeFalse("the request carries neither prompt=login nor max_age");
    }

    [Fact]
    public async Task The_hook_set_by_a_later_WithProviders_call_runs_for_a_provider_registered_by_an_earlier_one()
    {
        var calls = new List<string>();
        using var factory = new TestWebAppFactory(
            configureBuilder: builder =>
            {
                builder.WithProviders(
                    auth => auth.AddOAuth("acme", "Acme", ConfigureAcme),
                    options => options.OnProviderChallenge = context =>
                    {
                        calls.Add($"first:{context.Provider.Id}");
                        return ProviderChallengeOutcome.Proceed;
                    });
                builder.WithProviders(
                    auth => auth.AddOAuth("globex", "Globex", ConfigureAcme),
                    options => options.OnProviderChallenge = context =>
                    {
                        calls.Add($"second:{context.Provider.Id}");
                        return ProviderChallengeOutcome.Proceed;
                    });
            },
            mapEndpoints: MapHostPages);
        using var client = NewClient(factory);

        await ChooseProviderAsync(client);

        calls.Should().Equal("second:acme");
    }

    [Fact]
    public async Task Max_age_within_the_age_of_a_session_is_no_reauthentication_demand_and_the_challenge_proceeds()
    {
        // Near real time: the correlation cookie of the first round trip expires against the real clock.
        var time = new FakeTimeProvider(DateTimeOffset.UtcNow);
        ProviderChallengeContext? seen = null;
        using var host = new Host(context =>
        {
            seen = context;
            return ProviderChallengeOutcome.Proceed;
        }, time: time);
        var pending = await host.Client.GetAsync(AuthorizeUrl(("max_age", "300")), Cancellation);
        await ReturnThroughResumeAsync(host.Client, await ChooseProviderAsync(host.Client));
        time.Advance(TimeSpan.FromSeconds(60));

        var challenge = await host.Client.PostAsync(
            WithInteractionId(LoginPath, InteractionIdFrom(pending)), Form(("provider", "acme")), Cancellation);

        DestinationOf(challenge).Should().Be("https://acme.example.net/authorize");
        seen!.ReauthenticationRequired.Should().BeFalse("the session was authenticated 60 seconds ago, within max_age=300");
    }

    [Fact]
    public async Task A_hook_returning_Refuse_answers_the_client_with_login_required()
    {
        using var host = new Host(_ => ProviderChallengeOutcome.Refuse);

        var response = await ChooseProviderAsync(host.Client);

        ShouldHaveAnsweredTheClientWith(response, AuthorizeRequestErrors.LoginRequired);
        host.Challenged.Should().BeNull();
    }

    // ── A hook that fails ─────────────────────────────────────────────────────────────────────

    [Fact]
    public async Task A_hook_that_throws_answers_server_error_and_logs_the_exception_type_without_its_message()
    {
        using var host = new Host(_ => throw new InvalidOperationException("secret-value-not-for-the-log"), singleProvider: true);

        var response = await host.Client.GetAsync(AuthorizeUrl(), Cancellation);

        ShouldHaveAnsweredTheClientWith(response, AuthorizeRequestErrors.ServerError);
        host.Challenged.Should().BeNull();
        host.Logs.Entries.Should().Contain(entry =>
            entry.Level == LogLevel.Error && entry.Message.Contains(typeof(InvalidOperationException).FullName!, StringComparison.Ordinal));
        host.Logs.Entries.Should().NotContain(entry => entry.Message.Contains("secret-value", StringComparison.Ordinal));
    }

    [Fact]
    public async Task A_hook_returning_null_answers_server_error()
    {
        using var host = new Host(_ => null!);

        var response = await ChooseProviderAsync(host.Client);

        ShouldHaveAnsweredTheClientWith(response, AuthorizeRequestErrors.ServerError);
        host.Challenged.Should().BeNull();
    }

    // ── The round trip ────────────────────────────────────────────────────────────────────────

    [Fact]
    public async Task A_hook_that_overwrites_the_framework_items_still_resumes_the_interaction()
    {
        using var host = new Host(context =>
        {
            context.Properties.Items.Clear();
            context.Properties.RedirectUri = "https://attacker.example.net/";
            return ProviderChallengeOutcome.Proceed;
        });
        var challenge = await ChooseProviderAsync(host.Client);

        var resume = await ReturnThroughResumeAsync(host.Client, challenge);

        resume.ShouldHaveReachedConsent("the framework re-stamped its items after the hook");
    }

    [Fact]
    public async Task A_hook_that_sets_ticket_lifetime_properties_does_not_extend_the_external_cookie()
    {
        using var host = new Host(context =>
        {
            context.Properties.ExpiresUtc = DateTimeOffset.UtcNow.AddDays(1);
            context.Properties.IsPersistent = true;
            return ProviderChallengeOutcome.Proceed;
        });
        var challenge = await ChooseProviderAsync(host.Client);

        var callback = await CallBackAsync(host.Client, challenge);

        var ticket = ExternalTicketOf(host.Factory, callback);
        ticket.Properties.ExpiresUtc.Should().BeOnOrBefore(DateTimeOffset.UtcNow.AddMinutes(5));
        ticket.Properties.IsPersistent.Should().BeFalse("a persistent cookie would carry the hook's expiry to the browser");
    }
}
