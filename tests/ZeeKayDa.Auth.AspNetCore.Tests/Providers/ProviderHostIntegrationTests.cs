using System.Net;
using System.Text.Encodings.Web;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.OAuth;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Routing;
using Microsoft.AspNetCore.WebUtilities;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using ZeeKayDa.Auth.AspNetCore.Interaction;

namespace ZeeKayDa.Auth.AspNetCore.Tests.Providers;

/// <summary>
/// External provider registration in a real host: what the login page sees, what the host
/// cannot reach, the startup checks that guard the framework's pins, and the dispatch rules the
/// authorization endpoint applies.
/// </summary>
public sealed class ProviderHostIntegrationTests
{
    private const string RegisteredRedirect = "https://test.example.com/callback";
    private const string Challenge = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM";

    private static void ConfigureAcme(OAuthOptions options)
    {
        options.ClientId = "acme-client";
        options.ClientSecret = "acme-secret";
        options.AuthorizationEndpoint = "https://acme.example.net/authorize";
        options.TokenEndpoint = "https://acme.example.net/token";
    }

    private static TestWebAppFactory NewFactory(
        Action<AuthorizationServerOptions>? configureOptions = null,
        Action<ZeeKayDaAuthBuilder>? configureBuilder = null) =>
        new(configureOptions, configureBuilder, MapHostPages);

    private static HttpClient NewClient(TestWebAppFactory factory) => factory.CreateClient(new()
    {
        BaseAddress = new Uri("https://test.example.com"),
        AllowAutoRedirect = false,
    });

    /// <summary>The host's pages: a probe reporting what the login page would render.</summary>
    private static void MapHostPages(IEndpointRouteBuilder endpoints)
    {
        endpoints.MapGet("/test/login-options", (ILoginInteraction login) => Results.Ok(new
        {
            local = login.LocalLoginEnabled,
            providers = login.Providers.Select(provider => $"{provider.Id}:{provider.DisplayName}"),
        }));

        // What the invariant forbids a host from doing, and what removal makes impossible.
        endpoints.MapGet("/test/challenge-provider", (HttpContext context) => context.ChallengeAsync("acme"));
    }

    private static string AuthorizeUrl() => QueryHelpers.AddQueryString("/connect/authorize", new Dictionary<string, string?>
    {
        ["client_id"] = "test-client",
        ["redirect_uri"] = RegisteredRedirect,
        ["response_type"] = "code",
        ["scope"] = "openid",
        ["nonce"] = "n-0S6_WzA2Mj",
        ["code_challenge"] = Challenge,
        ["code_challenge_method"] = "S256",
    });

    private static void ShouldFailStartupWith(TestWebAppFactory factory, string code)
    {
        var start = () => factory.CreateClient();

        start.Should().Throw<Exception>()
            .Where(ex => ExceptionChain.FindInChain<ZeeKayDaConfigurationException>(ex)!
                .AggregatedFailures.Any(failure => failure.Code == code));
    }

    // ── What the login page sees ──────────────────────────────────────────────────────────────

    [Fact]
    public async Task The_login_page_sees_the_registered_providers_and_the_local_sign_in_flag()
    {
        using var factory = NewFactory(configureBuilder: builder => builder.WithProviders(auth =>
        {
            auth.AddOAuth("acme", "Acme Corp", ConfigureAcme);
            auth.AddOAuth("globex", ConfigureAcme);
        }));
        using var client = NewClient(factory);

        var body = await client.GetStringAsync("/test/login-options", TestContext.Current.CancellationToken);

        // "OAuth" is the display name AddOAuth defaults when the registration gives none.
        body.Should().Be("""{"local":true,"providers":["acme:Acme Corp","globex:OAuth"]}""");
    }

    [Fact]
    public async Task A_host_with_local_sign_in_off_reports_it_to_the_page()
    {
        using var factory = NewFactory(
            configureOptions: options => options.AuthorizationEndpoint.Interaction.SupportsLocalSignIn = false,
            configureBuilder: builder => builder.WithProviders(auth => auth.AddOAuth("acme", ConfigureAcme)));
        using var client = NewClient(factory);

        var body = await client.GetStringAsync("/test/login-options", TestContext.Current.CancellationToken);

        body.Should().Be("""{"local":false,"providers":["acme:OAuth"]}""");
    }

    // ── Invisible to the host ─────────────────────────────────────────────────────────────────

    [Fact]
    public async Task A_provider_scheme_cannot_be_challenged_by_name_from_host_code()
    {
        using var factory = NewFactory(configureBuilder: builder =>
            builder.WithProviders(auth => auth.AddOAuth("acme", ConfigureAcme)));
        using var client = NewClient(factory);

        var challenge = () => client.GetAsync("/test/challenge-provider", TestContext.Current.CancellationToken);

        await challenge.Should().ThrowAsync<InvalidOperationException>()
            .WithMessage("*No authentication handler is registered for the scheme 'acme'*");
    }

    [Fact]
    public async Task A_provider_scheme_is_absent_from_the_host_scheme_map_of_a_running_host()
    {
        using var factory = NewFactory(configureBuilder: builder =>
            builder.WithProviders(auth => auth.AddOAuth("acme", ConfigureAcme)));
        using var client = NewClient(factory);

        var schemes = await factory.Services.GetRequiredService<IAuthenticationSchemeProvider>().GetAllSchemesAsync();

        schemes.Select(scheme => scheme.Name).Should().NotContain("acme");
    }

    // ── Pinned, and asserted at startup ───────────────────────────────────────────────────────

    [Fact]
    public void A_running_host_has_pinned_the_callback_path_under_the_issuer_and_the_sign_in_scheme()
    {
        using var factory = NewFactory(
            configureOptions: options => options.Issuer = "https://test.example.com/id",
            configureBuilder: builder => builder.WithProviders(auth => auth.AddOAuth("acme", ConfigureAcme)));
        using var client = NewClient(factory);

        var options = factory.Services.GetRequiredService<IOptionsMonitor<OAuthOptions>>().Get("acme");

        options.CallbackPath.Should().Be(new PathString("/id/connect/callback/acme"));
        options.SignInScheme.Should().Be(ZeeKayDaCookies.External);
    }

    [Fact]
    public void A_post_configurer_registered_after_WithProviders_that_moves_the_callback_path_fails_startup()
    {
        using var factory = NewFactory(configureBuilder: builder =>
        {
            builder.WithProviders(auth => auth.AddOAuth("acme", ConfigureAcme));
            builder.Services.PostConfigure<OAuthOptions>("acme", options => options.CallbackPath = "/signin-acme");
        });

        ShouldFailStartupWith(factory, "provider.options_invalid");
    }

    [Fact]
    public void A_post_configurer_registered_after_WithProviders_that_changes_the_sign_in_scheme_fails_startup()
    {
        using var factory = NewFactory(configureBuilder: builder =>
        {
            builder.WithProviders(auth => auth.AddOAuth("acme", ConfigureAcme));
            builder.Services.PostConfigure<OAuthOptions>("acme", options => options.SignInScheme = "host-cookie");
        });

        ShouldFailStartupWith(factory, "provider.options_invalid");
    }

    [Fact]
    public void A_post_configurer_registered_after_WithProviders_that_sets_an_access_denied_page_fails_startup()
    {
        using var factory = NewFactory(configureBuilder: builder =>
        {
            builder.WithProviders(auth => auth.AddOAuth("acme", ConfigureAcme));
            builder.Services.PostConfigure<OAuthOptions>("acme", options => options.AccessDeniedPath = "/denied");
        });

        ShouldFailStartupWith(factory, "provider.options_invalid");
    }

    [Fact]
    public void A_post_configurer_registered_after_WithProviders_that_forwards_the_challenge_fails_startup()
    {
        using var factory = NewFactory(configureBuilder: builder =>
        {
            builder.WithProviders(auth => auth.AddOAuth("acme", ConfigureAcme));
            builder.Services.PostConfigure<OAuthOptions>("acme", options => options.ForwardChallenge = "host-cookie");
        });

        ShouldFailStartupWith(factory, "provider.options_invalid");
    }

    [Fact]
    public void A_provider_whose_own_options_are_incomplete_fails_startup_rather_than_at_first_sign_in()
    {
        // OAuthOptions.Validate throws ArgumentNullException rather than reporting a validation
        // failure; the provider is named in the failure and the exception travels as its root cause.
        using var factory = NewFactory(configureBuilder: builder =>
            builder.WithProviders(auth => auth.AddOAuth("acme", options => options.ClientId = "acme-client")));

        var start = () => factory.CreateClient();

        start.Should().Throw<Exception>()
            .Where(ex => ExceptionChain.FindInChain<ZeeKayDaConfigurationException>(ex)!
                .AggregatedFailures.Any(failure => failure.Code == "provider.options_invalid" && failure.Message.Contains("'acme'")))
            .Where(ex => ExceptionChain.FindInChain<ArgumentNullException>(ex) != null);
    }

    [Fact]
    public void Every_provider_is_checked_even_after_an_earlier_one_failed()
    {
        using var factory = NewFactory(configureBuilder: builder =>
        {
            builder.WithProviders(auth =>
            {
                auth.AddOAuth("broken", options => options.ClientId = "only-a-client-id");
                auth.AddOAuth("drifted", ConfigureAcme);
            });
            builder.Services.PostConfigure<OAuthOptions>("drifted", options => options.CallbackPath = "/signin-drifted");
        });

        var start = () => factory.CreateClient();

        start.Should().Throw<Exception>()
            .Where(ex => ExceptionChain.FindInChain<ZeeKayDaConfigurationException>(ex)!
                .AggregatedFailures.Count(failure => failure.Code == "provider.options_invalid") == 2);
    }

    [Fact]
    public void A_startup_failure_repeats_the_framework_pin_assertions_but_not_the_provider_validators_text()
    {
        const string Sentinel = "s3cr3t-that-must-not-be-copied";
        using var factory = NewFactory(configureBuilder: builder =>
        {
            builder.WithProviders(auth => auth.AddOAuth("acme", ConfigureAcme));
            builder.Services.AddOptions<OAuthOptions>("acme")
                .Validate(_ => false, $"Provider validator text mentioning {Sentinel}");
            builder.Services.PostConfigure<OAuthOptions>("acme", options => options.SignInScheme = "host-cookie");
        });

        var start = () => factory.CreateClient();

        var thrown = start.Should().Throw<Exception>().Which;
        var message = ExceptionChain.FindInChain<ZeeKayDaConfigurationException>(thrown)!
            .AggregatedFailures.Single(failure => failure.Code == "provider.options_invalid").Message;

        message.Should().Contain("SignInScheme").And.NotContain(Sentinel);
        thrown.ToString().Should().Contain(Sentinel, "the provider's own text still reaches the operator as the root cause");
    }

    [Fact]
    public void A_configuration_exception_thrown_by_a_provider_validator_keeps_its_own_code()
    {
        using var factory = NewFactory(configureBuilder: builder =>
        {
            builder.WithProviders(auth => auth.AddOAuth("acme", ConfigureAcme));
            builder.Services.AddOptions<OAuthOptions>("acme").Validate(_ =>
                throw new ZeeKayDaConfigurationException(
                    new ZeeKayDaConfigurationFailure("acme.tenant_missing", "The Acme tenant is not configured.")));
        });

        ShouldFailStartupWith(factory, "acme.tenant_missing");
    }

    [Fact]
    public void A_post_configurer_registered_between_two_WithProviders_calls_still_fails_startup()
    {
        using var factory = NewFactory(configureBuilder: builder =>
        {
            builder.WithProviders(auth => auth.AddOAuth("first", ConfigureAcme));
            builder.Services.PostConfigure<OAuthOptions>("first", options => options.CallbackPath = "/signin-first");
            builder.WithProviders(auth => auth.AddOAuth("second", ConfigureAcme));
        });

        ShouldFailStartupWith(factory, "provider.options_invalid");
    }

    [Fact]
    public void A_remote_options_handler_outside_the_remote_base_class_is_asserted_at_startup_too()
    {
        using var factory = NewFactory(configureBuilder: builder =>
        {
            builder.WithProviders(auth => auth.AddScheme<OddRemoteOptions, OddRemoteHandler>("odd", "Odd", _ => { }));
            builder.Services.PostConfigure<OddRemoteOptions>("odd", options => options.CallbackPath = "/signin-odd");
        });

        ShouldFailStartupWith(factory, "provider.options_invalid");
    }

    [Fact]
    public void A_provider_name_the_host_also_registered_as_a_scheme_fails_startup()
    {
        using var factory = NewFactory(configureBuilder: builder =>
        {
            builder.WithProviders(auth => auth.AddOAuth("acme", ConfigureAcme));
            builder.Services.AddAuthentication().AddCookie("acme");
        });

        ShouldFailStartupWith(factory, "provider.scheme_visible_to_host");
    }

    [Fact]
    public async Task A_handler_outside_the_remote_hierarchy_is_a_provider_with_nothing_to_pin()
    {
        using var factory = NewFactory(configureBuilder: builder => builder.WithProviders(auth =>
            auth.AddScheme<AuthenticationSchemeOptions, PlainHandler>("plain", "Plain", _ => { })));
        using var client = NewClient(factory);

        var body = await client.GetStringAsync("/test/login-options", TestContext.Current.CancellationToken);

        body.Should().Be("""{"local":true,"providers":["plain:Plain"]}""");
    }

    // ── Dispatch at the authorization endpoint ────────────────────────────────────────────────

    [Fact]
    public async Task A_configured_login_page_is_used_even_with_a_single_provider_and_local_sign_in_off()
    {
        using var factory = NewFactory(
            configureOptions: options => options.AuthorizationEndpoint.Interaction.SupportsLocalSignIn = false,
            configureBuilder: builder => builder.WithProviders(auth => auth.AddOAuth("acme", ConfigureAcme)));
        using var client = NewClient(factory);

        var response = await client.GetAsync(AuthorizeUrl(), TestContext.Current.CancellationToken);

        response.StatusCode.Should().Be(HttpStatusCode.Redirect, "the framework never skips a page the host built");
        response.Headers.Location!.OriginalString.Should().StartWith("/account/login?");
    }

    [Fact]
    public async Task A_single_provider_with_no_login_page_and_local_sign_in_off_is_dispatched_to_the_provider()
    {
        using var factory = NewFactory(
            configureOptions: options =>
            {
                options.AuthorizationEndpoint.Interaction.LoginPath = null;
                options.AuthorizationEndpoint.Interaction.SupportsLocalSignIn = false;
            },
            configureBuilder: builder => builder.WithProviders(auth => auth.AddOAuth("acme", ConfigureAcme)));
        using var client = NewClient(factory);

        var response = await client.GetAsync(AuthorizeUrl(), TestContext.Current.CancellationToken);

        // The challenge itself lands with the external round trip; until then the request stops
        // here rather than being reported to the client as a configuration failure.
        response.StatusCode.Should().Be(HttpStatusCode.NotImplemented);
    }

    [Fact]
    public async Task Two_providers_with_no_login_page_answer_the_client_with_server_error()
    {
        using var factory = NewFactory(
            configureOptions: options =>
            {
                options.AuthorizationEndpoint.Interaction.LoginPath = null;
                options.AuthorizationEndpoint.Interaction.SupportsLocalSignIn = false;
            },
            configureBuilder: builder => builder.WithProviders(auth =>
            {
                auth.AddOAuth("acme", ConfigureAcme);
                auth.AddOAuth("globex", ConfigureAcme);
            }));
        using var client = NewClient(factory);

        var response = await client.GetAsync(AuthorizeUrl(), TestContext.Current.CancellationToken);

        response.StatusCode.Should().Be(HttpStatusCode.Redirect);
        response.Headers.Location!.OriginalString.Should().StartWith(RegisteredRedirect)
            .And.Contain("error=server_error");
    }

    /// <summary>
    /// Remote-shaped options on a handler that does not derive from the remote base class: the
    /// pin and validator key on the options type, so the startup assertion must find it too.
    /// </summary>
    private sealed class OddRemoteOptions : RemoteAuthenticationOptions;

    private sealed class OddRemoteHandler(
        IOptionsMonitor<OddRemoteOptions> options,
        ILoggerFactory logger,
        UrlEncoder encoder)
        : AuthenticationHandler<OddRemoteOptions>(options, logger, encoder)
    {
        protected override Task<AuthenticateResult> HandleAuthenticateAsync()
            => Task.FromResult(AuthenticateResult.NoResult());
    }

    /// <summary>A handler outside the remote hierarchy — supported, with nothing to pin.</summary>
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
