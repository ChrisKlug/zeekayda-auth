using System.Text.Encodings.Web;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.OAuth;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using ZeeKayDa.Auth.AspNetCore.Interaction;
using ZeeKayDa.Auth.AspNetCore.Providers;

namespace ZeeKayDa.Auth.AspNetCore.Tests.Providers;

/// <summary>
/// <c>WithProviders</c> at registration time: what the callback registered is observed and taken
/// for the framework's scheme map, the host's <see cref="AuthenticationOptions"/> never learns of
/// it, and everything that would break that guarantee fails where it is written.
/// </summary>
public sealed class WithProvidersTests
{
    private const string Issuer = "https://auth.example.com";

    private static IServiceCollection NewServices()
    {
        var services = new ServiceCollection();
        services.AddLogging();
        services.AddDataProtection();
        services.Configure<AuthorizationServerOptions>(options => options.Issuer = Issuer);
        services.AddAuthentication();
        return services;
    }

    private static void ConfigureAcme(OAuthOptions options)
    {
        options.ClientId = "acme-client";
        options.ClientSecret = "acme-secret";
        options.AuthorizationEndpoint = "https://acme.example.net/authorize";
        options.TokenEndpoint = "https://acme.example.net/token";
    }

    // ── Observe, then take ────────────────────────────────────────────────────────────────────

    [Fact]
    public void A_remote_scheme_registered_in_the_callback_becomes_a_provider()
    {
        var services = NewServices();

        new ZeeKayDaAuthBuilder(services).WithProviders(auth => auth.AddOAuth("acme", "Acme Corp", ConfigureAcme));

        var registry = ProviderRegistry.FindIn(services);
        registry.Descriptors.Should().ContainSingle()
            .Which.Should().BeEquivalentTo(new { Id = "acme", DisplayName = "Acme Corp" });
        registry.Find("acme")!.HandlerType.Should().Be(typeof(OAuthHandler<OAuthOptions>));
    }

    [Fact]
    public async Task A_provider_scheme_is_absent_from_the_host_scheme_map()
    {
        var services = NewServices();
        new ZeeKayDaAuthBuilder(services).WithProviders(auth => auth.AddOAuth("acme", ConfigureAcme));
        using var provider = services.BuildServiceProvider();

        var schemes = provider.GetRequiredService<IAuthenticationSchemeProvider>();

        (await schemes.GetSchemeAsync("acme")).Should().BeNull();
        (await schemes.GetAllSchemesAsync()).Select(scheme => scheme.Name).Should().NotContain("acme");
    }

    [Fact]
    public void The_handler_and_its_named_options_stay_registered_for_the_framework_to_use()
    {
        var services = NewServices();
        new ZeeKayDaAuthBuilder(services).WithProviders(auth => auth.AddOAuth("acme", ConfigureAcme));
        using var provider = services.BuildServiceProvider();

        provider.GetService<OAuthHandler<OAuthOptions>>().Should().NotBeNull();
        provider.GetRequiredService<IOptionsMonitor<OAuthOptions>>().Get("acme").ClientId.Should().Be("acme-client");
    }

    [Fact]
    public void Every_route_into_the_scheme_map_is_observed_identically()
    {
        var services = NewServices();

        new ZeeKayDaAuthBuilder(services).WithProviders(auth =>
        {
            auth.AddOAuth("remote", ConfigureAcme);
            auth.AddScheme<AuthenticationSchemeOptions, PlainHandler>("plain", "Plain", _ => { });
            auth.AddPolicyScheme("policy", "Policy", options => options.ForwardDefault = "plain");
            auth.Services.Configure<AuthenticationOptions>(options => options.AddScheme<PlainHandler>("raw", "Raw"));
        });

        ProviderRegistry.FindIn(services).Descriptors.Select(descriptor => descriptor.Id)
            .Should().Equal("remote", "plain", "policy", "raw");
    }

    [Fact]
    public void Repeated_calls_accumulate_in_registration_order()
    {
        var services = NewServices();
        var builder = new ZeeKayDaAuthBuilder(services);

        builder.WithProviders(auth => auth.AddOAuth("first", ConfigureAcme));
        builder.WithProviders(auth => auth.AddOAuth("second", ConfigureAcme));

        ProviderRegistry.FindIn(services).Descriptors.Select(descriptor => descriptor.Id)
            .Should().Equal("first", "second");
        services.Count(descriptor => descriptor.ServiceType == typeof(ProviderRegistry)).Should().Be(1);
    }

    [Fact]
    public void A_scheme_the_host_registered_outside_the_window_is_left_alone()
    {
        var services = NewServices();
        services.AddAuthentication().AddOAuth("host-oauth", options =>
        {
            ConfigureAcme(options);
            options.CallbackPath = "/signin-host";
        });

        new ZeeKayDaAuthBuilder(services).WithProviders(auth => auth.AddOAuth("acme", ConfigureAcme));
        using var provider = services.BuildServiceProvider();

        var hostOptions = provider.GetRequiredService<IOptionsMonitor<OAuthOptions>>().Get("host-oauth");
        hostOptions.CallbackPath.Should().Be(new PathString("/signin-host"));
        hostOptions.SignInScheme.Should().NotBe(ZeeKayDaCookies.External);
        ProviderRegistry.FindIn(services).Contains("host-oauth").Should().BeFalse();
    }

    // ── The pin ───────────────────────────────────────────────────────────────────────────────

    [Fact]
    public void The_framework_pins_every_member_it_owns_whatever_the_registration_set()
    {
        var services = NewServices();
        new ZeeKayDaAuthBuilder(services).WithProviders(auth => auth.AddOAuth("acme", options =>
        {
            ConfigureAcme(options);
            options.CallbackPath = "/signin-acme";
            options.SignInScheme = "host-cookie";
            options.AccessDeniedPath = "/denied";
            options.ForwardDefault = "x";
            options.ForwardDefaultSelector = _ => "x";
            options.ForwardAuthenticate = "x";
            options.ForwardChallenge = "x";
            options.ForwardForbid = "x";
            options.ForwardSignIn = "x";
            options.ForwardSignOut = "x";
        }));
        using var provider = services.BuildServiceProvider();

        var options = provider.GetRequiredService<IOptionsMonitor<OAuthOptions>>().Get("acme");

        options.CallbackPath.Should().Be(new PathString("/connect/callback/acme"));
        options.SignInScheme.Should().Be(ZeeKayDaCookies.External);
        options.AccessDeniedPath.HasValue.Should().BeFalse();
        options.ForwardDefault.Should().BeNull();
        options.ForwardDefaultSelector.Should().BeNull();
        options.ForwardAuthenticate.Should().BeNull();
        options.ForwardChallenge.Should().BeNull();
        options.ForwardForbid.Should().BeNull();
        options.ForwardSignIn.Should().BeNull();
        options.ForwardSignOut.Should().BeNull();
    }

    [Fact]
    public void The_callback_path_sits_under_a_path_based_issuer()
    {
        var services = NewServices();
        services.Configure<AuthorizationServerOptions>(options => options.Issuer = "https://auth.example.com/tenant");
        new ZeeKayDaAuthBuilder(services).WithProviders(auth => auth.AddOAuth("acme", ConfigureAcme));
        using var provider = services.BuildServiceProvider();

        provider.GetRequiredService<IOptionsMonitor<OAuthOptions>>().Get("acme").CallbackPath
            .Should().Be(new PathString("/tenant/connect/callback/acme"));
    }

    [Fact]
    public void A_provider_registered_in_a_later_call_is_pinned_too()
    {
        var services = NewServices();
        var builder = new ZeeKayDaAuthBuilder(services);
        builder.WithProviders(auth => auth.AddOAuth("first", ConfigureAcme));
        builder.WithProviders(auth => auth.AddOAuth("second", options =>
        {
            ConfigureAcme(options);
            options.SignInScheme = "host-cookie";
        }));
        using var provider = services.BuildServiceProvider();

        provider.GetRequiredService<IOptionsMonitor<OAuthOptions>>().Get("second").SignInScheme
            .Should().Be(ZeeKayDaCookies.External);
    }

    // ── Refused at registration ───────────────────────────────────────────────────────────────

    [Theory]
    [InlineData("a/b")]
    [InlineData("a b")]
    [InlineData(".")]
    [InlineData("..")]
    [InlineData("acme?x")]
    [InlineData("ümlaut")]
    [InlineData("abcdefghijabcdefghijabcdefghijabcdefghijabcdefghijabcdefghijabcde")]
    public void A_provider_name_outside_the_grammar_is_refused(string name)
    {
        var services = NewServices();

        var register = () => new ZeeKayDaAuthBuilder(services).WithProviders(auth => auth.AddOAuth(name, ConfigureAcme));

        register.Should().Throw<InvalidOperationException>().WithMessage("*not valid*");
    }

    [Theory]
    [InlineData("acme")]
    [InlineData("Acme.Corp-2_0")]
    [InlineData("abcdefghijabcdefghijabcdefghijabcdefghijabcdefghijabcdefghijabcd")]
    public void A_provider_name_inside_the_grammar_is_accepted(string name)
    {
        var services = NewServices();

        new ZeeKayDaAuthBuilder(services).WithProviders(auth => auth.AddOAuth(name, ConfigureAcme));

        ProviderRegistry.FindIn(services).Contains(name).Should().BeTrue();
    }

    [Fact]
    public void A_provider_name_taken_by_an_earlier_call_is_refused_ignoring_case()
    {
        var services = NewServices();
        var builder = new ZeeKayDaAuthBuilder(services);
        builder.WithProviders(auth => auth.AddOAuth("Acme", ConfigureAcme));

        var register = () => builder.WithProviders(auth => auth.AddOAuth("acme", ConfigureAcme));

        register.Should().Throw<InvalidOperationException>().WithMessage("*already registered*");
    }

    [Fact]
    public void A_callback_that_sets_an_authentication_default_is_refused()
    {
        var services = NewServices();

        var register = () => new ZeeKayDaAuthBuilder(services).WithProviders(auth =>
        {
            auth.AddOAuth("acme", ConfigureAcme);
            auth.Services.AddAuthentication("acme");
        });

        register.Should().Throw<InvalidOperationException>().WithMessage("*AuthenticationOptions default*");
    }

    [Fact]
    public void A_scheme_map_configurer_that_cannot_be_replayed_is_refused()
    {
        var services = NewServices();

        var register = () => new ZeeKayDaAuthBuilder(services).WithProviders(auth =>
            auth.Services.AddSingleton<IConfigureOptions<AuthenticationOptions>, OpaqueSchemeConfigurer>());

        register.Should().Throw<InvalidOperationException>().WithMessage("*not an instance*");
    }

    [Fact]
    public void A_post_configurer_for_the_scheme_map_is_refused()
    {
        var services = NewServices();

        var register = () => new ZeeKayDaAuthBuilder(services).WithProviders(auth =>
            auth.Services.PostConfigure<AuthenticationOptions>(_ => { }));

        register.Should().Throw<InvalidOperationException>().WithMessage("*IPostConfigureOptions<AuthenticationOptions>*");
    }

    [Fact]
    public void A_callback_that_touches_earlier_registrations_is_refused()
    {
        var services = NewServices();

        var register = () => new ZeeKayDaAuthBuilder(services).WithProviders(auth =>
        {
            auth.AddOAuth("acme", ConfigureAcme);
            auth.Services.RemoveAt(0);
        });

        register.Should().Throw<InvalidOperationException>().WithMessage("*existed before it ran*");
    }

    [Fact]
    public void A_callback_that_inserts_ahead_of_earlier_registrations_is_refused()
    {
        var services = NewServices();

        var register = () => new ZeeKayDaAuthBuilder(services).WithProviders(auth =>
            auth.Services.Insert(0, ServiceDescriptor.Singleton(new object())));

        register.Should().Throw<InvalidOperationException>().WithMessage("*existed before it ran*");
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

    private sealed class OpaqueSchemeConfigurer : IConfigureOptions<AuthenticationOptions>
    {
        public void Configure(AuthenticationOptions options) => options.AddScheme<PlainHandler>("opaque", null);
    }
}
