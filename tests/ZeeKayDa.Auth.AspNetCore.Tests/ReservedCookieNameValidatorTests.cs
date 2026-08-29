using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.Extensions.DependencyInjection;
using ZeeKayDa.Auth.AspNetCore.Interaction;

namespace ZeeKayDa.Auth.AspNetCore.Tests;

/// <summary>
/// The reserved cookie names are a security control, not a courtesy: a host scheme sharing
/// <c>zkd.session</c> would overwrite the framework's ticket with one whose claims the host wrote,
/// including the session identifier every later binding is keyed on.
/// </summary>
public sealed class ReservedCookieNameValidatorTests
{
    private static async Task<StartupVerificationContext> VerifyAsync(Action<AuthenticationBuilder> configure)
    {
        var services = new ServiceCollection();
        services.AddLogging();
        configure(services.AddAuthentication());

        using var provider = services.BuildServiceProvider();
        var context = new StartupVerificationContext();

        await new ReservedCookieNameValidator()
            .VerifyAsync(context, provider, TestContext.Current.CancellationToken);

        return context;
    }

    [Theory]
    [InlineData(ZeeKayDaCookies.Session)]
    [InlineData(ZeeKayDaCookies.Interaction)]
    [InlineData(ZeeKayDaCookies.External)]
    [InlineData(ZeeKayDaCookies.Pending)]
    public async Task A_host_scheme_taking_a_reserved_cookie_name_fails_startup(string reservedName)
    {
        var context = await VerifyAsync(auth =>
            auth.AddCookie("host-scheme", options => options.Cookie.Name = reservedName));

        context.Failures.Should().ContainSingle()
            .Which.Code.Should().Be("cookie.reserved_name");
    }

    [Fact]
    public async Task A_host_scheme_with_a_name_of_its_own_passes()
    {
        var context = await VerifyAsync(auth =>
            auth.AddCookie("host-scheme", options => options.Cookie.Name = "host.session"));

        context.Failures.Should().BeEmpty();
    }

    [Fact]
    public void A_real_host_taking_a_reserved_cookie_name_does_not_start()
    {
        // Control-presence: the validator above is only a control if AddZeeKayDaAuth registers it.
        using var factory = new TestWebAppFactory(
            configureBuilder: builder => builder.Services
                .AddAuthentication()
                .AddCookie("host-scheme", options => options.Cookie.Name = ZeeKayDaCookies.Session));

        var start = () => factory.CreateClient();

        start.Should().Throw<Exception>()
            .Where(ex => ExceptionChain.FindInChain<ZeeKayDaConfigurationException>(ex)!
                .AggregatedFailures.Any(failure => failure.Code == "cookie.reserved_name"));
    }

    [Fact]
    public async Task A_host_scheme_named_for_the_one_reserved_cookie_with_no_scheme_is_still_reported()
    {
        // zkd.interaction is a reserved cookie name the framework never registers a scheme for, so
        // skipping "the framework's own schemes" must not skip a host scheme that took that name.
        var context = await VerifyAsync(auth => auth.AddCookie(
            ZeeKayDaCookies.Interaction,
            options => options.Cookie.Name = ZeeKayDaCookies.Interaction));

        context.Failures.Should().ContainSingle()
            .Which.Code.Should().Be("cookie.reserved_name");
    }

    [Fact]
    public async Task The_frameworks_own_schemes_are_not_reported_against_themselves()
    {
        var context = await VerifyAsync(auth =>
        {
            foreach (var scheme in ZeeKayDaCookies.SchemeNames)
                auth.AddCookie(scheme, options => options.Cookie.Name = scheme);
        });

        context.Failures.Should().BeEmpty();
    }
}
