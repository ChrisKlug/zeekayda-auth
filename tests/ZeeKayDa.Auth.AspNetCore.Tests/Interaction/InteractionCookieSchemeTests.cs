using Microsoft.AspNetCore.Authentication;
using Microsoft.Extensions.DependencyInjection;
using ZeeKayDa.Auth.AspNetCore.Interaction;

namespace ZeeKayDa.Auth.AspNetCore.Tests.Interaction;

/// <summary>
/// The framework's cookie schemes must stay invisible to the host's own authentication. ASP.NET
/// Core promotes a lone registered scheme to the automatic default, which would silently make the
/// SSO session answer <c>[Authorize]</c> and receive a host's unqualified <c>SignInAsync</c> —
/// turning the fail-closed "no default scheme" error a host used to get into a silent grant, and
/// pre-empting the explicit opt-in that is #593.
/// </summary>
public sealed class InteractionCookieSchemeTests
{
    private static ServiceProvider BuildHost()
    {
        var services = new ServiceCollection();
        services.AddLogging();
        services.AddZeeKayDaAuth(options => options.Issuer = "https://auth.example.com");

        return services.BuildServiceProvider();
    }

    [Fact]
    public async Task The_framework_contributes_no_default_authenticate_scheme()
    {
        using var provider = BuildHost();
        var schemes = provider.GetRequiredService<IAuthenticationSchemeProvider>();

        (await schemes.GetDefaultAuthenticateSchemeAsync()).Should().BeNull(
            "a host with no authentication of its own must keep failing closed, not inherit the SSO session");
    }

    [Fact]
    public async Task The_framework_contributes_no_default_sign_in_scheme()
    {
        using var provider = BuildHost();
        var schemes = provider.GetRequiredService<IAuthenticationSchemeProvider>();

        (await schemes.GetDefaultSignInSchemeAsync()).Should().BeNull(
            "an unqualified HttpContext.SignInAsync must not write the framework's session cookie");
    }

    [Fact]
    public async Task Every_principal_carrying_cookie_is_registered_as_a_scheme()
    {
        using var provider = BuildHost();
        var schemes = provider.GetRequiredService<IAuthenticationSchemeProvider>();

        var registered = (await schemes.GetAllSchemesAsync()).Select(scheme => scheme.Name);

        // zkd.interaction is absent by design: it carries protocol state rather than a principal,
        // so it is a Data-Protection payload written directly, not a cookie authentication ticket.
        registered.Should().Contain(
            [ZeeKayDaCookies.Session, ZeeKayDaCookies.External, ZeeKayDaCookies.Pending],
            "registering a single scheme would hand ASP.NET Core an automatic default");
    }
}
