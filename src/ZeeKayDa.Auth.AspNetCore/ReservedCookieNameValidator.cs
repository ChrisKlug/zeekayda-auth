using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;
using ZeeKayDa.Auth.AspNetCore.Interaction;

namespace ZeeKayDa.Auth.AspNetCore;

/// <summary>
/// Fails startup when a host's own cookie authentication scheme uses one of the cookie names
/// ZeeKayDa.Auth reserves.
/// </summary>
/// <remarks>
/// <para>
/// Two schemes writing one cookie name means each overwrites the other's ticket, and the framework
/// would read host-written claims where it expects only its own — including the session identifier
/// every later binding is keyed on. Startup is the only place to catch it: at runtime it looks
/// like an intermittently lost session.
/// </para>
/// <para>
/// An activator rather than a verifier, by the mechanical rule: reading a scheme's options runs
/// the host's own configuration callback for that scheme.
/// </para>
/// </remarks>
internal sealed class ReservedCookieNameValidator : IStartupActivator
{
    /// <inheritdoc/>
    public string Name => "ReservedCookieNames";

    /// <inheritdoc/>
    public async ValueTask VerifyAsync(
        StartupVerificationContext context,
        IServiceProvider scopedServices,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(context);
        ArgumentNullException.ThrowIfNull(scopedServices);

        var schemeProvider = scopedServices.GetService<IAuthenticationSchemeProvider>();
        var cookieOptions = scopedServices.GetService<IOptionsMonitor<CookieAuthenticationOptions>>();
        if (schemeProvider is null || cookieOptions is null)
            return;

        var schemes = await schemeProvider.GetAllSchemesAsync().ConfigureAwait(false);

        foreach (var scheme in schemes.Where(scheme => !IsFrameworkScheme(scheme.Name)))
        {
            cancellationToken.ThrowIfCancellationRequested();

            // Every cookie handler resolves CookieAuthenticationOptions; a scheme backed by any
            // other handler resolves the default instance, whose cookie name is null.
            var name = cookieOptions.Get(scheme.Name).Cookie.Name;
            if (name is not null && ZeeKayDaCookies.ReservedNames.Contains(name, StringComparer.Ordinal))
            {
                context.AddFailure(
                    "cookie.reserved_name",
                    $"The authentication scheme '{scheme.Name}' uses the cookie name '{name}', which is " +
                    "reserved by ZeeKayDa.Auth. Choose another name: sharing one with the framework " +
                    "would let the two overwrite each other's tickets.");
            }
        }
    }

    private static bool IsFrameworkScheme(string schemeName) =>
        ZeeKayDaCookies.ReservedNames.Contains(schemeName, StringComparer.Ordinal);
}
