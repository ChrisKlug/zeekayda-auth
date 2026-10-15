using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;
using ZeeKayDa.Auth.AspNetCore.Providers;
using ZeeKayDa.Auth.StartupVerification;

namespace ZeeKayDa.Auth.AspNetCore.Interaction;

/// <summary>
/// Fails startup when a host cookie scheme uses a reserved cookie name; at runtime it would look
/// like an intermittently lost session. An activator, since reading options runs host callbacks.
/// </summary>
internal sealed class ReservedCookieNameActivator(
    IAuthenticationSchemeProvider? schemeProvider = null,
    IOptionsMonitor<CookieAuthenticationOptions>? cookieOptions = null) : IStartupActivator
{
    /// <inheritdoc/>
    public string Name => "ReservedCookieNames";

    /// <inheritdoc/>
    public async Task VerifyAsync(StartupVerificationContext context, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(context);

        if (schemeProvider is null || cookieOptions is null)
            return;

        var schemes = await schemeProvider.GetAllSchemesAsync().ConfigureAwait(false);

        foreach (var scheme in schemes.Where(scheme => !IsFrameworkScheme(scheme.Name)))
        {
            cancellationToken.ThrowIfCancellationRequested();

            // A non-cookie scheme resolves the default instance, whose cookie name is null.
            var name = cookieOptions.Get(scheme.Name).Cookie.Name;
            if (name is not null && IsReserved(name))
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
        ZeeKayDaCookies.SchemeNames.Contains(schemeName, StringComparer.Ordinal);

    /// <summary>A reserved name, or anything under the per-interaction binding and challenge prefixes.</summary>
    private static bool IsReserved(string name) =>
        ZeeKayDaCookies.ReservedNames.Contains(name, StringComparer.Ordinal)
        || name.StartsWith(InteractionBindingCookie.NamePrefix, StringComparison.Ordinal)
        || name.StartsWith(ProviderChallengeCookie.NamePrefix, StringComparison.Ordinal);
}
