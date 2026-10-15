using Microsoft.AspNetCore.Http;
using ZeeKayDa.Auth.AspNetCore.Interaction;
using ZeeKayDa.Auth.Authorization;

namespace ZeeKayDa.Auth.AspNetCore.Providers;

/// <summary>
/// Names, to a provider's callback, the interaction a login-page challenge was issued for:
/// <c>zkd.challenge.&lt;id&gt;</c>, scoped to the callback route, removed when the round trip ends.
/// </summary>
/// <remarks>
/// The way back when a handler throws instead of handing its properties to the failure event. Not
/// a secret and proves nothing: a forgery can only change the login page's message. Two such cookies
/// name nothing.
/// </remarks>
internal static class ProviderChallengeCookie
{
    /// <summary>The prefix every challenge cookie's name starts with; the interaction identifier follows it.</summary>
    internal const string NamePrefix = ZeeKayDaCookies.Challenge + ".";

    public static void Issue(HttpContext context, Uri issuerUri, ProviderRegistration registration, AuthorizationRequestContext requestContext)
    {
        ArgumentNullException.ThrowIfNull(context);
        ArgumentNullException.ThrowIfNull(registration);
        ArgumentNullException.ThrowIfNull(requestContext);

        context.Response.Cookies.Append(
            NamePrefix + requestContext.Id,
            "1",
            OptionsFor(ProviderCallbackRoute.For(issuerUri, registration.Name), requestContext.ExpiresAt));
    }

    /// <summary>The interaction the request's one challenge cookie names, or <see langword="null"/>.</summary>
    public static string? Single(HttpContext context)
    {
        ArgumentNullException.ThrowIfNull(context);

        var named = context.Request.Cookies.Keys.Where(IsChallengeCookie).Take(2).ToArray();
        return named.Length == 1 ? named[0][NamePrefix.Length..] : null;
    }

    /// <summary>Removes the challenge cookie for <paramref name="interactionId"/> at <paramref name="registration"/>'s callback route.</summary>
    public static void Clear(HttpContext context, Uri issuerUri, ProviderRegistration registration, string interactionId)
    {
        ArgumentNullException.ThrowIfNull(context);
        ArgumentNullException.ThrowIfNull(registration);
        ArgumentException.ThrowIfNullOrEmpty(interactionId);

        context.Response.Cookies.Delete(NamePrefix + interactionId, OptionsFor(ProviderCallbackRoute.For(issuerUri, registration.Name), null));
    }

    private static bool IsChallengeCookie(string name) =>
        name.StartsWith(NamePrefix, StringComparison.Ordinal) && name.Length > NamePrefix.Length;

    private static CookieOptions OptionsFor(PathString callbackPath, DateTimeOffset? expiresAt) => new()
    {
        HttpOnly = true,
        Secure = true,

        // A top-level GET callback carries it; a cross-site form_post does not, and errors locally.
        SameSite = SameSiteMode.Lax,
        Path = callbackPath.Value,
        Expires = expiresAt,
        IsEssential = true,
    };
}
