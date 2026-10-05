using Microsoft.AspNetCore.Http;
using ZeeKayDa.Auth.AspNetCore.Interaction;

namespace ZeeKayDa.Auth.AspNetCore.Providers;

/// <summary>
/// Names, to a provider's callback, the interaction its challenge was issued for: a cookie scoped
/// to that provider's callback route, written when the user is sent out and removed when they
/// come back.
/// </summary>
/// <remarks>
/// <para>
/// A remote handler surfaces its properties — and the interaction stamped into them — only for a
/// refusal. A failure, a token exchange that fails after the provider redirected back among them,
/// arrives with none, and without this the framework could not say which login page to return the
/// user to.
/// </para>
/// <para>
/// The value is not a secret and grants nothing: the identifier already travels in URLs, and it
/// is acted on only for a browser that also carries the interaction's binding, only to send the
/// user back to the login page with the interaction left alive. Two tabs challenging the same
/// provider share one cookie, the later one's, which is why a refusal's own properties are
/// preferred when there are some.
/// </para>
/// </remarks>
internal static class ProviderChallengeCookie
{
    public static void Issue(HttpContext context, PathString callbackPath, string interactionId, DateTimeOffset expiresAt)
    {
        ArgumentNullException.ThrowIfNull(context);
        ArgumentException.ThrowIfNullOrEmpty(interactionId);

        context.Response.Cookies.Append(ZeeKayDaCookies.Challenge, interactionId, OptionsFor(callbackPath, expiresAt));
    }

    /// <summary>
    /// The interaction the cookie names, or <see langword="null"/> without one, and the cookie
    /// removed either way: it is read once, on the callback it was written for.
    /// </summary>
    public static string? Take(HttpContext context)
    {
        ArgumentNullException.ThrowIfNull(context);

        if (!context.Request.Cookies.TryGetValue(ZeeKayDaCookies.Challenge, out var interactionId))
            return null;

        context.Response.Cookies.Delete(ZeeKayDaCookies.Challenge, OptionsFor(context.Request.PathBase.Add(context.Request.Path), null));
        return string.IsNullOrEmpty(interactionId) ? null : interactionId;
    }

    private static CookieOptions OptionsFor(PathString callbackPath, DateTimeOffset? expiresAt) => new()
    {
        HttpOnly = true,
        Secure = true,

        // Lax, as the binding is: the callback is a top-level GET back from the provider. A
        // form_post callback carries neither, and falls back to the local error page.
        SameSite = SameSiteMode.Lax,
        Path = callbackPath.Value,
        Expires = expiresAt,
        IsEssential = true,
    };
}
