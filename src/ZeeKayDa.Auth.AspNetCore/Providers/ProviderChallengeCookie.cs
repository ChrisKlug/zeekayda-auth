using Microsoft.AspNetCore.Http;
using ZeeKayDa.Auth.AspNetCore.Interaction;
using ZeeKayDa.Auth.Authorization;

namespace ZeeKayDa.Auth.AspNetCore.Providers;

/// <summary>
/// Names, to a provider's callback, the interaction a challenge from the login page was issued for:
/// one cookie per challenged interaction, <c>zkd.challenge.&lt;id&gt;</c>, scoped to that provider's
/// callback route, written when the user is sent out and removed when the round trip comes back
/// either way: at <c>/connect/resume</c>, when it sends the user back to the login page, or when
/// a host's own failure event answered the callback.
/// </summary>
/// <remarks>
/// <para>
/// A remote handler hands the failure event its properties — and the interaction stamped into them —
/// only when it reports the failure itself. When it throws instead, as the OAuth handler does for a
/// token endpoint error that is not JSON or for a network failure, they are dropped, and a handler
/// outside ASP.NET Core's remote base never hands them over. This is the generic way back.
/// </para>
/// <para>
/// The cookie proves nothing about the callback: a forged one in a browser mid-challenge can make the
/// login page report a failure that did not happen, and that is accepted, since it changes only the
/// message. It is not a secret and grants nothing either: the identifier already travels in URLs, and
/// it is acted on only for a browser that also carries the interaction's binding. When the callback
/// receives more than one — two tabs challenging the same provider — it cannot tell which tab it
/// belongs to, and names none rather than guess.
/// </para>
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

    /// <summary>
    /// The interaction the request's one challenge cookie names, or <see langword="null"/> when it
    /// carries none, or several.
    /// </summary>
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

        // Lax, as the binding is: the callback is a top-level GET back from the provider. A
        // form_post callback carries neither, and falls back to the local error page.
        SameSite = SameSiteMode.Lax,
        Path = callbackPath.Value,
        Expires = expiresAt,
        IsEssential = true,
    };
}
