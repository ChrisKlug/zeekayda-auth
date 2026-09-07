using System.Globalization;
using Microsoft.AspNetCore.Http;
using ZeeKayDa.Auth.Stores;

namespace ZeeKayDa.Auth.AspNetCore.Interaction;

/// <summary>
/// Binds an interaction to the browser that started it: one small cookie per interaction, named
/// <c>zkd.interaction.&lt;id&gt;</c>, holding a random secret that the store key for the
/// interaction is derived from.
/// </summary>
/// <remarks>
/// <para>
/// The interaction identifier travels in a URL, and URLs leak — into <c>Referer</c> headers,
/// browser history and request logs. Without the cookie, anyone who saw the URL could act on the
/// interaction from their own browser. The value is a secret rather than a marker for the same
/// reason: a fixed value could be set by hand in another browser once the identifier is known.
/// </para>
/// <para>
/// One cookie per interaction rather than one per browser, so each dies with its own interaction
/// and concurrent tabs share nothing. The count is capped: an authorize request that finds the
/// cap already reached evicts the oldest before writing its own, so a run of abandoned or planted
/// requests cannot grow the browser's <c>Cookie</c> header past what proxies accept.
/// </para>
/// </remarks>
internal sealed class InteractionBindingCookie
{
    /// <summary>The prefix every binding cookie's name starts with; the interaction identifier follows it.</summary>
    internal const string NamePrefix = ZeeKayDaCookies.Interaction + ".";

    /// <summary>
    /// The most binding cookies one browser accumulates in sequence. Generous for a person — two or
    /// three tabs is a busy sign-in — and, at under a hundred bytes each, a header cost of about
    /// 1 KB. Enforced per response from the request's own cookies, so requests made simultaneously
    /// overshoot it by their own count; that is a user's tabs, since a browser stores these cookies
    /// only from a top-level navigation and cross-site content cannot make several at once.
    /// </summary>
    internal const int MaxPerBrowser = 10;

    private const char Separator = '.';

    private readonly TimeProvider _timeProvider;

    public InteractionBindingCookie(TimeProvider timeProvider)
    {
        ArgumentNullException.ThrowIfNull(timeProvider);

        _timeProvider = timeProvider;
    }

    /// <summary>A fresh binding secret: 256 bits from the CSPRNG, Base64Url-encoded.</summary>
    public static string NewSecret() => StoreKeyGenerator.Generate();

    /// <summary>
    /// Writes the binding cookie for <paramref name="interactionId"/> carrying
    /// <paramref name="secret"/>, expiring at <paramref name="expiresAt"/>. Evicts the oldest
    /// bindings first when the browser already holds the maximum.
    /// </summary>
    public void Issue(HttpContext context, string interactionId, DateTimeOffset expiresAt, string secret)
    {
        ArgumentNullException.ThrowIfNull(context);
        ArgumentException.ThrowIfNullOrEmpty(interactionId);
        ArgumentException.ThrowIfNullOrEmpty(secret);

        var now = _timeProvider.GetUtcNow();
        EvictOldest(context);

        var value = string.Concat(now.ToUnixTimeSeconds().ToString(CultureInfo.InvariantCulture), Separator, secret);
        context.Response.Cookies.Append(NamePrefix + interactionId, value, BuildCookieOptions(expiresAt - now));
    }

    /// <summary>The secret bound to <paramref name="interactionId"/> in this request, or <see langword="null"/> when the browser holds none.</summary>
    public string? Read(HttpContext context, string interactionId)
    {
        ArgumentNullException.ThrowIfNull(context);
        ArgumentException.ThrowIfNullOrEmpty(interactionId);

        return context.Request.Cookies.TryGetValue(NamePrefix + interactionId, out var value)
            && TryParse(value, out _, out var secret)
            ? secret
            : null;
    }

    /// <summary>Removes the binding cookie for <paramref name="interactionId"/>.</summary>
    public void Delete(HttpContext context, string interactionId)
    {
        ArgumentNullException.ThrowIfNull(context);
        ArgumentException.ThrowIfNullOrEmpty(interactionId);

        context.Response.Cookies.Delete(NamePrefix + interactionId, BuildCookieOptions(null));
    }

    /// <summary>
    /// Deletes enough of the oldest bindings the request carries that one more fits under the
    /// cap. A value that does not parse counts as the oldest of all: whatever wrote it, it is not
    /// one this framework can use.
    /// </summary>
    private void EvictOldest(HttpContext context)
    {
        var bindings = context.Request.Cookies
            .Where(cookie => IsBindingCookie(cookie.Key))
            .Select(cookie => (Name: cookie.Key, IssuedAt: IssuedAtOf(cookie.Value)))
            .OrderBy(binding => binding.IssuedAt)
            .ToArray();

        var excess = bindings.Length - MaxPerBrowser + 1;
        foreach (var (name, _) in bindings.Take(Math.Max(excess, 0)))
            context.Response.Cookies.Delete(name, BuildCookieOptions(null));
    }

    private static bool IsBindingCookie(string name) =>
        name.Length > NamePrefix.Length && name.StartsWith(NamePrefix, StringComparison.Ordinal);

    private static long IssuedAtOf(string value) => TryParse(value, out var issuedAt, out _) ? issuedAt : long.MinValue;

    private static bool TryParse(string? value, out long issuedAt, out string secret)
    {
        issuedAt = 0;
        secret = string.Empty;

        if (value is null)
            return false;

        var separator = value.IndexOf(Separator);
        if (separator <= 0 || separator == value.Length - 1)
            return false;

        if (!long.TryParse(value.AsSpan(0, separator), NumberStyles.None, CultureInfo.InvariantCulture, out issuedAt))
            return false;

        secret = value[(separator + 1)..];
        return true;
    }

    private static CookieOptions BuildCookieOptions(TimeSpan? maxAge) => new()
    {
        HttpOnly = true,
        // Unconditionally Secure: the route group already refuses non-HTTPS except loopback, and a
        // TLS-terminating proxy without UseForwardedHeaders must not silently downgrade the
        // cookie.
        Secure = true,
        // Lax, not Strict: the interaction has to survive a top-level GET back from an external
        // identity provider. Not None — nothing here is read from a cross-site POST.
        SameSite = SameSiteMode.Lax,
        // Root path: the host's own login and consent pages read this, and they live wherever the
        // host put them.
        Path = "/",
        MaxAge = maxAge,
        IsEssential = true,
    };
}
