using System.Globalization;
using System.Security.Cryptography;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.AspNetCore.Http;
using ZeeKayDa.Auth.Stores;

namespace ZeeKayDa.Auth.AspNetCore.Interaction;

/// <summary>
/// Binds an interaction to the browser that started it: one small cookie per interaction, named
/// <c>zkd.interaction.&lt;id&gt;</c>, holding a random secret that the store key for the
/// interaction is derived from, and an encrypted hint naming the client the interaction is for.
/// </summary>
/// <remarks>
/// <para>
/// The interaction identifier travels in a URL, and URLs leak — into <c>Referer</c> headers,
/// browser history and request logs. Without the cookie, anyone who saw the URL could act on the
/// interaction from their own browser. The value is a secret rather than a marker for the same
/// reason: a fixed value could be set by hand in another browser once the identifier is known.
/// </para>
/// <para>
/// The cookie outlives its interaction by <see cref="RetainedFor"/>, and an interaction that ends
/// leaves it behind as a tombstone: the secret removed, the client hint kept. A page submitted
/// for an interaction that expired or already completed can then still say which client the user
/// came from, so the framework can send them back to it rather than to a dead end. The hint only
/// ever selects a registered client; it never carries a destination.
/// </para>
/// <para>
/// One cookie per interaction rather than one per browser, so concurrent tabs share nothing. The
/// count is capped: an authorize request that finds the cap already reached evicts the oldest
/// before writing its own, so a run of abandoned or planted requests cannot grow the browser's
/// <c>Cookie</c> header past what proxies accept.
/// </para>
/// </remarks>
internal sealed class InteractionBindingCookie
{
    /// <summary>The prefix every binding cookie's name starts with; the interaction identifier follows it.</summary>
    internal const string NamePrefix = ZeeKayDaCookies.Interaction + ".";

    /// <summary>
    /// The most binding cookies one browser accumulates in sequence. Generous for a person — two or
    /// three tabs is a busy sign-in — and, at about two hundred bytes each, a header cost of about
    /// 2 KB. Enforced per response from the request's own cookies, so requests made simultaneously
    /// overshoot it by their own count; that is a user's tabs, since a browser stores these cookies
    /// only from a top-level navigation and cross-site content cannot make several at once.
    /// </summary>
    internal const int MaxPerBrowser = 10;

    /// <summary>How long a binding is kept after its interaction ends, for its client hint.</summary>
    internal static readonly TimeSpan RetainedFor = TimeSpan.FromDays(1);

    private const char Separator = '.';
    private const string HintPurpose = "ZeeKayDa.Auth:InteractionClientHint";

    private readonly TimeProvider _timeProvider;
    private readonly IDataProtector _hintProtector;

    public InteractionBindingCookie(TimeProvider timeProvider, IDataProtectionProvider dataProtectionProvider)
    {
        ArgumentNullException.ThrowIfNull(timeProvider);
        ArgumentNullException.ThrowIfNull(dataProtectionProvider);

        _timeProvider = timeProvider;
        _hintProtector = dataProtectionProvider.CreateProtector(HintPurpose);
    }

    /// <summary>A fresh binding secret: 256 bits from the CSPRNG, Base64Url-encoded.</summary>
    public static string NewSecret() => StoreKeyGenerator.Generate();

    /// <summary>
    /// Writes the binding cookie for <paramref name="interactionId"/> carrying
    /// <paramref name="secret"/> and, when there is one, a hint naming <paramref name="clientId"/>.
    /// The cookie lasts until <paramref name="expiresAt"/> plus <see cref="RetainedFor"/>. Evicts the
    /// oldest bindings first when the browser already holds the maximum.
    /// </summary>
    public void Issue(HttpContext context, string interactionId, DateTimeOffset expiresAt, string secret, string? clientId)
    {
        ArgumentNullException.ThrowIfNull(context);
        ArgumentException.ThrowIfNullOrEmpty(interactionId);
        ArgumentException.ThrowIfNullOrEmpty(secret);

        var now = _timeProvider.GetUtcNow();
        EvictOldest(context);

        var lifetime = expiresAt - now + RetainedFor;
        var binding = new Binding(
            now.ToUnixTimeSeconds(),
            secret,
            clientId is null ? string.Empty : ProtectHint(interactionId, clientId, lifetime));

        Write(context, interactionId, binding, lifetime);

        // The browser has not seen the cookie yet. A request that stores an interaction and then
        // ends it — prompt=none with no session, a configuration gap — must still be able to
        // address the entry it just wrote, so the binding stays with the request as well.
        context.Items[ItemKey(interactionId)] = binding;
    }

    /// <summary>
    /// The secret bound to <paramref name="interactionId"/>: the one this request issued, or the
    /// one the browser sent. <see langword="null"/> when there is neither, or the binding is a
    /// tombstone.
    /// </summary>
    public string? Read(HttpContext context, string interactionId)
    {
        ArgumentNullException.ThrowIfNull(context);
        ArgumentException.ThrowIfNullOrEmpty(interactionId);

        return Find(context, interactionId) is { Secret.Length: > 0 } binding ? binding.Secret : null;
    }

    /// <summary>
    /// The client the binding for <paramref name="interactionId"/> names, live or retired.
    /// <see langword="null"/> when there is no binding, it names no client, or its hint cannot be
    /// read — expired, tampered with, or sealed for another interaction.
    /// </summary>
    public string? ReadClientId(HttpContext context, string interactionId)
    {
        ArgumentNullException.ThrowIfNull(context);
        ArgumentException.ThrowIfNullOrEmpty(interactionId);

        if (Find(context, interactionId) is not { Hint.Length: > 0 } binding)
            return null;

        try
        {
            return HintProtectorFor(interactionId).Unprotect(binding.Hint);
        }
        catch (CryptographicException)
        {
            return null;
        }
    }

    /// <summary>
    /// Ends the binding for <paramref name="interactionId"/>: the secret is removed, so nothing can
    /// address the interaction through it again. A binding that names a client is left behind as a
    /// tombstone for <see cref="RetainedFor"/>; one that names none is deleted.
    /// </summary>
    public void Retire(HttpContext context, string interactionId)
    {
        ArgumentNullException.ThrowIfNull(context);
        ArgumentException.ThrowIfNullOrEmpty(interactionId);

        var binding = Find(context, interactionId);
        context.Items.Remove(ItemKey(interactionId));

        if (binding is not { Hint.Length: > 0 })
        {
            context.Response.Cookies.Delete(NamePrefix + interactionId, BuildCookieOptions(null));
            return;
        }

        // The hint was sealed to expire with the cookie it was issued in; a tombstone lasts no
        // longer than that, so a retirement cannot extend what the hint is good for.
        Write(context, interactionId, binding with { Secret = string.Empty }, RetainedFor);
    }

    /// <summary>
    /// Removes every binding cookie the request carries, tombstones included. Signing out ends
    /// whatever this browser still has in flight, so no interaction outlives the session it may
    /// have been started on.
    /// </summary>
    public static void DeleteAll(HttpContext context)
    {
        ArgumentNullException.ThrowIfNull(context);

        foreach (var name in context.Request.Cookies.Keys.Where(IsBindingCookie))
            context.Response.Cookies.Delete(name, BuildCookieOptions(null));
    }

    private static string ItemKey(string interactionId) => "ZeeKayDa.Auth:Binding:" + interactionId;

    private static Binding? Find(HttpContext context, string interactionId)
    {
        if (context.Items.TryGetValue(ItemKey(interactionId), out var issued) && issued is Binding issuedBinding)
            return issuedBinding;

        return context.Request.Cookies.TryGetValue(NamePrefix + interactionId, out var value)
            && TryParse(value, out var binding)
            ? binding
            : null;
    }

    private static void Write(HttpContext context, string interactionId, Binding binding, TimeSpan maxAge)
    {
        var value = string.Join(
            Separator,
            binding.IssuedAt.ToString(CultureInfo.InvariantCulture),
            binding.Secret,
            binding.Hint);

        context.Response.Cookies.Append(NamePrefix + interactionId, value, BuildCookieOptions(maxAge));
    }

    // The data protector measures the lifetime on its own clock, so it is passed as a duration.
    private string ProtectHint(string interactionId, string clientId, TimeSpan lifetime) =>
        HintProtectorFor(interactionId).Protect(clientId, lifetime);

    // Sealed per interaction, so a hint cannot be lifted into another interaction's cookie.
    private ITimeLimitedDataProtector HintProtectorFor(string interactionId) =>
        _hintProtector.CreateProtector(interactionId).ToTimeLimitedDataProtector();

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

    private static long IssuedAtOf(string value) => TryParse(value, out var binding) ? binding.IssuedAt : long.MinValue;

    /// <summary>
    /// Reads <c>issuedAt.secret.hint</c>. The secret is empty on a tombstone and the hint empty when
    /// the binding names no client; a value with neither is not one this framework writes.
    /// </summary>
    private static bool TryParse(string? value, out Binding binding)
    {
        binding = default!;

        if (value?.Split(Separator) is not [var issuedAtText, var secret, var hint])
            return false;

        if (!long.TryParse(issuedAtText, NumberStyles.None, CultureInfo.InvariantCulture, out var issuedAt))
            return false;

        if (secret.Length == 0 && hint.Length == 0)
            return false;

        binding = new Binding(issuedAt, secret, hint);
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

    /// <summary>A binding as the cookie holds it: when it was issued, its secret, and its client hint.</summary>
    private sealed record Binding(long IssuedAt, string Secret, string Hint);
}
