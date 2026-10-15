using System.Globalization;
using System.Security.Cryptography;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.AspNetCore.Http;
using ZeeKayDa.Auth.Stores;

namespace ZeeKayDa.Auth.AspNetCore.Interaction;

/// <summary>
/// Binds an interaction to the browser that started it: a cookie per interaction,
/// <c>zkd.interaction.&lt;id&gt;</c>, holding the random secret its store key is derived from and an
/// encrypted hint naming its client.
/// </summary>
/// <remarks>
/// <para>
/// The identifier travels in URLs, which leak; the secret keeps anyone who saw one from acting on
/// the interaction from another browser.
/// </para>
/// <para>
/// An ended interaction leaves a tombstone for <see cref="RetainedFor"/>: secret removed, client
/// hint kept, so a late submission can still be sent back to its client. The hint only selects a
/// registered client; it never carries a destination.
/// </para>
/// </remarks>
internal sealed class InteractionBindingCookie(
    TimeProvider timeProvider,
    IDataProtectionProvider dataProtectionProvider)
{
    /// <summary>The prefix every binding cookie's name starts with; the interaction identifier follows it.</summary>
    internal const string NamePrefix = ZeeKayDaCookies.Interaction + ".";

    /// <summary>
    /// The most binding cookies one browser holds, live and retired together, so planted requests
    /// cannot grow the <c>Cookie</c> header past what proxies accept. Simultaneous requests can
    /// overshoot it by their own count.
    /// </summary>
    internal const int MaxPerBrowser = 10;

    /// <summary>The most retired bindings kept at once; they are always evicted before a live one.</summary>
    internal const int MaxRetired = 3;

    /// <summary>How long a binding is kept after its interaction ends, for its client hint.</summary>
    internal static readonly TimeSpan RetainedFor = TimeSpan.FromDays(1);

    private const char Separator = '.';
    private const char HintSeparator = '|';
    private const string HintPurpose = "ZeeKayDa.Auth:InteractionClientHint";

    private readonly IDataProtector _hintProtector = dataProtectionProvider.CreateProtector(HintPurpose);

    /// <summary>A fresh binding secret: 256 bits from the CSPRNG, Base64Url-encoded.</summary>
    public static string NewSecret() => StoreKeyGenerator.Generate();

    /// <summary>
    /// Writes the binding cookie, lasting until the interaction expires plus, when it names a
    /// client, <see cref="RetainedFor"/>; evicts first when the browser is at the cap.
    /// </summary>
    public void Issue(HttpContext context, IssuedBinding issued)
    {
        ArgumentNullException.ThrowIfNull(context);
        ArgumentNullException.ThrowIfNull(issued);

        var (interactionId, expiresAt, secret, clientId) = issued;
        ArgumentException.ThrowIfNullOrEmpty(interactionId);
        ArgumentException.ThrowIfNullOrEmpty(secret);

        var now = timeProvider.GetUtcNow();
        EvictOldest(context);

        var lifetime = expiresAt - now + (clientId is null ? TimeSpan.Zero : RetainedFor);
        var binding = new Binding(
            now.ToUnixTimeSeconds(),
            secret,
            clientId is null ? string.Empty : ProtectHint(interactionId, clientId, now + lifetime));

        Write(context, interactionId, binding, lifetime);

        // A request that stores an interaction and then ends it must address it before the browser has the cookie.
        context.Items[ItemKey(interactionId)] = binding;
    }

    /// <summary>The live secret bound to <paramref name="interactionId"/>, issued by this request or sent by the browser.</summary>
    public string? Read(HttpContext context, string interactionId)
    {
        ArgumentNullException.ThrowIfNull(context);
        ArgumentException.ThrowIfNullOrEmpty(interactionId);

        return Find(context, interactionId) is { Secret.Length: > 0 } binding ? binding.Secret : null;
    }

    /// <summary>The client a live or retired binding names, if its hint is intact and unexpired.</summary>
    public string? ReadClientId(HttpContext context, string interactionId)
    {
        ArgumentNullException.ThrowIfNull(context);
        ArgumentException.ThrowIfNullOrEmpty(interactionId);

        if (Find(context, interactionId) is not { Hint.Length: > 0 } binding)
            return null;

        string payload;
        try
        {
            payload = HintProtectorFor(interactionId).Unprotect(binding.Hint);
        }
        catch (CryptographicException)
        {
            return null;
        }

        // Judged on the framework's clock: the cookie's max-age is the browser's to honour.
        return TryParseHint(payload, out var expiresAt, out var clientId) && timeProvider.GetUtcNow() < expiresAt
            ? clientId
            : null;
    }

    /// <summary>Removes the binding's secret, leaving a tombstone when it names a client.</summary>
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

        DeleteOldest(context, OtherBindings(context, interactionId).Where(other => !other.IsLive), MaxRetired - 1);

        Write(context, interactionId, binding with { Secret = string.Empty }, RetainedFor);
    }

    /// <summary>Removes every binding cookie the request carries, tombstones included, at sign-out.</summary>
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

    private string ProtectHint(string interactionId, string clientId, DateTimeOffset expiresAt) =>
        HintProtectorFor(interactionId).Protect(
            string.Concat(expiresAt.ToUnixTimeSeconds().ToString(CultureInfo.InvariantCulture), HintSeparator, clientId));

    private static bool TryParseHint(string payload, out DateTimeOffset expiresAt, out string clientId)
    {
        expiresAt = default;
        clientId = string.Empty;

        var separator = payload.IndexOf(HintSeparator);
        if (separator <= 0
            || !long.TryParse(payload.AsSpan(0, separator), NumberStyles.None, CultureInfo.InvariantCulture, out var seconds))
        {
            return false;
        }

        expiresAt = DateTimeOffset.FromUnixTimeSeconds(seconds);
        clientId = payload[(separator + 1)..];
        return clientId.Length > 0;
    }

    // Sealed per interaction, so a hint cannot be lifted into another interaction's cookie.
    private IDataProtector HintProtectorFor(string interactionId) => _hintProtector.CreateProtector(interactionId);

    /// <summary>Makes room for one more binding; an unparseable value counts as the oldest retired one.</summary>
    private static void EvictOldest(HttpContext context)
    {
        var bindings = OtherBindings(context, interactionId: null);
        var retired = bindings.Where(binding => !binding.IsLive).ToArray();
        var keptRetired = DeleteOldest(context, retired, MaxRetired);

        var remaining = bindings.Where(binding => binding.IsLive).Concat(keptRetired).ToArray();
        DeleteOldest(context, remaining, MaxPerBrowser - 1);
    }

    /// <summary>Deletes the oldest, retired before live, until <paramref name="keep"/> remain; returns those kept.</summary>
    private static IEnumerable<CookieBinding> DeleteOldest(HttpContext context, IEnumerable<CookieBinding> bindings, int keep)
    {
        var ordered = bindings.OrderBy(binding => binding.IsLive).ThenBy(binding => binding.IssuedAt).ToArray();
        var excess = Math.Max(ordered.Length - keep, 0);

        foreach (var binding in ordered.Take(excess))
            context.Response.Cookies.Delete(binding.Name, BuildCookieOptions(null));

        return ordered.Skip(excess);
    }

    /// <summary>The binding cookies the request carries, other than <paramref name="interactionId"/>'s.</summary>
    private static CookieBinding[] OtherBindings(HttpContext context, string? interactionId) =>
        [.. context.Request.Cookies
            .Where(cookie => IsBindingCookie(cookie.Key) && cookie.Key != NamePrefix + interactionId)
            .Select(cookie => TryParse(cookie.Value, out var binding)
                ? new CookieBinding(cookie.Key, binding.IssuedAt, binding.Secret.Length > 0)
                : new CookieBinding(cookie.Key, long.MinValue, IsLive: false))];

    private static bool IsBindingCookie(string name) =>
        name.Length > NamePrefix.Length && name.StartsWith(NamePrefix, StringComparison.Ordinal);

    /// <summary>Reads <c>issuedAt.secret.hint</c>, either of the last two possibly empty, not both.</summary>
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
        // Even behind a TLS-terminating proxy without UseForwardedHeaders.
        Secure = true,
        // Survives a top-level GET back from an external identity provider.
        SameSite = SameSiteMode.Lax,
        // The host's pages read it, wherever the host put them.
        Path = "/",
        MaxAge = maxAge,
        IsEssential = true,
    };

    /// <summary>A binding to write, naming <c>ClientId</c> in its hint when there is one.</summary>
    internal sealed record IssuedBinding(string InteractionId, DateTimeOffset ExpiresAt, string Secret, string? ClientId);

    /// <summary>A binding as the cookie holds it: when it was issued, its secret, and its client hint.</summary>
    private sealed record Binding(long IssuedAt, string Secret, string Hint);

    /// <summary>A binding cookie the request carries, as eviction sees it.</summary>
    private sealed record CookieBinding(string Name, long IssuedAt, bool IsLive);
}
