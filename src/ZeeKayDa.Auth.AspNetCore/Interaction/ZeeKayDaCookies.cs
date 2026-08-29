namespace ZeeKayDa.Auth.AspNetCore.Interaction;

/// <summary>
/// The cookies ZeeKayDa.Auth owns. Each name is both the cookie's name and, where the cookie is
/// backed by a cookie authentication handler, that handler's scheme name.
/// </summary>
/// <remarks>
/// <para>
/// All four names are reserved: a host that registers a cookie authentication scheme using one of
/// them fails at startup rather than silently sharing a cookie with the framework. Sharing would
/// let host-written claims arrive where the framework expects only its own.
/// </para>
/// <para>
/// Host code never names any of these. The framework registers the schemes, writes the cookies,
/// and reads them back through the interaction services — which is what keeps scheme names,
/// callback paths and <c>ReturnUrl</c> out of a host's login page.
/// </para>
/// </remarks>
internal static class ZeeKayDaCookies
{
    /// <summary>The SSO session. Written at sign-in promotion; the session <em>is</em> this cookie.</summary>
    public const string Session = "zkd.session";

    /// <summary>The authorization request context, carried across the flow's redirects.</summary>
    public const string Interaction = "zkd.interaction";

    /// <summary>The raw provider callback, before ZeeKayDa reads it. Lives for seconds.</summary>
    public const string External = "zkd.external";

    /// <summary>A half-authenticated external principal, single-use and bound to its interaction.</summary>
    public const string Pending = "zkd.pending";

    /// <summary>
    /// Every reserved name, including the two whose schemes are not registered until the external
    /// provider leg lands. A name is reserved because the framework will use it, not because it
    /// already does — a host that takes <c>zkd.external</c> today would break on upgrade, and
    /// startup is a better place to learn that than production.
    /// </summary>
    public static readonly string[] ReservedNames = [Session, Interaction, External, Pending];
}
