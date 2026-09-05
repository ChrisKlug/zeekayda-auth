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

    /// <summary>
    /// The raw provider callback, before ZeeKayDa reads it. Lives for seconds. The one name a
    /// host may need, to configure a handler the framework cannot, so it is public as
    /// <see cref="ZeeKayDaSchemes.External"/>.
    /// </summary>
    public const string External = ZeeKayDaSchemes.External;

    /// <summary>A half-authenticated external principal, single-use and bound to its interaction.</summary>
    public const string Pending = "zkd.pending";

    /// <summary>
    /// Every reserved name, whether or not a scheme backs it. A name is reserved because the
    /// framework uses it, not because a scheme registers it — <see cref="Interaction"/> is written
    /// directly and has no scheme, and a host taking that name collides just as squarely as one
    /// taking <see cref="Session"/>. Startup is a better place to learn that than production.
    /// </summary>
    public static readonly string[] ReservedNames = [Session, Interaction, External, Pending];

    /// <summary>
    /// The reserved names that are also authentication scheme names. <see cref="Interaction"/> is
    /// absent: it carries protocol state rather than a principal, so it is a Data-Protection
    /// payload written directly and no scheme backs it. Keeping the two lists apart is what lets
    /// the startup check skip the framework's own schemes without also skipping a host scheme that
    /// took the one reserved name the framework never registers.
    /// </summary>
    public static readonly string[] SchemeNames = [Session, External, Pending];
}
