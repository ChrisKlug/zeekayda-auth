namespace ZeeKayDa.Auth.AspNetCore.Interaction;

/// <summary>
/// The cookies ZeeKayDa.Auth owns, each name also its handler's scheme name where one backs it.
/// A host scheme taking one fails at startup: sharing would let host-written claims in.
/// </summary>
internal static class ZeeKayDaCookies
{
    /// <summary>The SSO session. Written at sign-in promotion; the session <em>is</em> this cookie.</summary>
    public const string Session = "zkd.session";

    /// <summary>The prefix of the per-interaction binding cookies, <c>zkd.interaction.&lt;id&gt;</c>.</summary>
    public const string Interaction = "zkd.interaction";

    /// <summary>The raw provider callback, for seconds; public as <see cref="ZeeKayDaSchemes.External"/>.</summary>
    public const string External = ZeeKayDaSchemes.External;

    /// <summary>Never written as a cookie; names the ticket a parked principal is serialised as.</summary>
    public const string Pending = "zkd.pending";

    /// <summary>
    /// The prefix of the challenge cookies, <c>zkd.challenge.&lt;id&gt;</c>, scoped to the provider's
    /// callback route so a failed callback can find its way back to the login page.
    /// </summary>
    public const string Challenge = "zkd.challenge";

    /// <summary>Every reserved name, whether or not a scheme backs it.</summary>
    public static readonly string[] ReservedNames = [Session, Interaction, External, Pending, Challenge];

    /// <summary>
    /// The reserved names the framework registers as schemes; the startup check skips only these,
    /// so a host scheme taking any other reserved name still fails.
    /// </summary>
    public static readonly string[] SchemeNames = [Session, External];
}
