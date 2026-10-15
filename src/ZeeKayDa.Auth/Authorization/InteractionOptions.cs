namespace ZeeKayDa.Auth.Authorization;

/// <summary>
/// Paths of the host-owned pages the authorization flow hands off to.
/// </summary>
public sealed class InteractionOptions
{
    /// <summary>
    /// Gets or sets the path of the host's error page for authorization errors that cannot be redirected
    /// to the client. When <see langword="null"/> (the default), the framework renders a minimal page.
    /// </summary>
    /// <remarks>
    /// Must be an absolute path within the host application, without scheme, authority, query or fragment. The redirect carries only an opaque error identifier; the page reads the details
    /// through the error interaction service, keeping them out of proxy logs and browser history.
    /// </remarks>
    public string? ErrorPath { get; set; }

    /// <summary>
    /// Gets or sets the path of the host's login page, which completes the flow by calling
    /// <c>LoginInteraction.SignInAsync</c>. Defaults to <c>/login</c>; the host still has to serve it.
    /// </summary>
    /// <remarks>
    /// <para>
    /// Must be an absolute path within the host application, without scheme, authority, query or fragment. Not used when <see cref="SupportsLocalSignIn"/> is off and exactly one external
    /// provider is registered. When <see langword="null"/> otherwise, startup warns and the client gets <c>server_error</c>.
    /// </para>
    /// <para>
    /// The redirect carries a <c>zkd_i</c> query parameter the page must keep across its form post. A
    /// <c>&lt;form method="post"&gt;</c> with no <c>action</c> keeps it; one built from routing
    /// (<c>asp-page</c>, <c>asp-controller</c>) needs <c>asp-route-zkd_i</c>.
    /// </para>
    /// </remarks>
    public string? LoginPath { get; set; } = "/login";

    /// <summary>
    /// Gets or sets the path of the host's consent page, which completes the flow by calling
    /// <c>ConsentInteraction.GrantAsync</c> or <c>ConsentInteraction.DenyAsync</c>. Defaults to
    /// <c>/consent</c>; the host still has to serve it if any client requires consent.
    /// </summary>
    /// <remarks>
    /// Must be an absolute path within the host application, without scheme, authority, query or fragment. The redirect carries <c>zkd_i</c> on the same terms as <see cref="LoginPath"/>. When
    /// <see langword="null"/>, a client that requires consent gets <c>server_error</c>; there is no startup
    /// warning, because the framework does not enumerate clients at startup.
    /// </remarks>
    public string? ConsentPath { get; set; } = "/consent";

    /// <summary>
    /// Gets or sets whether the host's login page signs users in itself through
    /// <c>LoginInteraction.SignInAsync</c>. Defaults to <see langword="true"/>; set it to
    /// <see langword="false"/> for a host that authenticates only through external providers.
    /// </summary>
    /// <remarks>
    /// With it off and no providers registered, nobody can authenticate, so startup fails.
    /// </remarks>
    public bool SupportsLocalSignIn { get; set; } = true;
}
