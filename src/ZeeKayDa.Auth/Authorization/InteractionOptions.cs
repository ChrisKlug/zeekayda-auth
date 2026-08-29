namespace ZeeKayDa.Auth.Authorization;

/// <summary>
/// Paths of the host-owned interaction pages the authorization flow hands off to. ZeeKayDa owns
/// no interaction UI; each configured path is a page the host application builds and drives
/// through the corresponding interaction service.
/// </summary>
public sealed class InteractionOptions
{
    /// <summary>
    /// Gets or sets the host-relative path of the host's error page for authorization requests
    /// whose errors cannot be redirected to the client (phase-1 validation failures — unknown
    /// client or unregistered redirect URI). When <see langword="null"/> (the default), the
    /// framework renders a minimal unbranded error response itself.
    /// </summary>
    /// <remarks>
    /// Must be an absolute path within the host application (starting with <c>/</c>), without
    /// scheme, authority, query, or fragment. The redirect to this page carries only an opaque
    /// error identifier — the error details are read server-side via the error interaction
    /// service, never from the query string, which would leak into proxy logs and browser
    /// history.
    /// </remarks>
    public string? ErrorPath { get; set; }

    /// <summary>
    /// Gets or sets the host-relative path of the host's login page. The framework redirects an
    /// authorization request that needs authentication here, and the page completes the flow by
    /// calling <c>ILoginInteraction.SignInAsync</c>. When <see langword="null"/> (the default),
    /// an authorization request that needs local authentication fails with a local error.
    /// </summary>
    /// <remarks>
    /// <para>
    /// Must be an absolute path within the host application (starting with <c>/</c>), without
    /// scheme, authority, query, or fragment.
    /// </para>
    /// <para>
    /// The redirect carries one query parameter, <c>zkd_i</c>, identifying the interaction being
    /// resumed. The login page must preserve it across its own form post — a
    /// <c>&lt;form method="post"&gt;</c> with no <c>action</c> does so by default, because the
    /// browser posts to the current URL including its query string. A form that regenerates the
    /// URL from routing (<c>asp-page</c>, <c>asp-controller</c>) drops it, and must pass it back
    /// explicitly with <c>asp-route-zkd_i</c>.
    /// </para>
    /// </remarks>
    public string? LoginPath { get; set; }
}
