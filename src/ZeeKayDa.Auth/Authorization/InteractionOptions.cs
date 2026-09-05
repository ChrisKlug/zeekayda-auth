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
    /// a host with <see cref="SupportsLocalSignIn"/> off and exactly one external provider sends
    /// the request straight to that provider; any other host needs the page, is warned at
    /// startup, and answers the client with <c>server_error</c>.
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

    /// <summary>
    /// Gets or sets the host-relative path of the host's consent page. The framework redirects an
    /// authenticated authorization request here when the client requires consent, and the page
    /// completes the flow by calling <c>IConsentInteraction.GrantAsync</c> or
    /// <c>IConsentInteraction.DenyAsync</c>. When <see langword="null"/> (the default), a request
    /// for a client that requires consent answers the client with <c>server_error</c> and logs
    /// an error naming this option.
    /// </summary>
    /// <remarks>
    /// <para>
    /// Must be an absolute path within the host application (starting with <c>/</c>), without
    /// scheme, authority, query, or fragment.
    /// </para>
    /// <para>
    /// The redirect carries the same <c>zkd_i</c> query parameter as <see cref="LoginPath"/>, and
    /// the consent page must preserve it across its own form post on the same terms.
    /// </para>
    /// <para>
    /// There is no startup warning for a missing consent page: whether one is needed depends on
    /// the registered clients, which the framework does not enumerate at startup. A host whose
    /// clients all set <c>RequireConsent</c> to <see langword="false"/> never needs the page.
    /// </para>
    /// </remarks>
    public string? ConsentPath { get; set; }

    /// <summary>
    /// Gets or sets whether the host's login page signs users in itself, with a credential form
    /// whose handler calls <c>ILoginInteraction.SignInAsync</c>. Defaults to <see langword="true"/>.
    /// Set it to <see langword="false"/> for a host that authenticates only through external
    /// providers; with exactly one provider registered and no <see cref="LoginPath"/>, an
    /// authorization request is then sent straight to that provider.
    /// </summary>
    /// <remarks>
    /// Local sign-in is a flag rather than a provider because it shares nothing with the
    /// redirect-out-and-back lifecycle of an external provider. A host with local sign-in off and
    /// no providers has no way to authenticate anyone, and fails at startup saying so.
    /// </remarks>
    public bool SupportsLocalSignIn { get; set; } = true;
}
