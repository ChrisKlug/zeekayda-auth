namespace ZeeKayDa.Auth.Authorization;

/// <summary>
/// End-session endpoint configuration options: where a relying party sends the user to sign out
/// (OpenID Connect RP-Initiated Logout 1.0), and the host pages that sign-out hands off to.
/// </summary>
/// <remarks>
/// The endpoint is served, and advertised as <c>end_session_endpoint</c>, only on a host whose
/// <see cref="AuthorizationServerOptions.GrantTypesSupported"/> contains
/// <see cref="GrantType.AuthorizationCode"/>: that flow is the only one that signs a user in, so
/// without it there is no session to end.
/// </remarks>
public sealed class EndSessionEndpointOptions
{
    /// <summary>
    /// Gets or sets an explicit override for the <c>end_session_endpoint</c> URI published in the
    /// discovery document. When <see langword="null"/>, the value is derived from the issuer.
    /// </summary>
    public string? Uri { get; set; }

    /// <summary>
    /// Gets or sets the host-relative path of the host's logout page, where the user confirms a
    /// sign-out. The framework redirects a sign-out that must be confirmed here, and the page
    /// completes it by calling <c>ILogoutInteraction.SignOutAsync</c>. When
    /// <see langword="null"/> (the default), the framework renders a minimal unbranded
    /// confirmation page itself.
    /// </summary>
    /// <remarks>
    /// <para>
    /// Must be an absolute path within the host application (starting with <c>/</c>), without
    /// scheme, authority, query, or fragment.
    /// </para>
    /// <para>
    /// The redirect carries one query parameter, <c>zkd_i</c>, identifying the sign-out being
    /// confirmed, and the page must preserve it across its own form post on the same terms as
    /// the login page: a <c>&lt;form method="post"&gt;</c> with no <c>action</c> does so by
    /// default.
    /// </para>
    /// </remarks>
    public string? LogoutPath { get; set; }

    /// <summary>
    /// Gets or sets the host-relative path of the page the user lands on once signed out, when
    /// there is no client to send them back to. When <see langword="null"/> (the default), the
    /// framework renders a minimal unbranded page itself.
    /// </summary>
    /// <remarks>
    /// Must be an absolute path within the host application (starting with <c>/</c>), without
    /// scheme, authority, query, or fragment. The redirect carries nothing, so the page can be
    /// static; it needs no interaction service.
    /// </remarks>
    public string? SignedOutPath { get; set; }
}
