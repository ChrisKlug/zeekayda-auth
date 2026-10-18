using ZeeKayDa.Auth.Configuration;

namespace ZeeKayDa.Auth.Authorization;

/// <summary>
/// End-session endpoint options (OpenID Connect RP-Initiated Logout 1.0) and the host pages sign-out
/// hands off to. Served only with <see cref="GrantType.AuthorizationCode"/>, the one flow that signs a user in.
/// </summary>
public sealed class EndSessionEndpointOptions
{
    private string? _uri;
    private string? _logoutPath;
    private string? _signedOutPath;
    private bool _frozen;

    /// <summary>
    /// Gets or sets an explicit override for the <c>end_session_endpoint</c> URI published in the
    /// discovery document. When <see langword="null"/>, the value is derived from the issuer.
    /// </summary>
    public string? Uri
    {
        get => _uri;
        set => _uri = FrozenOptions.Assign(_frozen, value, "AuthorizationServerOptions.EndSessionEndpoint.Uri");
    }

    /// <summary>
    /// Gets or sets the path of the host's logout page, where the user confirms a sign-out by
    /// calling <c>LogoutInteraction.SignOutAsync</c>. When <see langword="null"/> (the default),
    /// the framework renders a minimal page.
    /// </summary>
    /// <remarks>
    /// Must be an absolute path within the host application, without scheme, authority, query or
    /// fragment. The redirect carries <c>zkd_i</c> on the same terms as <see cref="InteractionOptions.LoginPath"/>.
    /// </remarks>
    public string? LogoutPath
    {
        get => _logoutPath;
        set => _logoutPath = FrozenOptions.Assign(_frozen, value, "AuthorizationServerOptions.EndSessionEndpoint.LogoutPath");
    }

    /// <summary>
    /// Gets or sets the path of the page a signed-out user lands on when there is no client to
    /// return to. When <see langword="null"/> (the default), the framework renders a minimal page.
    /// </summary>
    /// <remarks>
    /// Must be an absolute path within the host application, without scheme, authority, query or
    /// fragment. The redirect carries nothing, so the page can be static.
    /// </remarks>
    public string? SignedOutPath
    {
        get => _signedOutPath;
        set => _signedOutPath = FrozenOptions.Assign(_frozen, value, "AuthorizationServerOptions.EndSessionEndpoint.SignedOutPath");
    }

    /// <summary>Refuses any later change to these options.</summary>
    internal void Freeze() => _frozen = true;
}
