using ZeeKayDa.Auth.Configuration;

namespace ZeeKayDa.Auth.Claims;

/// <summary>
/// UserInfo endpoint configuration options.
/// </summary>
public sealed class UserInfoEndpointOptions
{
    private string? _uri;
    private bool _frozen;

    /// <summary>
    /// Gets or sets an explicit override for the <c>userinfo_endpoint</c> URI published in the
    /// discovery document. When <see langword="null"/>, the value is derived from the issuer.
    /// </summary>
    /// <remarks>
    /// Absolute, on the issuer's authority, with no query or fragment, since the route matches on path alone.
    /// CORS origins come from <see cref="AuthorizationServerOptions.CorsOrigins"/>.
    /// </remarks>
    public string? Uri
    {
        get => _uri;
        set => _uri = FrozenOptions.Assign(_frozen, value, "AuthorizationServerOptions.UserInfoEndpoint.Uri");
    }

    /// <summary>Refuses any later change to these options.</summary>
    internal void Freeze() => _frozen = true;
}
