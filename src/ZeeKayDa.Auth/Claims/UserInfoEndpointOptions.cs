namespace ZeeKayDa.Auth.Claims;

/// <summary>
/// UserInfo endpoint configuration options.
/// </summary>
public sealed class UserInfoEndpointOptions
{
    /// <summary>
    /// Gets or sets an explicit override for the <c>userinfo_endpoint</c> URI published in the
    /// discovery document. When <see langword="null"/>, the value is derived from the issuer.
    /// </summary>
    /// <remarks>
    /// Must be an absolute URI sharing the issuer's authority, with no query or fragment: the
    /// route matches on the path alone, so a query could never be honoured. The browser origins
    /// allowed to read the response are <see cref="AuthorizationServerOptions.CorsOrigins"/>,
    /// shared with the discovery and JWKS endpoints.
    /// </remarks>
    public string? Uri { get; set; }
}
