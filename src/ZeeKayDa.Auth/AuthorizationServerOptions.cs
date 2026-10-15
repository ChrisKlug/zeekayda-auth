using ZeeKayDa.Auth.Authorization;
using ZeeKayDa.Auth.Claims;
using ZeeKayDa.Auth.Configuration;
using ZeeKayDa.Auth.Discovery;
using ZeeKayDa.Auth.Security;
using ZeeKayDa.Auth.Tokens;

namespace ZeeKayDa.Auth;

/// <summary>
/// Configuration options for the ZeeKayDa authorization server.
/// </summary>
/// <remarks>
/// Per-endpoint settings live in get-only groups such as <see cref="AuthorizationEndpoint"/>: their
/// members may be changed, the groups not replaced.
/// </remarks>
public sealed class AuthorizationServerOptions
{
    private ICollection<GrantType> _grantTypesSupported = [GrantType.AuthorizationCode];
    private ICollection<string> _corsOrigins = [];
    private bool _frozen;

    /// <summary>
    /// Gets or sets the issuer identifier for this authorization server.
    /// </summary>
    /// <remarks>
    /// An absolute HTTPS URI with no query or fragment, published verbatim as the discovery <c>issuer</c>.
    /// </remarks>
    public string? Issuer { get; set; }

    /// <summary>
    /// Gets or sets the one clock-skew grace window applied to every token and authorization code
    /// validity check: store expiry and the access token <c>exp</c> and <c>nbf</c> claims.
    /// </summary>
    /// <remarks>
    /// Must be at least <see cref="TimeSpan.Zero"/> and less than half of
    /// <c>AuthorizationEndpoint.AuthorizationCodeLifetime</c>, or it would nullify code expiry.
    /// </remarks>
    public TimeSpan ClockSkewTolerance { get; set; } = TimeSpan.FromSeconds(5);

    /// <summary>
    /// Gets or sets the grant types supported by this authorization server.
    /// Defaults to <c>[<see cref="GrantType.AuthorizationCode"/>]</c>.
    /// </summary>
    public ICollection<GrantType> GrantTypesSupported
    {
        get => _grantTypesSupported;
        set => _grantTypesSupported = FrozenOptions.Assign(_frozen, value, "AuthorizationServerOptions.GrantTypesSupported");
    }

    /// <summary>
    /// Gets or sets the browser origins allowed to read discovery, JWKS and userinfo responses. Empty
    /// (the default) emits <c>Access-Control-Allow-Origin: *</c>; otherwise the request <c>Origin</c>
    /// must match an entry exactly, and the match is echoed with <c>Vary: Origin</c>.
    /// </summary>
    /// <remarks>
    /// Each entry is an absolute <c>scheme://host[:port]</c> origin with no path, query, fragment,
    /// userinfo, wildcard or <c>null</c> literal; invalid entries fail startup. HTTP origins need
    /// <see cref="DevelopmentOptions.AllowHttpLoopbackCorsOrigins"/>.
    /// </remarks>
    public ICollection<string> CorsOrigins
    {
        get => _corsOrigins;
        set => _corsOrigins = FrozenOptions.Assign(_frozen, value, "AuthorizationServerOptions.CorsOrigins");
    }

    /// <summary>
    /// Gets the discovery document configuration options.
    /// </summary>
    public DiscoveryOptions DiscoveryDocument { get; } = new();

    /// <summary>
    /// Gets the authorization endpoint configuration options.
    /// </summary>
    public AuthorizationEndpointOptions AuthorizationEndpoint { get; } = new();

    /// <summary>
    /// Gets the end-session endpoint configuration options.
    /// </summary>
    public EndSessionEndpointOptions EndSessionEndpoint { get; } = new();

    /// <summary>
    /// Gets the token endpoint configuration options.
    /// </summary>
    public TokenEndpointOptions TokenEndpoint { get; } = new();

    /// <summary>
    /// Gets the JSON Web Key Set endpoint configuration options.
    /// </summary>
    public JwksEndpointOptions JwksEndpoint { get; } = new();

    /// <summary>
    /// Gets the signing key timing options.
    /// </summary>
    public SigningKeyOptions SigningKeys { get; } = new();

    /// <summary>
    /// Gets the UserInfo endpoint configuration options.
    /// </summary>
    public UserInfoEndpointOptions UserInfoEndpoint { get; } = new();

    /// <summary>
    /// Gets the response configuration options.
    /// </summary>
    public ResponseOptions Response { get; } = new();

    /// <summary>
    /// Gets the security headers applied to every ZeeKayDa.Auth protocol endpoint response.
    /// </summary>
    public SecurityHeadersOptions SecurityHeaders { get; } = new();

    /// <summary>
    /// Gets the switches that weaken security and must not be enabled in production.
    /// </summary>
    public DevelopmentOptions Development { get; } = new();

    /// <summary>
    /// Makes every collection read-only, refuses any later replacement, and fixes the
    /// <see cref="Development"/> switches.
    /// </summary>
    internal void Freeze()
    {
        if (_frozen)
            return;

        GrantTypesSupported = FrozenOptions.Copy(GrantTypesSupported);
        CorsOrigins = FrozenOptions.Copy(CorsOrigins);
        AuthorizationEndpoint.Freeze();
        TokenEndpoint.Freeze();
        Response.Freeze();
        Development.Freeze();
        _frozen = true;
    }
}
