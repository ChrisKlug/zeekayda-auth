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
/// Server-wide settings are exposed directly on this class. Per-endpoint settings are grouped
/// into nested sealed option classes (<see cref="DiscoveryDocument"/>, <see cref="AuthorizationEndpoint"/>,
/// <see cref="TokenEndpoint"/>, <see cref="JwksEndpoint"/>, <see cref="Response"/>,
/// <see cref="SecurityHeaders"/>, <see cref="Development"/>)
/// which are initialized to default instances. Group properties are get-only and cannot be nulled;
/// consumers may mutate the members of each group but not replace the group itself.
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
    /// Must be an absolute HTTPS URI with no query string or fragment component.
    /// This value is published verbatim as the <c>issuer</c> field in the OIDC Discovery document.
    /// </remarks>
    public string? Issuer { get; set; }

    /// <summary>
    /// Gets or sets the server-wide clock-skew grace window applied to token and authorization code
    /// validity checks.
    /// </summary>
    /// <remarks>
    /// Clocks drift between the nodes of a deployment and between the server and its callers, so
    /// one tolerance covers every such check: the authorization code and refresh token stores
    /// apply it to their expiry checks (<c>entry.ExpiresAt + ClockSkewTolerance &gt; now</c>), and
    /// access token validation applies it to the <c>exp</c> and <c>nbf</c> claims. There is no
    /// per-component setting. Must be greater than or equal to
    /// <see cref="TimeSpan.Zero"/>, and must be less than half of
    /// <c>AuthorizationEndpoint.AuthorizationCodeLifetime</c> — otherwise it would effectively
    /// nullify the code expiry guarantee. Both are enforced at startup by
    /// <c>AuthorizationServerOptionsValidator</c>.
    /// </remarks>
    public TimeSpan ClockSkewTolerance { get; set; } = TimeSpan.FromSeconds(5);

    /// <summary>
    /// Gets or sets the grant types supported by this authorization server.
    /// Defaults to <c>[<see cref="GrantType.AuthorizationCode"/>]</c>.
    /// </summary>
    /// <remarks>
    /// This is a server-wide setting with no per-endpoint variant in the OIDC Discovery specification.
    /// </remarks>
    public ICollection<GrantType> GrantTypesSupported
    {
        get => _grantTypesSupported;
        set => _grantTypesSupported = FrozenOptions.Assign(_frozen, value, "AuthorizationServerOptions.GrantTypesSupported");
    }

    /// <summary>
    /// Gets or sets the browser origins allowed to read the responses of the endpoints a script
    /// may call: discovery, JWKS and userinfo. When empty (the default), each of them emits
    /// <c>Access-Control-Allow-Origin: *</c>. When non-empty, each performs an exact canonical
    /// match against the request <c>Origin</c> header and emits the matching allowlist entry in
    /// <c>Access-Control-Allow-Origin</c>, plus <c>Vary: Origin</c>.
    /// </summary>
    /// <remarks>
    /// <para>
    /// One list for every endpoint rather than one per endpoint: none of them authenticates with
    /// a cookie, so the allowlist decides which origins may read a public document or a response
    /// the caller already holds the token for, and that answer does not vary by endpoint.
    /// </para>
    /// <para>
    /// Each entry must be an absolute origin in the form <c>scheme://host[:port]</c> with no path,
    /// query, fragment, userinfo, wildcards, or <c>null</c> literal. Entries are validated at
    /// startup and frozen as configured; invalid entries fail startup. The endpoints match against
    /// a canonical (lowercased, punycode, de-duplicated) form derived from them, not stored here.
    /// </para>
    /// <para>
    /// HTTP origins are rejected unless
    /// <see cref="DevelopmentOptions.AllowHttpLoopbackCorsOrigins"/> admits HTTP loopback origins.
    /// </para>
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
    /// Gets the security headers configuration options. These settings are applied to all
    /// ZeeKayDa.Auth protocol endpoint responses via the internal route group.
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
