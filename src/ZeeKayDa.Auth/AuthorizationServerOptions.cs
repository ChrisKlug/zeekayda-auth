namespace ZeeKayDa.Auth;

/// <summary>
/// Configuration options for the ZeeKayDa authorization server.
/// </summary>
/// <remarks>
/// Server-wide settings are exposed directly on this class. Per-endpoint settings are grouped
/// into nested sealed option classes (<see cref="Discovery"/>, <see cref="Authorization"/>,
/// <see cref="Token"/>, <see cref="Jwks"/>, <see cref="IdToken"/>, <see cref="Response"/>)
/// which are initialized to default instances. Group properties are get-only and cannot be nulled;
/// consumers may mutate the members of each group but not replace the group itself.
/// </remarks>
public sealed class AuthorizationServerOptions
{
    /// <summary>
    /// Gets or sets the issuer identifier for this authorization server.
    /// </summary>
    /// <remarks>
    /// Must be an absolute HTTPS URI with no query string or fragment component.
    /// This value is published verbatim as the <c>issuer</c> field in the OIDC Discovery document.
    /// </remarks>
    public string? Issuer { get; set; }

    /// <summary>
    /// Gets or sets a value indicating whether an HTTP (non-HTTPS) loopback issuer URI is permitted.
    /// </summary>
    /// <remarks>
    /// <para>
    /// This is a <strong>development-only</strong> setting. It must never be set to
    /// <see langword="true"/> in production environments. A warning is emitted at startup
    /// whenever this flag is enabled to make the risk visible and intentional.
    /// </para>
    /// <para>
    /// When <see langword="false"/> (the default), an HTTP issuer causes a startup failure via
    /// the fail-fast validator registered by <c>AddZeeKayDaAuth()</c>. When
    /// <see langword="true"/>, only loopback HTTP issuers such as <c>http://localhost:5000</c>
    /// are accepted.
    /// </para>
    /// </remarks>
    public bool AllowInsecureIssuer { get; set; }

    /// <summary>
    /// Gets or sets the grant types supported by this authorization server.
    /// Defaults to <c>[<see cref="GrantType.AuthorizationCode"/>]</c>.
    /// </summary>
    /// <remarks>
    /// This is a server-wide setting with no per-endpoint variant in the OIDC Discovery specification.
    /// </remarks>
    public ICollection<GrantType> GrantTypesSupported { get; set; } = [GrantType.AuthorizationCode];

    /// <summary>
    /// Gets the discovery document configuration options.
    /// </summary>
    public DiscoveryOptions Discovery { get; } = new();

    /// <summary>
    /// Gets the authorization endpoint configuration options.
    /// </summary>
    public AuthorizationOptions Authorization { get; } = new();

    /// <summary>
    /// Gets the token endpoint configuration options.
    /// </summary>
    public TokenOptions Token { get; } = new();

    /// <summary>
    /// Gets the JSON Web Key Set endpoint configuration options.
    /// </summary>
    public JwksOptions Jwks { get; } = new();

    /// <summary>
    /// Gets the ID token configuration options.
    /// </summary>
    public IdTokenOptions IdToken { get; } = new();

    /// <summary>
    /// Gets the response configuration options.
    /// </summary>
    public ResponseOptions Response { get; } = new();
}
