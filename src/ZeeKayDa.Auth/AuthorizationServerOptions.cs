using ZeeKayDa.Auth.Authorization;
using ZeeKayDa.Auth.Discovery;
using ZeeKayDa.Auth.Logging;
using ZeeKayDa.Auth.Security;
using ZeeKayDa.Auth.Tokens;

namespace ZeeKayDa.Auth;

/// <summary>
/// Configuration options for the ZeeKayDa authorization server.
/// </summary>
/// <remarks>
/// Server-wide settings are exposed directly on this class. Per-endpoint settings are grouped
/// into nested sealed option classes (<see cref="DiscoveryDocument"/>, <see cref="AuthorizationEndpoint"/>,
/// <see cref="TokenEndpoint"/>, <see cref="JwksEndpoint"/>, <see cref="IdToken"/>, <see cref="Response"/>,
/// <see cref="SecurityHeaders"/>, <see cref="Logging"/>)
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
    /// <strong>Development-only</strong> — must never be <see langword="true"/> in production. A
    /// warning is emitted at startup whenever this flag is enabled. When <see langword="false"/>
    /// (the default), an HTTP issuer fails startup validation; when <see langword="true"/>, only
    /// loopback HTTP issuers such as <c>http://localhost:5000</c> are accepted.
    /// </remarks>
    public bool AllowInsecureIssuer { get; set; }

    /// <summary>
    /// Gets or sets the clock-skew grace window applied to token expiry checks in multi-node
    /// store implementations.
    /// </summary>
    /// <remarks>
    /// In load-balanced deployments, node clocks can drift. Multi-node store implementations apply
    /// this value as a grace window on <c>ExpiresAt</c> liveness checks:
    /// <c>entry.ExpiresAt + ClockSkewTolerance &gt; now</c>. Must be greater than or equal to
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
    public ICollection<GrantType> GrantTypesSupported { get; set; } = [GrantType.AuthorizationCode];

    /// <summary>
    /// Gets the discovery document configuration options.
    /// </summary>
    public DiscoveryOptions DiscoveryDocument { get; } = new();

    /// <summary>
    /// Gets the authorization endpoint configuration options.
    /// </summary>
    public AuthorizationEndpointOptions AuthorizationEndpoint { get; } = new();

    /// <summary>
    /// Gets the token endpoint configuration options.
    /// </summary>
    public TokenEndpointOptions TokenEndpoint { get; } = new();

    /// <summary>
    /// Gets the JSON Web Key Set endpoint configuration options.
    /// </summary>
    public JwksEndpointOptions JwksEndpoint { get; } = new();

    /// <summary>
    /// Gets the ID token configuration options.
    /// </summary>
    public IdTokenOptions IdToken { get; } = new();

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
    /// Gets the logging framework-behavior options. These settings control how ZeeKayDa.Auth
    /// emits log entries and are not advertised in the OIDC Discovery document.
    /// </summary>
    public LoggingOptions Logging { get; } = new();
}
