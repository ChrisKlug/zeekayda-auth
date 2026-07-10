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
    /// Gets or sets a value indicating whether in-memory token stores are permitted outside a
    /// Development environment.
    /// </summary>
    /// <remarks>
    /// <para>
    /// In-memory stores lose all issued tokens on process restart and disable single-use
    /// enforcement across multiple instances. When this flag is <see langword="false"/> (the
    /// default) and the application is not running in the <c>Development</c> environment,
    /// startup fails with a <see cref="ZeeKayDaConfigurationException"/> so that an accidental
    /// in-memory configuration is never silently deployed to a non-development host.
    /// </para>
    /// <para>
    /// Set this to <see langword="true"/> only in test hosts that intentionally run under a
    /// non-Development environment name (e.g. integration test hosts configured as
    /// <c>Production</c>). A <see cref="Microsoft.Extensions.Logging.LogLevel.Warning"/> is
    /// still emitted so the override is always visible in logs.
    /// </para>
    /// </remarks>
    public bool AllowInMemoryStoresOutsideDevelopment { get; set; }

    /// <summary>
    /// Gets or sets the list of environment names in which development JWT signing keys
    /// (<c>AddDevelopmentJwtSigningKeys()</c>) are permitted. Defaults to <c>["Development"]</c>.
    /// </summary>
    /// <remarks>
    /// <para>
    /// Development signing keys are ephemeral or stored in a local file and are not suitable
    /// for production. When the host environment is not in this list, startup fails with a
    /// <see cref="ZeeKayDaConfigurationException"/> so that an accidental development-key
    /// configuration is never silently deployed to a non-permitted host. This is a server-wide
    /// safety gate — mirroring <see cref="AllowInMemoryStoresOutsideDevelopment"/> above — not a
    /// per-provider tuning knob, so it lives here rather than on a provider-specific options type.
    /// </para>
    /// <para>
    /// <c>Production</c> can never be added to this list: the gate rejects a <c>Production</c>
    /// host environment unconditionally, regardless of the list's contents. This is enforced
    /// both at startup validation time and again by the gate itself, so it cannot be bypassed
    /// by misconfiguration.
    /// </para>
    /// <para>
    /// The default list contains only <c>"Development"</c>. Callers may widen this list to
    /// include additional environment names — for example,
    /// <c>["Development", "IntegrationTesting", "CI"]</c> — for test hosts that intentionally
    /// run under a non-Development environment name. A
    /// <see cref="Microsoft.Extensions.Logging.LogLevel.Critical"/> entry is emitted on every
    /// startup while the host environment is in the list but is not <c>"Development"</c>,
    /// because an ephemeral or non-rotating signing key in such an environment breaks signature
    /// validation for every relying party on restart.
    /// </para>
    /// <para>
    /// This list MUST NOT be sourced from <c>appsettings.json</c> or any other file that may
    /// be committed to source control. Set it explicitly in code or via an environment variable.
    /// Sourcing from configuration defeats the purpose of the gate because a misconfiguration
    /// in a config file could silently widen the allowed environments in production.
    /// </para>
    /// </remarks>
    public IReadOnlyList<string> AllowedDevelopmentJwtSigningKeysEnvironments { get; set; } =
        ["Development"];

    /// <summary>
    /// Gets or sets the clock-skew grace window applied to token expiry checks in multi-node
    /// store implementations.
    /// </summary>
    /// <remarks>
    /// <para>
    /// In load-balanced deployments, node clocks can drift. Store implementations that operate
    /// across multiple nodes apply this value as a grace window on <c>ExpiresAt</c> liveness
    /// checks: <c>entry.ExpiresAt + ClockSkewTolerance &gt; now</c>. The in-memory store
    /// (single-instance; one clock; inter-node skew is structurally impossible) and tombstone
    /// TTLs are unaffected.
    /// </para>
    /// <para>
    /// Must be greater than or equal to <see cref="TimeSpan.Zero"/>. A negative value is rejected
    /// at startup by <c>AuthorizationServerOptionsValidator</c> because it would cause expiry
    /// checks to reject tokens before their stated expiry time.
    /// </para>
    /// <para>
    /// The default of 5 seconds is intentionally small. A <c>ClockSkewTolerance</c> approaching
    /// half the authorization code lifetime effectively nullifies the code expiry guarantee. Values
    /// equal to or exceeding half of <c>AuthorizationEndpoint.AuthorizationCodeLifetime</c> are
    /// rejected at startup. See ADR 0008 §Security Considerations — Clock skew tolerance.
    /// </para>
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
