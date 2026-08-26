namespace ZeeKayDa.Auth.Discovery;

/// <summary>
/// JSON Web Key Set endpoint configuration options.
/// </summary>
public sealed class JwksEndpointOptions
{
    /// <summary>
    /// Gets or sets an explicit override for the <c>jwks_uri</c> URI published in the discovery
    /// document. When <see langword="null"/>, the value is derived from the issuer.
    /// </summary>
    public string? Uri { get; set; }

    /// <summary>
    /// Gets or sets the <c>Cache-Control</c> <c>max-age</c> duration for the JWKS response.
    /// Defaults to one hour. The header's resolution is whole seconds; a value below one second
    /// emits <c>no-store</c>.
    /// </summary>
    /// <remarks>
    /// Set to <see cref="TimeSpan.Zero"/> to disable public caching entirely
    /// (<c>Cache-Control: no-store</c>). This value governs how long a relying party may keep
    /// trusting a cached key set — including a key that has since been removed from configuration.
    /// A shorter TTL shortens that revocation window at the cost of more JWKS traffic.
    /// </remarks>
    public TimeSpan CacheMaxAge { get; set; } = TimeSpan.FromHours(1);

    /// <summary>
    /// Gets the list of allowed CORS origins for the JWKS endpoint. When empty (the default),
    /// the endpoint emits <c>Access-Control-Allow-Origin: *</c>. When non-empty, the endpoint
    /// performs an exact canonical match against the request <c>Origin</c> header and emits the
    /// matching allowlist entry in <c>Access-Control-Allow-Origin</c>, plus <c>Vary: Origin</c>.
    /// </summary>
    /// <remarks>
    /// Each entry must be an absolute origin in the form <c>scheme://host[:port]</c> with no path,
    /// query, fragment, userinfo, wildcards, or <c>null</c> literal. Entries are validated at
    /// startup, canonicalized (lowercased), deduplicated, then replaced with an immutable snapshot.
    /// Invalid entries fail startup.
    ///
    /// HTTP origins are rejected by default. Set <see cref="AuthorizationServerOptions.AllowInsecureIssuer"/>
    /// to <see langword="true"/> to permit HTTP loopback origins for local development only.
    /// </remarks>
    public IList<string> CorsOrigins { get; internal set; } = [];
}
