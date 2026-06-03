namespace ZeeKayDa.Auth;

/// <summary>
/// Discovery document configuration options.
/// </summary>
public sealed class DiscoveryOptions
{
    /// <summary>
    /// Gets or sets the <c>Cache-Control</c> <c>max-age</c> value (in seconds) for the OpenID Connect
    /// discovery document response. Defaults to <c>3600</c> (one hour).
    /// </summary>
    /// <remarks>
    /// Set to <c>0</c> to disable public caching entirely (<c>Cache-Control: no-store</c>).
    /// A shorter TTL reduces the window during which relying parties may serve a stale discovery
    /// document — important for emergency key rotation scenarios. A value of zero is appropriate
    /// for development environments where the document changes frequently.
    /// </remarks>
    public int CacheMaxAgeSeconds { get; set; } = 3600;

    /// <summary>
    /// Gets the list of allowed CORS origins for the discovery endpoint. When empty (the default),
    /// the endpoint emits <c>Access-Control-Allow-Origin: *</c>. When non-empty, the endpoint
    /// performs an exact canonical match against the request <c>Origin</c> header and emits the
    /// matching allowlist entry in <c>Access-Control-Allow-Origin</c>, plus <c>Vary: Origin</c>.
    /// </summary>
    /// <remarks>
    /// Each entry must be an absolute origin in the form <c>scheme://host[:port]</c> with no path,
    /// query, fragment, userinfo, wildcards, or <c>null</c> literal. Entries are validated at
    /// startup, canonicalized (lowercased), and deduplicated. Invalid entries fail startup.
    /// </remarks>
    public IList<string> CorsOrigins { get; } = [];
}
