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
}
