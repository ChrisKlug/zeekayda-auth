namespace ZeeKayDa.Auth.Discovery;

/// <summary>
/// Discovery document configuration options.
/// </summary>
public sealed class DiscoveryOptions
{
    /// <summary>
    /// Gets or sets the <c>Cache-Control</c> <c>max-age</c> duration for the OpenID Connect
    /// discovery document response. Defaults to one hour. The header's resolution is whole
    /// seconds; a value below one second emits <c>no-store</c>.
    /// </summary>
    /// <remarks>
    /// Set to <see cref="TimeSpan.Zero"/> to disable public caching entirely
    /// (<c>Cache-Control: no-store</c>). A shorter TTL reduces the window during which relying
    /// parties may serve a stale discovery document — important for emergency key rotation
    /// scenarios. A value of zero is appropriate for development environments where the document
    /// changes frequently.
    /// </remarks>
    public TimeSpan CacheMaxAge { get; set; } = TimeSpan.FromHours(1);
}
