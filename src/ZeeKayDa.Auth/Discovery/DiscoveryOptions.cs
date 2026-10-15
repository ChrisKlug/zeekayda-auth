namespace ZeeKayDa.Auth.Discovery;

/// <summary>
/// Discovery document configuration options.
/// </summary>
public sealed class DiscoveryOptions
{
    /// <summary>
    /// Gets or sets the discovery response's <c>Cache-Control</c> <c>max-age</c>, in whole seconds;
    /// below one second emits <c>no-store</c>. Defaults to one hour.
    /// </summary>
    public TimeSpan CacheMaxAge { get; set; } = TimeSpan.FromHours(1);
}
