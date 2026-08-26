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
    /// Defaults to one hour. The header's resolution is whole seconds; fractional seconds are
    /// truncated.
    /// </summary>
    /// <remarks>
    /// Set to <see cref="TimeSpan.Zero"/> to disable public caching entirely
    /// (<c>Cache-Control: no-store</c>). This value governs how long a relying party may keep
    /// trusting a cached key set — including a key that has since been removed from configuration.
    /// A shorter TTL shortens that revocation window at the cost of more JWKS traffic.
    /// </remarks>
    public TimeSpan CacheMaxAge { get; set; } = TimeSpan.FromHours(1);
}
