namespace ZeeKayDa.Auth.Tokens;

/// <summary>
/// Base options type for <see cref="JwtSigningService{TOptions}"/> implementations.
/// </summary>
/// <remarks>
/// Provider-specific options classes derive from this type and may add their own properties.
/// The base class carries only the cache-refresh throttle.
/// </remarks>
public abstract class JwtSigningServiceOptions
{
    /// <summary>
    /// Gets or sets the interval at which the base class re-invokes <c>LoadKeysAsync</c>
    /// to refresh the trusted key set.
    /// </summary>
    /// <remarks>
    /// Defaults to 5 minutes. The base class coalesces concurrent requests during a
    /// refresh using a single-flight gate so that a burst of signing or JWKS requests never
    /// fans out into multiple simultaneous <c>LoadKeysAsync</c> calls.
    /// A zero or negative value is rejected at startup by <c>JwtSigningServiceOptionsValidator</c>.
    /// </remarks>
    public TimeSpan RefreshInterval { get; set; } = TimeSpan.FromMinutes(5);
}
