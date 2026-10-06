namespace ZeeKayDa.Auth.Tokens;

/// <summary>
/// The timing rules that decide, from each key's dates, which key signs and which are published.
/// </summary>
public sealed class SigningKeyOptions
{
    /// <summary>
    /// Gets or sets how long a new key is published before it signs. Defaults to one day.
    /// </summary>
    /// <remarks>
    /// Relying parties that cached the key set before a new key appeared reject its tokens until
    /// they refresh, so a new key waits this long, counted from its <see cref="SourceKey.NotBefore"/>,
    /// before it takes over. A day covers relying parties that ignore the JWKS
    /// <c>Cache-Control</c> header (Microsoft.IdentityModel refreshes metadata every 12 hours by
    /// default). Must be greater than zero, and not shorter than
    /// <see cref="Discovery.JwksEndpointOptions.CacheMaxAge"/>.
    /// </remarks>
    public TimeSpan LeadTime { get; set; } = TimeSpan.FromDays(1);

    /// <summary>
    /// Gets or sets how long a key stays published after its successor takes over, or after it
    /// expires, so tokens it signed can still be verified. Defaults to the larger of
    /// <see cref="TokenEndpointOptions.AccessTokenLifetime"/> and
    /// <see cref="TokenEndpointOptions.IdTokenLifetime"/>, plus
    /// <see cref="AuthorizationServerOptions.ClockSkewTolerance"/>.
    /// </summary>
    /// <remarks>
    /// A client can override its token lifetimes, but clients may come from a database and are not
    /// known at startup. Raise this setting to the longest lifetime any client uses. Keys are read
    /// only at startup, so a successor takes over at a restart, possibly long after its lead time:
    /// the key it replaced therefore stays published for as long as the successor signs.
    /// </remarks>
    public TimeSpan? RetainRetiredKeysFor { get; set; }
}
