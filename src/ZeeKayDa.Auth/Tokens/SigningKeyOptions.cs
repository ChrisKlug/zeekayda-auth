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
    /// Relying parties that cached the key set before a key appeared reject its tokens until they refresh, so a
    /// key waits this long from its <see cref="SourceKey.NotBefore"/> before it signs. A day covers relying
    /// parties that ignore the JWKS <c>Cache-Control</c> header. Must be greater than zero, and not shorter
    /// than <see cref="Discovery.JwksEndpointOptions.CacheMaxAge"/> plus <see cref="RefreshInterval"/>.
    /// </remarks>
    public TimeSpan LeadTime { get; set; } = TimeSpan.FromDays(1);

    /// <summary>
    /// Gets or sets how often the signing key source is read again. Defaults to five minutes.
    /// </summary>
    /// <remarks>
    /// A key added to the source is published within this long of being listed, so it has been
    /// published for the lead time when it signs; a key removed stops signing and is unpublished
    /// within it. Must be at least one minute.
    /// </remarks>
    public TimeSpan RefreshInterval { get; set; } = TimeSpan.FromMinutes(5);

    /// <summary>The shortest <see cref="RefreshInterval"/> accepted.</summary>
    internal static readonly TimeSpan MinimumRefreshInterval = TimeSpan.FromMinutes(1);

    // Long enough to fix a failed handover on one replica before the others unpublish its key.
    private static readonly TimeSpan MinimumDefaultRetention = TimeSpan.FromDays(2);

    /// <summary>
    /// Gets or sets how long a key stays published after its successor takes over, or after it
    /// expires, so tokens it signed can still be verified. Defaults to two days, or to the larger of
    /// <see cref="TokenEndpointOptions.AccessTokenLifetime"/> and
    /// <see cref="TokenEndpointOptions.IdTokenLifetime"/> plus
    /// <see cref="AuthorizationServerOptions.ClockSkewTolerance"/> when that is longer.
    /// </summary>
    /// <remarks>
    /// Must cover the longest token lifetime any client uses, which is not known at startup when clients come
    /// from a database, so raise it to match. The two-day floor gives a replica whose handover is slow or fails
    /// time to be fixed while its old key still verifies. A value below the default logs a Warning at startup.
    /// </remarks>
    public TimeSpan? RetainRetiredKeysFor { get; set; }

    /// <summary>
    /// The value <see cref="RetainRetiredKeysFor"/> takes when it is not set: the longer server-wide
    /// token lifetime plus the clock skew tolerance, and at least two days.
    /// </summary>
    internal static TimeSpan DefaultRetainRetiredKeysFor(AuthorizationServerOptions options)
    {
        var tokens = TokenLifetimes.Sum(
            options.TokenEndpoint.AccessTokenLifetime > options.TokenEndpoint.IdTokenLifetime
                ? options.TokenEndpoint.AccessTokenLifetime
                : options.TokenEndpoint.IdTokenLifetime,
            options.ClockSkewTolerance);
        return tokens > MinimumDefaultRetention ? tokens : MinimumDefaultRetention;
    }
}
