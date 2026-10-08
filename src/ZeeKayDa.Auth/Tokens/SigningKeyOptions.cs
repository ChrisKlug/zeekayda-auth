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
    /// <see cref="Discovery.JwksEndpointOptions.CacheMaxAge"/> plus <see cref="RefreshInterval"/>.
    /// </remarks>
    public TimeSpan LeadTime { get; set; } = TimeSpan.FromDays(1);

    /// <summary>
    /// Gets or sets how often the signing key source is read again. Defaults to five minutes.
    /// </summary>
    /// <remarks>
    /// A key added to the source is published within this long of being listed, so it has been
    /// published for the lead time when it signs; a key removed stops signing and is unpublished
    /// within it. Must be greater than zero.
    /// </remarks>
    public TimeSpan RefreshInterval { get; set; } = TimeSpan.FromMinutes(5);

    // Long enough that a slow or failed handover on one replica is noticed and fixed before the
    // other replicas stop publishing the key it still signs with.
    private static readonly TimeSpan MinimumDefaultRetention = TimeSpan.FromDays(2);

    /// <summary>
    /// Gets or sets how long a key stays published after its successor takes over, or after it
    /// expires, so tokens it signed can still be verified. Defaults to two days, or to the larger of
    /// <see cref="TokenEndpointOptions.AccessTokenLifetime"/> and
    /// <see cref="TokenEndpointOptions.IdTokenLifetime"/> plus
    /// <see cref="AuthorizationServerOptions.ClockSkewTolerance"/> when that is longer.
    /// </summary>
    /// <remarks>
    /// Must cover the longest token lifetime, so tokens a key signed just before it stopped signing
    /// stay verifiable. The two days on top cover a replica whose handover to a successor is slow or
    /// fails: it signs on with the old key, which stays verifiable for this long from the
    /// successor's takeover. A failed handover must be fixed within it. Clients may override their
    /// token lifetimes and may come from a database, so they are not known at startup; raise this
    /// setting to the longest lifetime any client uses. A value below the default logs a Warning at
    /// startup.
    /// </remarks>
    public TimeSpan? RetainRetiredKeysFor { get; set; }

    /// <summary>
    /// The value <see cref="RetainRetiredKeysFor"/> takes when it is not set: the longer server-wide
    /// token lifetime plus the clock skew tolerance, and at least two days.
    /// </summary>
    internal static TimeSpan DefaultRetainRetiredKeysFor(AuthorizationServerOptions options)
    {
        // A retired key's last token stays valid for a token lifetime, and relying parties accept it
        // for the clock skew beyond that.
        var tokens = TokenLifetimes.Sum(
            options.TokenEndpoint.AccessTokenLifetime > options.TokenEndpoint.IdTokenLifetime
                ? options.TokenEndpoint.AccessTokenLifetime
                : options.TokenEndpoint.IdTokenLifetime,
            options.ClockSkewTolerance);
        return tokens > MinimumDefaultRetention ? tokens : MinimumDefaultRetention;
    }
}
