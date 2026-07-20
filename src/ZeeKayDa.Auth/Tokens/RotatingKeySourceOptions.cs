namespace ZeeKayDa.Auth.Tokens;

/// <summary>
/// Base options type for a <see cref="JwtSigningService{TOptions}"/> provider whose key source can
/// change while the process runs.
/// </summary>
/// <remarks>
/// This is the shared parent for the File, PFX, Windows Certificate Store, and Azure Key Vault
/// (cached and remote) provider options types — not Key-Vault-only (ADR 0011 §3.4).
/// </remarks>
public abstract class RotatingKeySourceOptions : JwtSigningServiceOptions
{
    /// <summary>
    /// Gets or sets how often the base class re-evaluates whether the active/included key set has
    /// changed (poll cadence, coalesced via the single-flight gate and the
    /// <c>HasKeySetChangedAsync</c> ask). Applies uniformly to all rotating providers — File, PFX,
    /// Windows Certificate Store, and Azure Key Vault (cached and remote) — including the
    /// certificate-store provider, where most cycles do no I/O.
    /// </summary>
    /// <remarks>
    /// <para>
    /// Defaults to 1 hour (ADR 0011 §3.4 amendment, issue #407). This property doubles as the
    /// publish-then-activate lead time for a newly rotated-in key (ADR 0011 §3.5) — how long the
    /// key must be visible in the JWKS before it is expected to become the active signer, so
    /// relying parties that cached the previous JWKS have had a chance to observe the new one. The
    /// default was raised from 5 minutes because 5 minutes sits well inside the range that is
    /// realistically unsafe against common relying-party JWKS caching behavior: ASP.NET Core's
    /// <c>Microsoft.IdentityModel</c> <c>ConfigurationManager</c> defaults its reactive
    /// refetch-on-unknown-<c>kid</c> cooldown to 5 minutes, so 1 hour clears that self-healing path
    /// many times over, while still keeping the poll-gated safety behaviors this interval also
    /// governs — emergency key disablement detection, the vanished-<c>kid</c> anomaly check, and
    /// certificate-expiry warnings — reasonably responsive. It is not a guarantee: relying parties
    /// with a longer fixed JWKS-cache TTL and no retry-on-miss logic are still exposed, and are best
    /// protected by keeping a published standby key rather than by raising this default further.
    /// The base class coalesces concurrent requests during a refresh using a single-flight gate so
    /// that a burst of signing or JWKS requests never fans out into multiple simultaneous
    /// <c>LoadKeysAsync</c> calls.
    /// </para>
    /// <para>
    /// Renamed from <c>KeySourceRefreshInterval</c> and moved from the shared
    /// <see cref="JwtSigningServiceOptions"/> base onto this tier (ADR 0011 §3.4, issue #409). The
    /// meaning is unchanged: how often the library re-evaluates whether the active/included key
    /// set has changed. This property is non-nullable — the previous "null means load once, never
    /// reload" static-source mode is now expressed structurally by deriving from
    /// <see cref="StaticKeySourceOptions"/> instead.
    /// </para>
    /// <para>
    /// A zero or negative value is rejected at startup by the provider's <c>IValidateOptions</c>
    /// implementation.
    /// </para>
    /// </remarks>
    public TimeSpan KeyRotationCheckInterval { get; set; } = TimeSpan.FromHours(1);
}
