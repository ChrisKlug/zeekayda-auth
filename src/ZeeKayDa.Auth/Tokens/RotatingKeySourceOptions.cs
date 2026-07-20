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
    /// Defaults to 5 minutes. The base class coalesces concurrent requests during a refresh using
    /// a single-flight gate so that a burst of signing or JWKS requests never fans out into
    /// multiple simultaneous <c>LoadKeysAsync</c> calls.
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
    public TimeSpan KeyRotationCheckInterval { get; set; } = TimeSpan.FromMinutes(5);
}
