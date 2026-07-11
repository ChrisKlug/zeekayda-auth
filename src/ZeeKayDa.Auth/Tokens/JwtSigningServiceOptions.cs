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
    /// to refresh the trusted key set, or <see langword="null"/> to load the key set exactly
    /// once and never reload it.
    /// </summary>
    /// <remarks>
    /// <para>
    /// Defaults to 5 minutes. The base class coalesces concurrent requests during a refresh
    /// using a single-flight gate so that a burst of signing or JWKS requests never fans out
    /// into multiple simultaneous <c>LoadKeysAsync</c> calls.
    /// </para>
    /// <para>
    /// <see langword="null"/> is a distinct, named static-source mode, not a sentinel value: it
    /// tells the base class the key source never changes, so <c>LoadKeysAsync</c> is called at
    /// most once for the lifetime of the service and the cached <see cref="SigningKeySet"/> is
    /// never invalidated or disposed while the service is live. <see cref="DevelopmentSigningKeyOptions"/>
    /// uses this mode because its keys are memoized for the process lifetime; calling
    /// <c>LoadKeysAsync</c> again would dispose a key set that memoization still references,
    /// throwing <see cref="ObjectDisposedException"/> on the next signing call. Providers whose
    /// key source can legitimately change (e.g. a KMS or HSM) must set a finite value instead —
    /// their validators reject <see langword="null"/>.
    /// </para>
    /// <para>
    /// This single property deliberately serves two roles at once for providers backed by a
    /// remote, rotating key source such as Azure Key Vault: it is both the cache-poll cadence
    /// (how often <c>LoadKeysAsync</c> re-invokes) <em>and</em>, per ADR 0011 §3.5, the
    /// publish-then-activate lead time — a rotated-in key must be observable in
    /// <c>GetSigningKeysAsync</c> results for at least this long before it may become the active
    /// signer, so that a relying party polling the JWKS at this cadence has had a chance to
    /// observe it first. These are intentionally <em>not</em> split into two separate properties:
    /// doing so would allow configuring an activation delay shorter than the poll interval,
    /// letting a key start signing before the process itself would even notice it exists —
    /// exactly the race the publish-then-activate/retirement-window model exists to prevent.
    /// </para>
    /// <para>
    /// A zero or negative value is rejected at startup by the provider's <c>IValidateOptions</c>
    /// implementation (e.g. <c>DevelopmentSigningKeyOptionsValidator</c>).
    /// </para>
    /// </remarks>
    public TimeSpan? KeySourceRefreshInterval { get; set; } = TimeSpan.FromMinutes(5);
}
