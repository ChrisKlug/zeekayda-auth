namespace ZeeKayDa.Auth.Tokens;

/// <summary>
/// Base options type for a <see cref="JwtSigningService{TOptions}"/> provider that re-supplies the
/// current key list on a cadence, because something else owns the keys and the provider only reads
/// them.
/// </summary>
/// <remarks>
/// <para>
/// This is Tier B of the two-tier signing-provider split introduced by ADR 0015 (issue #418): the
/// list genuinely changes between calls (a remote store, a database table, a file glob that
/// discovers new members at runtime). Azure Key Vault (cached and remote) is the intended
/// production consumer of this tier.
/// </para>
/// <para>
/// This tier lands alongside the existing <see cref="StaticKeySourceOptions"/>/
/// <see cref="RotatingKeySourceOptions"/> split (ADR 0011 §3.4) rather than replacing it — issue
/// #420 is additive-only. The old tiers retire only once every provider has migrated to this new
/// contract (issue #428).
/// </para>
/// </remarks>
public abstract class KeySourceOptions : JwtSigningServiceOptions
{
    private TimeSpan? _publicationLead;

    /// <summary>
    /// Gets or sets how often the base class re-asks the provider for the current key list.
    /// Defaults to one hour.
    /// </summary>
    /// <remarks>
    /// One meaning only: re-ask cadence. Replaces ADR 0011's <c>KeyRotationCheckInterval</c>, which
    /// conflated this with Tier A's internal clock-tick-over-a-fixed-timeline meaning — the reason
    /// ADR 0015 re-splits the tiers on acquisition rather than on "does it reload."
    /// </remarks>
    public TimeSpan RefreshInterval { get; set; } = TimeSpan.FromHours(1);

    /// <summary>
    /// Gets or sets how long before a key's <c>ActivateAt</c> its public half must already have
    /// been published. Defaults to <see cref="RefreshInterval"/> when left unset.
    /// </summary>
    /// <remarks>
    /// <para>
    /// Enforced entirely through durable, <c>ActivateAt</c>-derived timing: the base treats
    /// <c>PublishAt = ActivateAt − PublicationLead</c> as the instant the key's public half must
    /// already be in the JWKS, and the provider maps its store's durable timestamp onto
    /// <c>ActivateAt</c> so that lead is satisfied (e.g. Key Vault: <c>ActivateAt = CreatedOn +
    /// PublicationLead</c>). It is NEVER derived from observed/first-seen time.
    /// </para>
    /// <para>
    /// <b>Invariant:</b> <c>PublicationLead &gt;= RefreshInterval</c> — a config-level relationship
    /// (the lead is at least one poll cycle), not per-key state. A provider's
    /// <c>IValidateOptions</c> implementation should enforce this via
    /// <see cref="KeySourcePublicationLeadValidator"/>.
    /// </para>
    /// </remarks>
    public TimeSpan PublicationLead
    {
        get => _publicationLead ?? RefreshInterval;
        set => _publicationLead = value;
    }
}
