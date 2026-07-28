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
        get
        {
            var effective = _publicationLead ?? RefreshInterval;

            // Defense-in-depth (issue #425 security review, finding F6): the primary enforcement of
            // PublicationLead >= RefreshInterval is KeySourcePublicationLeadValidator.ValidateAtLeastRefreshInterval,
            // run by each provider's IValidateOptions at options-bind time. That only fires when the
            // options pipeline's validation actually runs (e.g. ValidateOnStart()) — it would not catch
            // an options instance built directly (a test, a bespoke host) or mutated afterwards without
            // going through that pipeline. Re-checking here, at the point where the effective value is
            // actually read (every ListKeysAsync call, via each Tier B provider's ComputeActivateAt),
            // closes that gap cheaply: a plain TimeSpan comparison on every read, no store access, no
            // base-class surgery. Only applies when PublicationLead was explicitly set — the derived
            // default (falling back to RefreshInterval) can never violate this invariant.
            if (_publicationLead is { } explicitLead && explicitLead < RefreshInterval)
            {
                throw new ZeeKayDaConfigurationException(
                    new ZeeKayDaConfigurationFailure(
                        "signing.publication_lead_below_refresh_interval",
                        $"{GetType().Name}.PublicationLead ({explicitLead}) must be greater than or equal " +
                        $"to {GetType().Name}.RefreshInterval ({RefreshInterval}). A shorter lead could let " +
                        "a key activate before its public half has ever been re-read and published in the " +
                        "JWKS."));
            }

            return effective;
        }
        set => _publicationLead = value;
    }

    /// <summary>
    /// The same effective value as <see cref="PublicationLead"/> (the explicitly set value, or
    /// <see cref="RefreshInterval"/> when unset), but without <see cref="PublicationLead"/>'s own
    /// defensive invariant check. Exists solely so <see cref="KeySourcePublicationLeadValidator.ValidateAtLeastRefreshInterval"/>
    /// can read the raw, possibly-invalid value it is in the middle of validating without
    /// triggering that same check itself — a validator whose job is to produce a friendly,
    /// aggregated <see cref="Microsoft.Extensions.Options.ValidateOptionsResult.Fail(string)"/> must
    /// not have the value it is inspecting throw out from under it before it can do so.
    /// </summary>
    internal TimeSpan RawPublicationLead => _publicationLead ?? RefreshInterval;
}
