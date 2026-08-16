namespace ZeeKayDa.Auth.Tokens;

/// <summary>
/// Base options type for a <see cref="JwtSigningService{TOptions}"/> provider that re-supplies the
/// current key list on a cadence, because something else owns the keys and the provider only reads
/// them.
/// </summary>
/// <remarks>
/// The list genuinely changes between calls (a remote store, a database table, a file glob that
/// discovers new members at runtime). Azure Key Vault (cached and remote) is the intended
/// production consumer. Together with <see cref="KeySetOptions"/>, this is the sole
/// signing-provider contract.
/// </remarks>
public abstract class KeySourceOptions : JwtSigningServiceOptions
{
    private TimeSpan? _publicationLead;

    /// <summary>
    /// Gets or sets how often the base class re-asks the provider for the current key list.
    /// Defaults to one hour.
    /// </summary>
    /// <remarks>
    /// One meaning only: re-ask cadence. This is distinct from <see cref="KeySetOptions"/>'s internal
    /// clock-tick-over-a-fixed-timeline meaning — the two option types split on acquisition shape
    /// rather than on "does it reload."
    /// </remarks>
    public TimeSpan RefreshInterval { get; set; } = TimeSpan.FromHours(1);

    /// <summary>
    /// Gets or sets how long before a key's <c>ActivateAt</c> its public half must already have
    /// been published. Defaults to <see cref="RefreshInterval"/> when left unset.
    /// </summary>
    /// <remarks>
    /// Enforced entirely through durable, <c>ActivateAt</c>-derived timing: the base treats
    /// <c>PublishAt = ActivateAt − PublicationLead</c> as the instant the key's public half must
    /// already be in the JWKS. It is never derived from observed/first-seen time.
    /// <b>Invariant:</b> <c>PublicationLead &gt;= RefreshInterval</c> (the lead is at least one poll
    /// cycle) — a provider's <c>IValidateOptions</c> implementation should enforce this via
    /// <see cref="KeySourcePublicationLeadValidator"/>.
    /// </remarks>
    public TimeSpan PublicationLead
    {
        get
        {
            var effective = _publicationLead ?? RefreshInterval;

            // Defense-in-depth: KeySourcePublicationLeadValidator is the primary enforcement of
            // PublicationLead >= RefreshInterval, but it only fires when the options pipeline's
            // validation actually runs. Re-checking here, at the point of actual use, catches an
            // options instance built or mutated without going through that pipeline.
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
    /// The same effective value as <see cref="PublicationLead"/>, but without its defensive
    /// invariant check, so <see cref="KeySourcePublicationLeadValidator.ValidateAtLeastRefreshInterval"/>
    /// can read the raw, possibly-invalid value without that check throwing out from under it.
    /// </summary>
    internal TimeSpan RawPublicationLead => _publicationLead ?? RefreshInterval;
}
