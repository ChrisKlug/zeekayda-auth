namespace ZeeKayDa.Auth.Tokens;

/// <summary>
/// Base options type for a <see cref="JwtSigningService{TOptions}"/> provider whose complete,
/// fixed set of keys is supplied at configuration time and never changes at runtime.
/// </summary>
/// <remarks>
/// <para>
/// This is Tier A of the two-tier signing-provider split introduced by ADR 0015 (issue #418): the
/// provider owns the full list of keys up front, and the only thing that ever advances is the wall
/// clock crossing each key's <c>ActivateAt</c>. File (PEM), PFX, and Windows Certificate Store are
/// the intended production consumers of this tier; development/in-memory signing is a trivial
/// degenerate case (one key, no <c>ActivateAt</c>, active from startup).
/// </para>
/// <para>
/// This tier lands alongside the existing <see cref="StaticKeySourceOptions"/>/
/// <see cref="RotatingKeySourceOptions"/> split (ADR 0011 §3.4) rather than replacing it — issue
/// #420 is additive-only. The old tiers retire only once every provider has migrated to this new
/// contract (issue #428).
/// </para>
/// </remarks>
public abstract class KeySetOptions : JwtSigningServiceOptions
{
    /// <summary>
    /// Gets or sets how long before a key's <c>ActivateAt</c> its public half must already be
    /// published in the JWKS. Defaults to one hour.
    /// </summary>
    /// <remarks>
    /// Advisory on this tier: the operator owns activation timing (via each key's <c>ActivateAt</c>
    /// in the provider's own configuration). Per ADR 0015 §1, this is the operator-facing lead time a
    /// key's public half must already be published in the JWKS before its <c>ActivateAt</c> — the
    /// same concept <see cref="KeySourceOptions.PublicationLead"/> carries on Tier B, where the base
    /// class derives <c>PublishAt</c> from it. On this tier it is currently advisory only:
    /// <see cref="JwtSigningService{TOptions}"/> does not yet call
    /// <see cref="SigningKeyRotation.HasTooSoonPendingActivation"/> or otherwise surface a
    /// too-soon-pending-activation warning from it — that remains unimplemented follow-up work, not a
    /// guarantee of this type. Replaces ADR 0011's <c>AssumedJwksPropagationDelay</c>.
    /// </remarks>
    public TimeSpan PublicationLead { get; set; } = TimeSpan.FromHours(1);
}
