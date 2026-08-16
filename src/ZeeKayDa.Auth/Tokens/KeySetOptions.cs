namespace ZeeKayDa.Auth.Tokens;

/// <summary>
/// Base options type for a <see cref="JwtSigningService{TOptions}"/> provider whose complete,
/// fixed set of keys is supplied at configuration time and never changes at runtime.
/// </summary>
/// <remarks>
/// The provider owns the full list of keys up front, and the only thing that ever advances is the
/// wall clock crossing each key's <c>ActivateAt</c>. File (PEM), PFX, and Windows Certificate Store
/// are the intended production consumers; development/in-memory signing is a trivial degenerate
/// case (one key, no <c>ActivateAt</c>, active from startup). Together with
/// <see cref="KeySourceOptions"/>, this is the sole signing-provider contract.
/// </remarks>
public abstract class KeySetOptions : JwtSigningServiceOptions
{
    /// <summary>
    /// Gets or sets how long before a key's <c>ActivateAt</c> its public half must already be
    /// published in the JWKS. Defaults to one hour.
    /// </summary>
    /// <remarks>
    /// The operator owns activation timing (via each key's <c>ActivateAt</c> in the provider's own
    /// configuration). <see cref="JwtSigningService{TOptions}"/> compares that timing against this
    /// value and logs a warning at startup if a rotated-in key's activation is scheduled sooner than
    /// this lead time allows.
    /// </remarks>
    public TimeSpan PublicationLead { get; set; } = TimeSpan.FromHours(1);
}
