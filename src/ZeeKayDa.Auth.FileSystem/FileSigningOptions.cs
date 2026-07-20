using ZeeKayDa.Auth.Tokens;

namespace ZeeKayDa.Auth.FileSystem;

/// <summary>
/// Shared base options type for the PEM and PFX file-based signing providers, mirroring
/// <see cref="FileSigningJwtSigningService{TOptions}"/> at the service level.
/// </summary>
/// <remarks>
/// <see cref="RotatingKeySourceOptions.KeyRotationCheckInterval"/> is inherited from the base
/// class and defaults to 5 minutes. Unlike the Azure Key Vault providers, this value does not gate
/// a re-download of private key material — every registered file is re-read from disk on every
/// refresh, which has no external cost.
/// </remarks>
public abstract class FileSigningOptions : RotatingKeySourceOptions
{
    /// <summary>
    /// Gets or sets the assumed worst-case delay before a newly-published key's public material
    /// has propagated to relying parties' JWKS caches, used as the threshold for warning when a
    /// rotated-in file's certificate <c>NotBefore</c> is scheduled too soon (ADR 0011 §3.5; see
    /// <see cref="SigningKeyRotation.HasTooSoonPendingActivation"/>). When unset (the default),
    /// defaults to <see cref="RotatingKeySourceOptions.KeyRotationCheckInterval"/>.
    /// </summary>
    public TimeSpan? AssumedJwksPropagationDelay { get; set; }
}
