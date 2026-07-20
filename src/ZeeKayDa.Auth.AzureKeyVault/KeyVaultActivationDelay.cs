namespace ZeeKayDa.Auth.AzureKeyVault;

/// <summary>
/// Resolves and validates <c>SigningKeyActivationDelay</c> against <c>KeyRotationCheckInterval</c>,
/// shared by both Key Vault signing providers (ADR 0011 §3.5, issue #409).
/// </summary>
/// <remarks>
/// The invariant <c>SigningKeyActivationDelay &gt;= KeyRotationCheckInterval</c> — a
/// newly-published key must not be able to activate before the process would even poll and notice
/// it exists — is enforced in exactly two places: (a) this type's
/// <see cref="ValidateNotShorterThanCheckInterval"/>, called from both Key Vault option validators,
/// and (b) independently inside <see cref="KeyVaultSigningKeyRotation.BuildActivationTimeline{T}"/>
/// itself, so a future custom KMS/HSM provider modeled on this pattern cannot silently reintroduce
/// the activation race by forgetting a cross-field validator.
/// </remarks>
internal static class KeyVaultActivationDelay
{
    /// <summary>
    /// Resolves the effective activation delay: <paramref name="signingKeyActivationDelay"/> when
    /// set, otherwise <paramref name="keyRotationCheckInterval"/>.
    /// </summary>
    public static TimeSpan Resolve(TimeSpan? signingKeyActivationDelay, TimeSpan keyRotationCheckInterval)
        => signingKeyActivationDelay ?? keyRotationCheckInterval;

    /// <summary>
    /// Validates that, when set, <paramref name="signingKeyActivationDelay"/> is not shorter than
    /// <paramref name="keyRotationCheckInterval"/>. Returns the error message to add to the
    /// validator's error list, or <see langword="null"/> when the value is valid or unset.
    /// </summary>
    public static string? ValidateNotShorterThanCheckInterval(
        string optionsTypeName, TimeSpan? signingKeyActivationDelay, TimeSpan keyRotationCheckInterval)
    {
        if (signingKeyActivationDelay is { } delay && delay < keyRotationCheckInterval)
        {
            return $"{optionsTypeName}.SigningKeyActivationDelay ({delay}) must be greater than or " +
                   $"equal to {optionsTypeName}.KeyRotationCheckInterval ({keyRotationCheckInterval}). " +
                   "A newly-published key must not be able to activate before the process would even " +
                   "poll and notice it exists (ADR 0011 §3.5).";
        }

        return null;
    }
}
