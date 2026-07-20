namespace ZeeKayDa.Auth.Tokens;

/// <summary>
/// Validates <c>AssumedJwksPropagationDelay</c>, shared by the File-based and Windows Certificate
/// Store signing providers (ADR 0011 §3.5, issue #409; security review of PR #414).
/// </summary>
/// <remarks>
/// Unlike Azure Key Vault's <c>SigningKeyActivationDelay</c> (validated in
/// <c>ZeeKayDa.Auth.AzureKeyVault.KeyVaultActivationDelay</c>), <c>AssumedJwksPropagationDelay</c> is
/// never used to compute or gate an actual activation time — it is a diagnostic heuristic feeding
/// <see cref="SigningKeyRotation.HasTooSoonPendingActivation"/>'s too-soon-<c>NotBefore</c> warning.
/// A too-short value therefore cannot reintroduce a real token-trust race the way a too-short
/// <c>SigningKeyActivationDelay</c> could, so this only rejects a value that would silently disable
/// the warning entirely (zero or negative), and otherwise warns rather than hard-fails.
/// </remarks>
internal static class JwksPropagationDelay
{
    /// <summary>
    /// Validates that, when set, <paramref name="assumedJwksPropagationDelay"/> is strictly
    /// positive. Returns the error message to add to the validator's error list, or
    /// <see langword="null"/> when the value is valid or unset.
    /// </summary>
    public static string? ValidatePositive(string optionsTypeName, TimeSpan? assumedJwksPropagationDelay)
    {
        if (assumedJwksPropagationDelay is { } delay && delay <= TimeSpan.Zero)
        {
            return $"{optionsTypeName}.AssumedJwksPropagationDelay ({delay}) must be greater than " +
                   "zero. A zero or negative value silently disables the too-soon-NotBefore warning " +
                   "this property exists to raise (ADR 0011 §3.5).";
        }

        return null;
    }

    /// <summary>
    /// Returns a non-blocking warning message when <paramref name="assumedJwksPropagationDelay"/> is
    /// set and shorter than <paramref name="keyRotationCheckInterval"/>, or <see langword="null"/>
    /// when the value is valid, unset, or already rejected by <see cref="ValidatePositive"/>.
    /// </summary>
    public static string? WarnIfShorterThanCheckInterval(
        string optionsTypeName, TimeSpan? assumedJwksPropagationDelay, TimeSpan keyRotationCheckInterval)
    {
        if (assumedJwksPropagationDelay is { } delay && delay > TimeSpan.Zero && delay < keyRotationCheckInterval)
        {
            return $"{optionsTypeName}.AssumedJwksPropagationDelay ({delay}) is shorter than " +
                   $"{optionsTypeName}.KeyRotationCheckInterval ({keyRotationCheckInterval}). The " +
                   "too-soon-NotBefore warning is only evaluated when this provider reloads its key " +
                   "set, so a value shorter than the poll cadence may miss a key whose activation " +
                   "window has already elapsed by the next reload, silently skipping the warning it " +
                   "exists to raise (ADR 0011 §3.5, PR #414 security review).";
        }

        return null;
    }
}
