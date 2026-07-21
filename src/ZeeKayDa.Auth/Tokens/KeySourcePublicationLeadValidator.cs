namespace ZeeKayDa.Auth.Tokens;

/// <summary>
/// Validates the <see cref="KeySourceOptions.PublicationLead"/> &gt;= <see cref="KeySourceOptions.RefreshInterval"/>
/// invariant (ADR 0015 §1), shared by every Tier B signing-provider options validator.
/// </summary>
/// <remarks>
/// This is a config-level relationship — the publication lead must be at least one poll cycle — not
/// per-key state. A concrete Tier B provider's own <c>IValidateOptions&lt;TOptions&gt;</c>
/// implementation should call <see cref="ValidateInvariant"/> alongside its own provider-specific
/// checks, the same way <see cref="JwksPropagationDelay"/> is shared by Tier A providers.
/// </remarks>
public static class KeySourcePublicationLeadValidator
{
    /// <summary>
    /// Validates that <paramref name="options"/>'s <see cref="KeySourceOptions.PublicationLead"/> is
    /// not shorter than its <see cref="KeySourceOptions.RefreshInterval"/>.
    /// </summary>
    /// <param name="optionsTypeName">The concrete options type's name, for the error message.</param>
    /// <param name="options">The options instance to validate.</param>
    /// <returns>
    /// The error message to add to the validator's error list, or <see langword="null"/> when the
    /// invariant holds.
    /// </returns>
    public static string? ValidateInvariant(string optionsTypeName, KeySourceOptions options)
    {
        ArgumentNullException.ThrowIfNull(optionsTypeName);
        ArgumentNullException.ThrowIfNull(options);

        if (options.PublicationLead < options.RefreshInterval)
        {
            return $"{optionsTypeName}.PublicationLead ({options.PublicationLead}) must be greater than " +
                   $"or equal to {optionsTypeName}.RefreshInterval ({options.RefreshInterval}). The lead " +
                   "must span at least one poll cycle, or a key could become active before its public " +
                   "half has ever been re-read and published (ADR 0015 §1).";
        }

        return null;
    }
}
