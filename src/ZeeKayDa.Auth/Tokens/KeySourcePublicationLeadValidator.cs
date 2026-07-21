namespace ZeeKayDa.Auth.Tokens;

/// <summary>
/// Shared <c>PublicationLead</c> validation for both <see cref="KeySetOptions"/> and
/// <see cref="KeySourceOptions"/>. A concrete provider's own <c>IValidateOptions&lt;TOptions&gt;</c>
/// implementation should call <see cref="ValidateMinimum"/> — and, for a Tier B provider, also
/// <see cref="ValidateAtLeastRefreshInterval"/> — alongside its own provider-specific checks.
/// </summary>
public static class KeySourcePublicationLeadValidator
{
    private static readonly TimeSpan MinimumPublicationLead = TimeSpan.FromMinutes(1);

    /// <summary>
    /// Validates that <paramref name="publicationLead"/> is at least one minute. A shorter value
    /// leaves too little time for a relying party to observe a key's public half in the JWKS before
    /// it becomes active.
    /// </summary>
    /// <param name="optionsTypeName">The concrete options type's name, for the error message.</param>
    /// <param name="publicationLead">The <c>PublicationLead</c> value to validate.</param>
    /// <returns>
    /// The error message to add to the validator's error list, or <see langword="null"/> when the
    /// value is valid.
    /// </returns>
    public static string? ValidateMinimum(string optionsTypeName, TimeSpan publicationLead)
    {
        ArgumentNullException.ThrowIfNull(optionsTypeName);

        if (publicationLead < MinimumPublicationLead)
        {
            return $"{optionsTypeName}.PublicationLead ({publicationLead}) must be at least " +
                   $"{MinimumPublicationLead}.";
        }

        return null;
    }

    /// <summary>
    /// Validates that <paramref name="options"/>'s <see cref="KeySourceOptions.PublicationLead"/> is
    /// not shorter than its <see cref="KeySourceOptions.RefreshInterval"/> — the lead must span at
    /// least one poll cycle, or a key could become active before its public half has ever been
    /// re-read and published.
    /// </summary>
    /// <param name="optionsTypeName">The concrete options type's name, for the error message.</param>
    /// <param name="options">The options instance to validate.</param>
    /// <returns>
    /// The error message to add to the validator's error list, or <see langword="null"/> when the
    /// invariant holds.
    /// </returns>
    public static string? ValidateAtLeastRefreshInterval(string optionsTypeName, KeySourceOptions options)
    {
        ArgumentNullException.ThrowIfNull(optionsTypeName);
        ArgumentNullException.ThrowIfNull(options);

        if (options.PublicationLead < options.RefreshInterval)
        {
            return $"{optionsTypeName}.PublicationLead ({options.PublicationLead}) must be greater than " +
                   $"or equal to {optionsTypeName}.RefreshInterval ({options.RefreshInterval}).";
        }

        return null;
    }
}
