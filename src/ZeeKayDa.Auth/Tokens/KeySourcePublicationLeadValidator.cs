namespace ZeeKayDa.Auth.Tokens;

/// <summary>
/// Shared <c>PublicationLead</c> validation for both <see cref="KeySetOptions"/> and
/// <see cref="KeySourceOptions"/>. A concrete provider's own <c>IValidateOptions&lt;TOptions&gt;</c>
/// implementation should call <see cref="ValidateMinimum(string, TimeSpan)"/> (or, for a
/// <see cref="KeySourceOptions"/> caller, the <see cref="ValidateMinimum(string, KeySourceOptions)"/>
/// overload) — and, for a Tier B provider, also <see cref="ValidateAtLeastRefreshInterval"/> —
/// alongside its own provider-specific checks.
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
    /// Same validation as <see cref="ValidateMinimum(string, TimeSpan)"/>, for a <see cref="KeySourceOptions"/>
    /// caller. Reads <paramref name="options"/>'s raw, possibly-invalid <c>PublicationLead</c>
    /// directly rather than through <see cref="KeySourceOptions.PublicationLead"/> itself, so that
    /// property's own defensive invariant check does not throw out from under this validator before
    /// it gets the chance to turn an invalid value into its own friendly, aggregated error instead.
    /// </summary>
    /// <param name="optionsTypeName">The concrete options type's name, for the error message.</param>
    /// <param name="options">The options instance to validate.</param>
    /// <returns>
    /// The error message to add to the validator's error list, or <see langword="null"/> when the
    /// value is valid.
    /// </returns>
    public static string? ValidateMinimum(string optionsTypeName, KeySourceOptions options)
    {
        ArgumentNullException.ThrowIfNull(optionsTypeName);
        ArgumentNullException.ThrowIfNull(options);

        return ValidateMinimum(optionsTypeName, options.RawPublicationLead);
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

        // Reads RawPublicationLead, not PublicationLead: this validator's whole job is to inspect a
        // possibly-invalid value and turn it into a friendly, aggregated error message — it must not
        // have PublicationLead's own defensive invariant check (KeySourceOptions.PublicationLead)
        // throw out from under it before it gets the chance.
        if (options.RawPublicationLead < options.RefreshInterval)
        {
            return $"{optionsTypeName}.PublicationLead ({options.RawPublicationLead}) must be greater than " +
                   $"or equal to {optionsTypeName}.RefreshInterval ({options.RefreshInterval}).";
        }

        return null;
    }
}
