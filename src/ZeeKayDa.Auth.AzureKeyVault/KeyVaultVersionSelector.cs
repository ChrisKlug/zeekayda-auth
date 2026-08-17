namespace ZeeKayDa.Auth.AzureKeyVault;

/// <summary>
/// Shared version-selection logic used by every Key Vault signing provider's <c>ListKeysAsync</c>.
/// </summary>
internal static class KeyVaultVersionSelector
{
    /// <summary>
    /// Determines the chronologically-first version ever recorded for a Key Vault key or
    /// certificate, from the full version history.
    /// </summary>
    /// <remarks>
    /// Computed over every version, including disabled ones — never restricted to the enabled
    /// subset. Key Vault's list-versions read is only eventually consistent during a regional
    /// failover; if computed over a partial (enabled-only) read, a stale response could let
    /// version #2 masquerade as "first ever" and activate immediately, bypassing the configured
    /// publication lead. Over the full history, a stale read can only omit every version outright,
    /// which the caller is expected to already fail closed on before calling this method.
    /// </remarks>
    /// <param name="allVersions">
    /// Every version of the key or certificate, including disabled ones. Must be non-empty — the
    /// caller is expected to already fail closed on an empty listing before calling this method
    /// (see remarks); this is enforced here rather than left as an undocumented LINQ precondition.
    /// </param>
    /// <returns>The version string of the chronologically-first version.</returns>
    public static string DetermineFirstEverVersion<TVersion>(IReadOnlyList<TVersion> allVersions)
        where TVersion : IKeyVaultVersionInfo
    {
        if (allVersions.Count == 0)
            throw new ArgumentException("At least one version is required.", nameof(allVersions));

        return allVersions
            .OrderBy(v => v.CreatedOn)
            .ThenBy(v => v.Version, StringComparer.Ordinal)
            .First()
            .Version;
    }
}
