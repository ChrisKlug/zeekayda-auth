namespace ZeeKayDa.Auth.AzureKeyVault;

/// <summary>
/// Turns a Key Vault object's versions into the keys a source lists: every enabled version, dated
/// by vault metadata every replica agrees on.
/// </summary>
internal static class KeyVaultVersions
{
    /// <summary>
    /// The smallest <c>MaxVersions</c> a source accepts: a rotation has a staged, a signing and a
    /// previous version live at once.
    /// </summary>
    public const int MinimumMaxVersions = 3;

    /// <summary>
    /// Returns every enabled version. Disabling a version is the operator's revocation lever, so a
    /// disabled version is never listed.
    /// </summary>
    /// <exception cref="ZeeKayDaConfigurationException">
    /// Thrown with failure code <c>signing.azure_key_vault.no_enabled_version</c> when no version is
    /// enabled, or <c>signing.azure_key_vault.unversioned_key_uri</c> when a version's identifier is
    /// not pinned to that version.
    /// </exception>
    public static IReadOnlyList<TVersion> Enabled<TVersion>(
        IReadOnlyList<TVersion> allVersions, string objectKind, string objectName, Uri vaultUri)
        where TVersion : IKeyVaultVersionInfo
    {
        var enabled = allVersions.Where(v => v.Enabled).ToList();
        if (enabled.Count == 0)
        {
            throw new ZeeKayDaConfigurationException(
                new ZeeKayDaConfigurationFailure(
                    "signing.azure_key_vault.no_enabled_version",
                    $"No enabled version of Key Vault {objectKind} '{objectName}' in vault " +
                    $"'{vaultUri}' exists. Verify the {objectKind} has at least one enabled version."));
        }

        // The SDK's CryptographyClient resolves a versionless URI to the vault's latest version at
        // sign time — a key the published set may not contain.
        var unpinnedIndex = enabled.FindIndex(v => !v.Id.AbsolutePath.EndsWith($"/{v.Version}", StringComparison.Ordinal));
        if (unpinnedIndex >= 0)
        {
            var unpinned = enabled[unpinnedIndex];
            throw new ZeeKayDaConfigurationException(
                new ZeeKayDaConfigurationFailure(
                    "signing.azure_key_vault.unversioned_key_uri",
                    $"The identifier URI reported for Key Vault {objectKind} version '{unpinned.Version}' " +
                    "is not pinned to that version. Signing with an unpinned identifier would use whatever " +
                    "version is newest at sign time rather than the version whose public half was published."));
        }

        return enabled;
    }

    /// <summary>
    /// Returns the <paramref name="maxVersions"/> newest of <paramref name="enabled"/>, by
    /// <see cref="NotBefore"/>, or all of them when <paramref name="maxVersions"/> is
    /// <see langword="null"/>.
    /// </summary>
    public static IReadOnlyList<TVersion> Newest<TVersion>(IReadOnlyList<TVersion> enabled, int? maxVersions)
        where TVersion : IKeyVaultVersionInfo =>
        maxVersions is { } max ? [.. enabled.OrderByDescending(v => NotBefore(v)).Take(max)] : enabled;

    /// <summary>
    /// A version is published from its creation and may not sign before its own <c>nbf</c>, so it
    /// counts as dated from the later of the two.
    /// </summary>
    public static DateTimeOffset NotBefore(IKeyVaultVersionInfo version) =>
        version.NotBefore is { } notBefore && notBefore > version.CreatedOn ? notBefore : version.CreatedOn;
}
