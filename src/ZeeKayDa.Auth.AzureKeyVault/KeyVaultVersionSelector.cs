namespace ZeeKayDa.Auth.AzureKeyVault;

/// <summary>
/// Shared version-selection logic used by every Key Vault signing provider: both the remote and the
/// cached source read one Key Vault object's version history and derive the same version-to-slot
/// mapping from it, so the derivation lives here, once, generic over
/// <see cref="IKeyVaultVersionInfo"/>.
/// </summary>
internal static class KeyVaultVersionSelector
{
    /// <summary>
    /// Names the Key Vault object a selection runs over, for failure messages: the remote provider
    /// selects among versions of a <c>key</c>, the cached provider among versions of a
    /// <c>certificate</c>. Built through the two factories rather than positionally, so a caller
    /// cannot transpose the string members, and the operator-remedy property path is
    /// <c>nameof</c>-anchored to the real options member rather than a literal that a rename would
    /// silently stalen.
    /// </summary>
    internal readonly record struct SelectionContext(
        string ObjectKind, string ObjectName, Uri VaultUri, string PreActivationDelayPath)
    {
        public static SelectionContext ForKey(string name, Uri vaultUri) => new(
            "key", name, vaultUri,
            $"{nameof(AzureKeyVaultRemoteSigningOptions)}.{nameof(AzureKeyVaultRemoteSigningOptions.PreActivationDelay)}");

        public static SelectionContext ForCertificate(string name, Uri vaultUri) => new(
            "certificate", name, vaultUri,
            $"{nameof(AzureKeyVaultCachedSigningOptions)}.{nameof(AzureKeyVaultCachedSigningOptions.PreActivationDelay)}");
    }

    /// <summary>
    /// Selects the signing version and the versions published alongside it from
    /// <paramref name="allVersions"/>. A version is <b>eligible to sign</b> when it is enabled,
    /// inside its own validity window, and was created at least
    /// <paramref name="preActivationDelay"/> ago — except the chronologically-first version ever
    /// recorded (see <see cref="DetermineFirstEverVersion"/>), which is exempt from the delay. The
    /// newest eligible version signs; every enabled version newer than it is published as staged —
    /// not only the next in line, so two replicas whose restarts straddle a version ripening still
    /// publish each other's signing key — and up to <paramref name="previousVersionsToPublish"/>
    /// enabled versions older than it stay published. Published versions are ordered previous
    /// newest-first, then staged oldest-first.
    /// </summary>
    /// <param name="allVersions">
    /// Every version of the object, including disabled ones. Must be non-empty — the caller is
    /// expected to already fail closed on an empty listing, with its own provider-specific failure
    /// code, before calling this method.
    /// </param>
    /// <param name="previousVersionsToPublish">How many enabled versions older than the signing one
    /// stay published.</param>
    /// <param name="preActivationDelay">How long a version must have existed before it may sign.</param>
    /// <param name="now">The instant eligibility is evaluated at.</param>
    /// <param name="context">Names the object for failure messages.</param>
    /// <exception cref="ZeeKayDaConfigurationException">
    /// No version is enabled, no version is eligible to sign, or the signing version's identifier
    /// URI is not pinned to its version.
    /// </exception>
    public static (TVersion Signing, IReadOnlyList<TVersion> Published) SelectVersions<TVersion>(
        IReadOnlyList<TVersion> allVersions,
        int previousVersionsToPublish,
        TimeSpan preActivationDelay,
        DateTimeOffset now,
        SelectionContext context)
        where TVersion : IKeyVaultVersionInfo
    {
        var firstEverVersion = DetermineFirstEverVersion(allVersions);

        var enabledNewestFirst = allVersions
            .Where(v => v.Enabled)
            .OrderByDescending(v => v.CreatedOn)
            .ThenByDescending(v => v.Version, StringComparer.Ordinal)
            .ToList();

        if (enabledNewestFirst.Count == 0)
        {
            throw new ZeeKayDaConfigurationException(
                new ZeeKayDaConfigurationFailure(
                    "signing.azure_key_vault.no_active_key",
                    $"No enabled version of Key Vault {context.ObjectKind} '{context.ObjectName}' in vault " +
                    $"'{context.VaultUri}' exists. Verify the {context.ObjectKind} has at least one enabled " +
                    "version."));
        }

        var signingIndex = enabledNewestFirst.FindIndex(
            v => IsEligibleToSign(v, firstEverVersion, preActivationDelay, now));

        if (signingIndex < 0)
            throw NoEligibleVersion(enabledNewestFirst, preActivationDelay, now, context);

        var signing = enabledNewestFirst[signingIndex];

        // Defence-in-depth: the remote provider pins its signer to this URI, and the SDK's
        // CryptographyClient resolves a versionless URI to the vault's LATEST version — a key the
        // published set may not contain. The ring's self-test would catch the mismatched signature,
        // but an unpinned URI is rejected here, where the failure can still name its cause. The
        // cached provider downloads by version string instead, but a listing entry whose URI is not
        // version-pinned is a broken listing for it too.
        if (!signing.Id.AbsolutePath.EndsWith($"/{signing.Version}", StringComparison.Ordinal))
        {
            throw new ZeeKayDaConfigurationException(
                new ZeeKayDaConfigurationFailure(
                    "signing.azure_key_vault.unversioned_key_uri",
                    $"The identifier URI reported for Key Vault {context.ObjectKind} version '{signing.Version}' " +
                    "is not pinned to that version. Signing with an unpinned identifier would use whatever " +
                    "version is newest at sign time rather than the version whose public half was published."));
        }

        var previous = enabledNewestFirst.Skip(signingIndex + 1).Take(previousVersionsToPublish);
        var staged = enabledNewestFirst.Take(signingIndex).Reverse();

        return (signing, [.. previous, .. staged]);
    }

    /// <summary>
    /// Determines the chronologically-first version ever recorded for a Key Vault key or
    /// certificate, from the full version history. That version is the one exempt from the
    /// pre-activation age gate — a brand-new deployment has no earlier key whose relying parties
    /// need protecting.
    /// </summary>
    /// <remarks>
    /// Computed over every version, including disabled ones — never restricted to the enabled
    /// subset. Key Vault's list-versions read is only eventually consistent during a regional
    /// failover; if computed over a partial (enabled-only) read, a stale response could let
    /// version #2 masquerade as "first ever" and sign immediately, bypassing the configured
    /// pre-activation delay. Over the full history, a stale read can only omit every version
    /// outright, which the caller is expected to already fail closed on before calling this method.
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

    /// <summary>
    /// Whether <paramref name="version"/> may be selected as the signing version at
    /// <paramref name="now"/>: inside its own validity window, and created at least
    /// <paramref name="preActivationDelay"/> ago — so relying parties have had that long to pick
    /// its public half up from a published JWKS before it signs anything. The chronologically-first
    /// version ever recorded is exempt from the delay: there was no earlier key whose relying
    /// parties need protecting, and without the exemption a brand-new deployment could not start.
    /// </summary>
    private static bool IsEligibleToSign<TVersion>(
        in TVersion version, string firstEverVersion, TimeSpan preActivationDelay, DateTimeOffset now)
        where TVersion : IKeyVaultVersionInfo
    {
        if (version.NotBefore is { } notBefore && notBefore > now)
            return false;

        if (version.ExpiresOn is { } expiresOn && expiresOn <= now)
            return false;

        // Written as a difference from `now` rather than `CreatedOn <= now - delay`, which
        // underflows for a fake-clock `now` near DateTimeOffset.MinValue.
        return version.Version == firstEverVersion || now - version.CreatedOn >= preActivationDelay;
    }

    /// <summary>
    /// Builds the fail-closed error for "enabled versions exist, but none may sign yet", telling
    /// the operator when the youngest blocker ripens and naming the two remedies: wait, or lower
    /// the pre-activation delay and restart.
    /// </summary>
    private static ZeeKayDaConfigurationException NoEligibleVersion<TVersion>(
        IReadOnlyList<TVersion> enabledVersions,
        TimeSpan preActivationDelay,
        DateTimeOffset now,
        SelectionContext context)
        where TVersion : IKeyVaultVersionInfo
    {
        // Only genuine future instants qualify: an already-expired version's past EligibleAt must
        // not win the Min and turn "create a new version" into a wait that can never succeed.
        var ripensAt = enabledVersions
            .Select(v => (Version: v, At: EligibleAt(v, preActivationDelay)))
            .Where(c => c.At > now && (c.Version.ExpiresOn is null || c.At < c.Version.ExpiresOn))
            .Select(c => (DateTimeOffset?)c.At)
            .Min();

        var remedy = ripensAt is { } at
            ? $"The next version becomes eligible at {at:O}. Wait until then, or lower " +
              $"{context.PreActivationDelayPath} (0 disables the delay) and restart."
            : "Every enabled version has expired or expires before it would become eligible. Create a " +
              $"new {context.ObjectKind} version.";

        return new ZeeKayDaConfigurationException(
            new ZeeKayDaConfigurationFailure(
                "signing.azure_key_vault.no_eligible_version",
                $"Key Vault {context.ObjectKind} '{context.ObjectName}' in vault '{context.VaultUri}' has " +
                $"{enabledVersions.Count} enabled version(s), but none is eligible to sign: a version must be " +
                $"inside its own validity window and at least {preActivationDelay} old before it signs, " +
                $"so relying parties have had time to see it in a published JWKS. {remedy}"));
    }

    /// <summary>
    /// The instant <paramref name="version"/> satisfies both the age gate and its own
    /// <c>NotBefore</c> — the later of the two.
    /// </summary>
    private static DateTimeOffset EligibleAt<TVersion>(in TVersion version, TimeSpan preActivationDelay)
        where TVersion : IKeyVaultVersionInfo
    {
        var ageSatisfiedAt = version.CreatedOn + preActivationDelay;
        return version.NotBefore is { } notBefore && notBefore > ageSatisfiedAt ? notBefore : ageSatisfiedAt;
    }
}
