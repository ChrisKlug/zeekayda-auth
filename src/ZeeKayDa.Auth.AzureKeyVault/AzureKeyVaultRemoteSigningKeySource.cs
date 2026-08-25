using System.Security.Cryptography;
using Microsoft.Extensions.Options;
using ZeeKayDa.Auth.Tokens;

namespace ZeeKayDa.Auth.AzureKeyVault;

/// <summary>
/// An <see cref="ISigningKeySource"/> that serves the versions of one Azure Key Vault (or Managed
/// HSM) key and signs remotely inside the vault. The private key never leaves the vault and is
/// never held in process memory — every signature is a network round trip to Key Vault's
/// <c>CryptographyClient</c>.
/// </summary>
/// <remarks>
/// <para>
/// Read once, never re-read: the ring reads this source exactly once at startup, and the read is
/// memoized here too, so a version added, disabled, or replaced after startup has no effect until
/// the host restarts.
/// </para>
/// <para>
/// The version-to-slot mapping is derived entirely from the vault's own durable per-version
/// metadata (<c>CreatedOn</c>, <c>Enabled</c>, <c>NotBefore</c>, <c>ExpiresOn</c>), so every
/// replica and every restart derives the same answer with no local state. A version is <b>eligible
/// to sign</b> when it is enabled, inside its own validity window, and was created at least
/// <see cref="AzureKeyVaultRemoteSigningOptions.PreActivationDelay"/> ago — except the
/// chronologically-first version ever recorded, which is exempt from the delay so a brand-new
/// deployment starts without waiting (see <see cref="KeyVaultVersionSelector"/>). The newest
/// eligible version signs; the oldest enabled version newer than it (still ripening through the
/// delay, or carrying a future <c>NotBefore</c>) is published as staged; and up to
/// <see cref="AzureKeyVaultRemoteSigningOptions.PreviousVersionsToPublish"/> enabled versions older
/// than the signing one stay published so relying parties can verify tokens they signed.
/// </para>
/// <para>
/// Disabling a version in the vault is the operator's revocation lever: a disabled version is
/// excluded from every slot unconditionally. An expired-but-enabled older version still publishes —
/// tokens it signed before expiry are still within their own lifetime — until the operator disables
/// it.
/// </para>
/// <para>
/// A failed or empty vault read always throws — never a partial key set — so a vault outage is
/// never indistinguishable from a revocation.
/// </para>
/// <para>
/// This source performs no algorithm/key-type check of its own.
/// <see cref="SigningKeySetBuilder"/> validates every reported key's algorithm against its key type
/// and EC curve, keyed on the source id — which here is the Key Vault version string, so its
/// failures still name the offending version — and the ring's per-handoff self-test is the pairing
/// check.
/// </para>
/// </remarks>
internal sealed class AzureKeyVaultRemoteSigningKeySource : ISigningKeySource
{
    private readonly IOptions<AzureKeyVaultRemoteSigningOptions> _options;
    private readonly IKeyVaultKeyReader _keyReader;
    private readonly IKeyVaultSigner _signer;
    private readonly TimeProvider _timeProvider;

    // Serialises reads so the vault is read exactly once even if two callers read concurrently —
    // "only the ring calls this" is not something this type can enforce. Deliberately not disposed:
    // disposing it would make a read already in flight at shutdown throw from its own Release, and
    // would strand any reader queued behind it.
    private readonly SemaphoreSlim _readGate = new(1, 1);

    // The one key set this source ever reports. Assigned only after every selected version's public
    // material has been fetched, so a failed read is never cached and a retry re-reads the vault;
    // once a read has succeeded, no later one can observe a version rotated in after startup.
    private SourceKeySet? _keySet;

    // The signing version the memoized read selected, with the versioned key URI its signer is
    // pinned to. volatile: written under _readGate, read by CreateSignerAsync without it — no
    // happens-before edge otherwise connects the two.
    private volatile SigningVersion? _signingVersion;

    public AzureKeyVaultRemoteSigningKeySource(
        IOptions<AzureKeyVaultRemoteSigningOptions> options,
        IKeyVaultKeyReader keyReader,
        IKeyVaultSigner signer,
        TimeProvider timeProvider)
    {
        ArgumentNullException.ThrowIfNull(options);
        ArgumentNullException.ThrowIfNull(keyReader);
        ArgumentNullException.ThrowIfNull(signer);
        ArgumentNullException.ThrowIfNull(timeProvider);

        _options = options;
        _keyReader = keyReader;
        _signer = signer;
        _timeProvider = timeProvider;
    }

    /// <inheritdoc/>
    public async ValueTask<SourceKeySet> ReadAsync(CancellationToken cancellationToken = default)
    {
        await _readGate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            if (_keySet is not null)
                return _keySet;

            var options = _options.Value;

            var allVersions = new List<KeyVaultKeyVersionInfo>();
            await foreach (var version in _keyReader.GetKeyVersionsAsync(cancellationToken).ConfigureAwait(false))
                allVersions.Add(version);

            if (allVersions.Count == 0)
            {
                throw new ZeeKayDaConfigurationException(
                    new ZeeKayDaConfigurationFailure(
                        "signing.azure_key_vault.no_key_versions",
                        $"Key Vault key '{options.KeyIdentifier.Name}' in vault '{options.KeyIdentifier.VaultUri}' " +
                        "has no versions. Create at least one key version before starting the host."));
            }

            // See KeyVaultVersionSelector.DetermineFirstEverVersion for why this is computed over
            // every version, including disabled ones, rather than over the enabled subset below.
            var firstEverVersion = KeyVaultVersionSelector.DetermineFirstEverVersion(allVersions);

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
                        $"No enabled version of Key Vault key '{options.KeyIdentifier.Name}' in vault " +
                        $"'{options.KeyIdentifier.VaultUri}' exists. Verify the key has at least one " +
                        "enabled version."));
            }

            var now = _timeProvider.GetUtcNow();
            var signingIndex = enabledNewestFirst.FindIndex(
                v => IsEligibleToSign(v, firstEverVersion, options.PreActivationDelay, now));

            if (signingIndex < 0)
                throw NoEligibleVersion(options, enabledNewestFirst, now);

            var signing = enabledNewestFirst[signingIndex];

            // Staged: the version next in line — the OLDEST enabled version newer than the signing
            // one. Even newer versions stay unpublished until later restarts move them up the line.
            KeyVaultKeyVersionInfo? staged = signingIndex > 0 ? enabledNewestFirst[signingIndex - 1] : null;

            var previous = enabledNewestFirst
                .Skip(signingIndex + 1)
                .Take(options.PreviousVersionsToPublish)
                .ToList();

            var signingKey = await ToSourceKeyAsync(signing, options, cancellationToken).ConfigureAwait(false);

            var alsoPublished = new List<SourceKey>(previous.Count + 1);
            foreach (var version in previous)
                alsoPublished.Add(await ToSourceKeyAsync(version, options, cancellationToken).ConfigureAwait(false));
            if (staged is { } stagedVersion)
                alsoPublished.Add(await ToSourceKeyAsync(stagedVersion, options, cancellationToken).ConfigureAwait(false));

            _signingVersion = new SigningVersion(signing.Version, signing.Id);
            return _keySet = new SourceKeySet(signingKey, [.. alsoPublished]);
        }
        finally
        {
            _readGate.Release();
        }
    }

    /// <inheritdoc/>
    public ValueTask<ISigner> CreateSignerAsync(SourceKeyId id, CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();

        var signingVersion = _signingVersion;

        // Only the version the memoized read selected as the signing key is ever openable for
        // signing. Published-only versions never sign, so an id naming one of them — or an id
        // arriving before any successful read — is a defect in the caller rather than a request
        // this source should honour.
        if (signingVersion is null || !string.Equals(signingVersion.Version, id.Value, StringComparison.Ordinal))
        {
            throw new InvalidOperationException(
                $"{nameof(CreateSignerAsync)} was called for key '{id.Value}', which is not the Key Vault " +
                "key version this source most recently reported as the signing key. This source reads the " +
                "vault exactly once, so the reported signing version cannot change after startup, and only " +
                "it ever signs.");
        }

        return new ValueTask<ISigner>(new KeyVaultRemoteSigner(
            _signer, signingVersion.KeyVersionUri, signingVersion.Version, _options.Value.Algorithm));
    }

    /// <summary>
    /// Whether <paramref name="version"/> may be selected as the signing version at
    /// <paramref name="now"/>: inside its own validity window, and created at least
    /// <paramref name="preActivationDelay"/> ago — so relying parties have had that long to pick its
    /// public half up from a published JWKS before it signs anything. The chronologically-first
    /// version ever recorded is exempt from the delay: there was no earlier key whose relying
    /// parties need protecting, and without the exemption a brand-new deployment could not start.
    /// </summary>
    private static bool IsEligibleToSign(
        in KeyVaultKeyVersionInfo version, string firstEverVersion, TimeSpan preActivationDelay, DateTimeOffset now)
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
    /// Builds the fail-closed error for "enabled versions exist, but none may sign yet", telling the
    /// operator when the youngest blocker ripens and naming the two remedies: wait, or lower
    /// <see cref="AzureKeyVaultRemoteSigningOptions.PreActivationDelay"/> and restart.
    /// </summary>
    private static ZeeKayDaConfigurationException NoEligibleVersion(
        AzureKeyVaultRemoteSigningOptions options,
        IReadOnlyList<KeyVaultKeyVersionInfo> enabledVersions,
        DateTimeOffset now)
    {
        var ripensAt = enabledVersions
            .Where(v => v.ExpiresOn is null || v.ExpiresOn > now)
            .Select(v => (DateTimeOffset?)EligibleAt(v, options.PreActivationDelay))
            .Min();

        var remedy = ripensAt is { } at
            ? $"The next version becomes eligible at {at:O}. Wait until then, or lower " +
              $"{nameof(AzureKeyVaultRemoteSigningOptions)}.{nameof(AzureKeyVaultRemoteSigningOptions.PreActivationDelay)} " +
              "(0 disables the delay) and restart."
            : "Every enabled version has expired. Create a new key version.";

        return new ZeeKayDaConfigurationException(
            new ZeeKayDaConfigurationFailure(
                "signing.azure_key_vault.no_eligible_version",
                $"Key Vault key '{options.KeyIdentifier.Name}' in vault '{options.KeyIdentifier.VaultUri}' has " +
                $"{enabledVersions.Count} enabled version(s), but none is eligible to sign: a version must be " +
                $"inside its own validity window and at least {options.PreActivationDelay} old before it signs, " +
                $"so relying parties have had time to see it in a published JWKS. {remedy}"));
    }

    /// <summary>
    /// The instant <paramref name="version"/> satisfies both the age gate and its own
    /// <c>NotBefore</c> — the later of the two.
    /// </summary>
    private static DateTimeOffset EligibleAt(in KeyVaultKeyVersionInfo version, TimeSpan preActivationDelay)
    {
        var ageSatisfiedAt = version.CreatedOn + preActivationDelay;
        return version.NotBefore is { } notBefore && notBefore > ageSatisfiedAt ? notBefore : ageSatisfiedAt;
    }

    /// <summary>
    /// Fetches <paramref name="version"/>'s public material from the vault and maps it to a
    /// <see cref="SourceKey"/>. Only public halves are ever fetched — Key Vault's
    /// <c>GetKey</c> cannot return private material for a non-exportable key at all.
    /// </summary>
    private async ValueTask<SourceKey> ToSourceKeyAsync(
        KeyVaultKeyVersionInfo version, AzureKeyVaultRemoteSigningOptions options, CancellationToken cancellationToken)
    {
        var (rawPublicKey, keyType) = await _keyReader
            .GetKeyMaterialAsync(version.Version, cancellationToken).ConfigureAwait(false);

        using var publicKey = rawPublicKey;

        return new SourceKey(
            new SourceKeyId(version.Version),
            options.Algorithm,
            ToPublicKeyParameters(publicKey, keyType),
            ExpiresAt: version.ExpiresOn,
            NotBefore: version.NotBefore);
    }

    /// <summary>
    /// Exports <paramref name="publicKey"/>'s public parameters. The cast is safe:
    /// <see cref="IKeyVaultKeyReader.GetKeyMaterialAsync"/> only ever returns an <see cref="RSA"/>
    /// paired with <see cref="SigningKeyType.Rsa"/> or an <see cref="ECDsa"/> paired with
    /// <see cref="SigningKeyType.Ec"/>.
    /// </summary>
    private static PublicKeyParameters ToPublicKeyParameters(AsymmetricAlgorithm publicKey, SigningKeyType keyType) =>
        keyType == SigningKeyType.Rsa
            ? PublicKeyParameters.FromRsa(((RSA)publicKey).ExportParameters(false))
            : PublicKeyParameters.FromEc(((ECDsa)publicKey).ExportParameters(false));

    /// <summary>
    /// The signing version a successful read selected: its version string (the source key id) and
    /// the versioned key URI its signer is pinned to.
    /// </summary>
    private sealed record SigningVersion(string Version, Uri KeyVersionUri);

    /// <summary>
    /// <see cref="ISigner"/> wrapper over the shared, DI-owned <see cref="IKeyVaultSigner"/> seam
    /// for one activation of one Key Vault key version. The private key never leaves Key Vault —
    /// every <see cref="SignAsync"/> call is a network round trip.
    /// </summary>
    /// <remarks>
    /// <see cref="Dispose"/> is deliberately a no-op: <paramref name="signer"/> is a shared seam
    /// that outlives any one activation, so disposing it here would break every later signer built
    /// over it.
    /// </remarks>
    private sealed class KeyVaultRemoteSigner(IKeyVaultSigner signer, Uri keyVersionUri, string version, SigningAlgorithm algorithm)
        : ISigner
    {
        public ValueTask<ReadOnlyMemory<byte>> SignAsync(
            ReadOnlyMemory<byte> signingInput, CancellationToken cancellationToken = default) =>
            signer.SignAsync(keyVersionUri, version, algorithm, signingInput.ToArray(), cancellationToken);

        public void Dispose()
        {
            // Intentionally empty — see the class remarks.
        }

        public SigningAlgorithm Algorithm => algorithm;
    }
}
