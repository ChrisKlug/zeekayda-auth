using Microsoft.Extensions.Options;
using ZeeKayDa.Auth.Logging;
using ZeeKayDa.Auth.Tokens;

namespace ZeeKayDa.Auth.AzureKeyVault;

/// <summary>
/// <see cref="IJwtSigningService"/> that signs remotely inside Azure Key Vault. The private key
/// never leaves the vault and is never held in process memory — every <see cref="IJwtSigningService.SignAsync"/>
/// call is a network round trip to Key Vault's <c>CryptographyClient</c>.
/// </summary>
/// <remarks>
/// <para>
/// ADR 0015 Tier B (<see cref="KeySourceOptions"/>, issue #425): <see cref="ListKeysAsync"/> re-asks
/// Key Vault for the key's current version list once per <see cref="KeySourceOptions.RefreshInterval"/>
/// — Key Vault, not this provider, owns the key's version history. Every returned
/// <see cref="KeyListing.ActivateAt"/> is derived entirely from Key Vault's own durable per-version
/// <c>CreatedOn</c> timestamp (<c>ActivateAt = CreatedOn + PublicationLead</c>), never from when this
/// process first observed the version — stateless, restart-safe, and identical across every replica.
/// The key version that was created first of all (by <c>CreatedOn</c>, tie-broken by version
/// identifier) is eligible from startup (<c>ActivateAt = null</c>), so the base class's ordinary
/// activation-timeline logic covers the "first ever version" bootstrap case with no special-case
/// code here.
/// </para>
/// <para>
/// Kill-by-omission (ADR 0015 §6) is entirely the base class's concern: this provider's only
/// obligation is to list currently-enabled versions and let a version silently drop out of the
/// returned list once Key Vault stops reporting it as enabled. There is no separate <c>Enabled</c>
/// flag anywhere in this contract.
/// </para>
/// <para>
/// <c>kid</c> is the RFC 7638 JWK thumbprint of each version's public key, derived by the base class
/// from each <see cref="KeyListing.PublicKey"/> — never the raw Key Vault version identifier, which
/// is only this provider's own internal <see cref="KeyId"/> (ADR 0015 §2).
/// </para>
/// <para>
/// <see cref="CreateSignerAsync"/> returns a small <see cref="ISigner"/> wrapper
/// (<see cref="KeyVaultRemoteSigner"/>) whose <see cref="ISigner.SignAsync"/> dispatches to the
/// shared, DI-owned <see cref="IKeyVaultSigner"/> seam. <see cref="IDisposable.Dispose"/> on that
/// wrapper is a deliberate no-op: it never disposes <see cref="IKeyVaultSigner"/> or any pooled
/// <c>CryptographyClient</c> it may hold, since those are shared across every activation and every
/// other <see cref="ISigner"/> instance (ADR 0015 §2/Security Considerations item 5).
/// </para>
/// </remarks>
internal sealed class AzureKeyVaultRemoteSigningJwtSigningService : JwtSigningService<AzureKeyVaultRemoteSigningOptions>
{
    private readonly IOptions<AzureKeyVaultRemoteSigningOptions> _options;
    private readonly IKeyVaultKeyReader _keyReader;
    private readonly IKeyVaultSigner _signer;

    // Populated wholesale on every ListKeysAsync call. CreateSignerAsync is only ever invoked for a
    // KeyId that appeared on a KeyListing this same ListKeysAsync call most recently returned (per
    // JwtSigningService{TOptions}.CreateSignerAsync's own contract), so looking up the corresponding
    // versioned key URI and kid here is always safe. Replaced entirely (never mutated in place) on
    // each refresh — never mutated in place, mirroring the base class's own snapshot replacement.
    // volatile: ListKeysAsync writes this field under the base class's snapshot lock
    // (JwtSigningService{TOptions}.EnsureSnapshotAsync), while CreateSignerAsync reads it under the
    // base class's separate signer lock (EnsureActiveSignerAsync). Those are two different monitors
    // with no happens-before edge between them, so without volatile a reader thread could observe a
    // stale (possibly pre-initialization-complete) reference to the dictionary object itself.
    private volatile IReadOnlyDictionary<string, (Uri KeyVersionUri, string Kid)> _versionMetadataById =
        new Dictionary<string, (Uri, string)>(StringComparer.Ordinal);

    /// <summary>
    /// Initialises the service with its options, time source, and the Key Vault seams it signs and
    /// reads key metadata through.
    /// </summary>
    public AzureKeyVaultRemoteSigningJwtSigningService(
        IOptions<AzureKeyVaultRemoteSigningOptions> options,
        TimeProvider timeProvider,
        IKeyVaultKeyReader keyReader,
        IKeyVaultSigner signer,
        ISigningKeyRetirementWindowProvider retirementWindowProvider,
        ISanitizingLogger<JwtSigningService<AzureKeyVaultRemoteSigningOptions>> logger)
        : base(options, timeProvider, retirementWindowProvider, logger)
    {
        ArgumentNullException.ThrowIfNull(keyReader);
        ArgumentNullException.ThrowIfNull(signer);

        _options = options;
        _keyReader = keyReader;
        _signer = signer;
    }

    /// <inheritdoc/>
    protected override async ValueTask<IReadOnlyList<KeyListing>> ListKeysAsync(CancellationToken cancellationToken)
    {
        var options = _options.Value;
        var keyIdentifier = options.KeyIdentifier;

        var allVersions = new List<KeyVaultKeyVersionInfo>();
        await foreach (var version in _keyReader.GetKeyVersionsAsync(cancellationToken).ConfigureAwait(false))
            allVersions.Add(version);

        if (allVersions.Count == 0)
        {
            throw new ZeeKayDaConfigurationException(
                new ZeeKayDaConfigurationFailure(
                    "signing.azure_key_vault.no_key_versions",
                    $"Key Vault key '{keyIdentifier.Name}' in vault '{keyIdentifier.VaultUri}' has no versions. " +
                    "Create at least one key version before starting the host."));
        }

        // Computed over allVersions — every version this key has ever recorded, including disabled
        // ones — never over enabledVersions below. This is deliberate, not an oversight: Key
        // Vault's list-key-versions read is only eventually consistent during a rare
        // Microsoft-initiated regional failover, and a stale/incomplete read during exactly that
        // window could transiently omit the true first-ever version. Computing "first ever" only
        // over whatever subset happened to come back would then let version #2 masquerade as the
        // first-ever version and activate immediately (ActivateAt = null), bypassing
        // PublicationLead entirely and exposing relying parties to a key they never had a chance to
        // observe in the JWKS first. Computing over the full, unfiltered history instead means a
        // stale read can only affect this derivation by omitting every version outright, which
        // already fails closed via the "no key versions" check above rather than silently promoting
        // the wrong version. This mirrors the risk analysis accepted for issue #300 (see ADR 0011,
        // Changelog, 2026-07-04 entry) for the original Key Vault provider.
        var firstEverVersion = allVersions
            .OrderBy(v => v.CreatedOn)
            .ThenBy(v => v.Version, StringComparer.Ordinal)
            .First()
            .Version;

        // Enabled is a Key Vault-side concept only — folded into "list enabled versions only" here
        // (ADR 0015 §6/§10) rather than surfaced as a flag anywhere in the KeyListing/options
        // contract. The base class's own kill-by-omission logic takes it from there.
        var enabledVersions = allVersions.Where(v => v.Enabled).ToList();
        if (enabledVersions.Count == 0)
        {
            throw new ZeeKayDaConfigurationException(
                new ZeeKayDaConfigurationFailure(
                    "signing.azure_key_vault.no_active_key",
                    $"No enabled version of Key Vault key '{keyIdentifier.Name}' in vault '{keyIdentifier.VaultUri}' " +
                    "exists. Verify the key has at least one enabled version."));
        }

        var listings = new List<KeyListing>(enabledVersions.Count);
        var versionMetadata = new Dictionary<string, (Uri, string)>(enabledVersions.Count, StringComparer.Ordinal);

        foreach (var version in enabledVersions)
        {
            var (publicKey, keyType) = await _keyReader
                .GetKeyMaterialAsync(version.Version, cancellationToken).ConfigureAwait(false);

            SigningKeyDescriptor descriptor;
            try
            {
                descriptor = KeyVaultSigningKeyDescriptorFactory.BuildDescriptor(
                    publicKey, keyType, options.Algorithm, nameof(AzureKeyVaultRemoteSigningOptions), "Key Vault key");
            }
            finally
            {
                publicKey.Dispose();
            }

            var publicKeyParameters = descriptor.KeyType == SigningKeyType.Rsa
                ? PublicKeyParameters.FromRsa(descriptor.RsaPublicParameters!.Value)
                : PublicKeyParameters.FromEc(descriptor.EcPublicParameters!.Value);

            var activateAt = ComputeActivateAt(version, firstEverVersion, options.PublicationLead);
            var expiresAt = version.ExpiresOn ?? DateTimeOffset.MaxValue;

            listings.Add(new KeyListing(new KeyId(version.Version), options.Algorithm, publicKeyParameters, activateAt, expiresAt));
            versionMetadata[version.Version] = (version.Id, descriptor.Kid);
        }

        _versionMetadataById = versionMetadata;
        return listings;
    }

    /// <inheritdoc/>
    protected override ValueTask<ISigner> CreateSignerAsync(KeyId id, CancellationToken cancellationToken)
    {
        if (!_versionMetadataById.TryGetValue(id.Value, out var metadata))
        {
            throw new AzureKeyVaultSigningException(
                $"No Key Vault key version is registered for id '{id.Value}'. This should not happen under " +
                "normal operation; retrying the request should self-heal once the next key refresh completes.");
        }

        return new ValueTask<ISigner>(
            new KeyVaultRemoteSigner(_signer, metadata.KeyVersionUri, metadata.Kid, _options.Value.Algorithm));
    }

    /// <summary>
    /// Derives a version's <see cref="KeyListing.ActivateAt"/> from Key Vault's own durable
    /// <c>CreatedOn</c> timestamp (never observed/first-seen time — ADR 0015 §3/Security
    /// Considerations item 4): <c>CreatedOn + publicationLead</c> for every version except the
    /// chronologically-first version ever recorded, which is eligible from startup. An explicit
    /// <c>NotBefore</c> floors the result when it schedules the version's go-live later than that.
    /// </summary>
    private static DateTimeOffset? ComputeActivateAt(
        KeyVaultKeyVersionInfo version, string firstEverVersion, TimeSpan publicationLead)
    {
        if (version.Version == firstEverVersion && version.NotBefore is null)
            return null;

        var baseline = version.Version == firstEverVersion
            ? version.CreatedOn
            : version.CreatedOn + publicationLead;

        return version.NotBefore is { } notBefore && notBefore > baseline ? notBefore : baseline;
    }

    /// <summary>
    /// <see cref="ISigner"/> wrapper over the shared, DI-owned <see cref="IKeyVaultSigner"/> seam for
    /// one activation of one Key Vault key version. The private key never leaves Key Vault — every
    /// <see cref="SignAsync"/> call is a network round trip.
    /// </summary>
    /// <remarks>
    /// <see cref="Dispose"/> is deliberately a no-op: this wrapper introduces no per-activation
    /// resource of its own to release, and <paramref name="signer"/> is a shared seam over pooled
    /// <c>CryptographyClient</c> instances that every other activation also depends on — disposing
    /// it here would break them all (ADR 0015 §2/Security Considerations item 5; see
    /// <see cref="ISigner"/>'s own Dispose contract).
    /// </remarks>
    private sealed class KeyVaultRemoteSigner(IKeyVaultSigner signer, Uri keyVersionUri, string kid, SigningAlgorithm algorithm)
        : ISigner
    {
        public ValueTask<ReadOnlyMemory<byte>> SignAsync(
            ReadOnlyMemory<byte> signingInput, CancellationToken cancellationToken = default) =>
            signer.SignAsync(keyVersionUri, kid, algorithm, signingInput.ToArray(), cancellationToken);

        public void Dispose()
        {
            // Intentionally empty — see the class remarks.
        }

        public SigningAlgorithm Algorithm => algorithm;
    }
}
