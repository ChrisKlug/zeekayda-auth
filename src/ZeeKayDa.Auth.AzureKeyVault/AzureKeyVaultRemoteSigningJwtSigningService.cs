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
/// <see cref="ListKeysAsync"/> re-asks Key Vault for the key's current version list once per
/// <see cref="KeySourceOptions.RefreshInterval"/>. Each <see cref="KeyListing.ActivateAt"/> is
/// derived from Key Vault's durable per-version <c>CreatedOn</c>, never from when this process
/// first observed the version, so activation timing is stateless and identical across replicas. A
/// disabled version simply stops appearing in the list; the base class handles kill-by-omission
/// from there. <see cref="CreateSignerAsync"/> returns a thin <see cref="ISigner"/> wrapper whose
/// <see cref="IDisposable.Dispose"/> is a deliberate no-op, since the shared
/// <see cref="IKeyVaultSigner"/> seam it dispatches to is used by every other activation too.
/// </remarks>
internal sealed class AzureKeyVaultRemoteSigningJwtSigningService : JwtSigningService<AzureKeyVaultRemoteSigningOptions>
{
    private readonly IOptions<AzureKeyVaultRemoteSigningOptions> _options;
    private readonly IKeyVaultKeyReader _keyReader;
    private readonly IKeyVaultSigner _signer;

    // Snapshot of each version's key URI and kid, replaced wholesale on every ListKeysAsync call.
    // CreateSignerAsync is only ever invoked for a KeyId this same call most recently returned, so
    // the lookup is always safe.
    // volatile: written under the base class's snapshot lock, read under its separate signer lock —
    // no happens-before edge otherwise connects the two.
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

        // Computed over allVersions, including disabled ones, never over enabledVersions below.
        // Key Vault's list-versions read is only eventually consistent during a regional failover;
        // if computed over a partial read, a stale response could let version #2 masquerade as
        // "first ever" and activate immediately, bypassing PublicationLead. Over the full history,
        // a stale read can only omit every version outright, which already fails closed above.
        var firstEverVersion = allVersions
            .OrderBy(v => v.CreatedOn)
            .ThenBy(v => v.Version, StringComparer.Ordinal)
            .First()
            .Version;

        // "Enabled" is a Key Vault-side concept only; the base class's kill-by-omission logic
        // handles a version dropping out of this list.
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

            using var _ = publicKey;

            var descriptor = KeyVaultSigningKeyDescriptorFactory.BuildDescriptor(
                publicKey, keyType, options.Algorithm, nameof(AzureKeyVaultRemoteSigningOptions), "Key Vault key");

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
    /// Derives a version's <see cref="KeyListing.ActivateAt"/> from Key Vault's durable
    /// <c>CreatedOn</c> timestamp: <c>CreatedOn + publicationLead</c>, except for the
    /// chronologically-first version ever recorded, which is eligible from startup. An explicit
    /// <c>NotBefore</c> pushes the result later when it is later than that baseline.
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
    /// <see cref="Dispose"/> is deliberately a no-op: <paramref name="signer"/> is a shared seam
    /// that every other activation also depends on, so disposing it here would break them all.
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
