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
/// eligible version signs; every enabled version newer than it — whatever is keeping it from
/// signing yet — is published as staged; and up to
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

            var (signing, published) = KeyVaultVersionSelector.SelectVersions(
                allVersions,
                options.PreviousVersionsToPublish,
                options.PreActivationDelay,
                _timeProvider.GetUtcNow(),
                new KeyVaultVersionSelector.SelectionContext(
                    "key", options.KeyIdentifier.Name, options.KeyIdentifier.VaultUri,
                    nameof(AzureKeyVaultRemoteSigningOptions)));

            var signingKey = await ToSourceKeyAsync(signing, options, cancellationToken).ConfigureAwait(false);

            var alsoPublished = new List<SourceKey>(published.Count);
            foreach (var version in published)
                alsoPublished.Add(await ToSourceKeyAsync(version, options, cancellationToken).ConfigureAwait(false));

            // The key set is built first and the signing version committed only after nothing can
            // throw any more, so a failed read can never leave a signer openable for a version that
            // was never reported in a key set.
            var keySet = new SourceKeySet(signingKey, [.. alsoPublished]);
            _signingVersion = new SigningVersion(signing.Version, signing.Id);
            return _keySet = keySet;
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
