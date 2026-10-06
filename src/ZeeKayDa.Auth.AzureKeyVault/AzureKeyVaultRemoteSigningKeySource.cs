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
/// Lists every enabled version, dated by the vault's own durable metadata (see
/// <see cref="KeyVaultVersions"/>), so every replica and every restart lists the same keys with no
/// local state. The framework decides which version signs. Disabling a version in the vault is the
/// operator's revocation lever: a disabled version is never listed.
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
internal sealed class AzureKeyVaultRemoteSigningKeySource(
    IOptions<AzureKeyVaultRemoteSigningOptions> options,
    IKeyVaultKeyReader keyReader,
    IKeyVaultSigner signer) : ISigningKeySource
{
    private readonly IOptions<AzureKeyVaultRemoteSigningOptions> _options = options;
    private readonly IKeyVaultSigner _signer = signer;

    // Serialises reads so the vault is read exactly once even if two callers read concurrently —
    // "only the ring calls this" is not something this type can enforce. Deliberately not disposed:
    // disposing it would make a read already in flight at shutdown throw from its own Release, and
    // would strand any reader queued behind it.
    private readonly SemaphoreSlim _readGate = new(1, 1);

    // The one key set this source ever reports. Assigned only after every listed version's public
    // material has been fetched, so a failed read is never cached and a retry re-reads the vault;
    // once a read has succeeded, no later one can observe a version rotated in after startup.
    private IReadOnlyList<SourceKey>? _keySet;

    // The versioned key URI of every version the memoized read listed, by version. volatile: written
    // under _readGate, read by CreateSignerAsync without it.
    private volatile IReadOnlyDictionary<string, Uri>? _listedVersions;

    /// <inheritdoc/>
    public async Task<IReadOnlyList<SourceKey>> ReadAsync(CancellationToken cancellationToken = default)
    {
        await _readGate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            if (_keySet is not null)
                return _keySet;

            var options = _options.Value;

            var allVersions = new List<KeyVaultKeyVersionInfo>();
            await foreach (var version in keyReader.GetKeyVersionsAsync(cancellationToken).ConfigureAwait(false))
                allVersions.Add(version);

            if (allVersions.Count == 0)
            {
                throw new ZeeKayDaConfigurationException(
                    new ZeeKayDaConfigurationFailure(
                        "signing.azure_key_vault.no_key_versions",
                        $"Key Vault key '{options.KeyIdentifier.Name}' in vault '{options.KeyIdentifier.VaultUri}' " +
                        "has no versions. Create at least one key version before starting the host."));
            }

            var enabled = KeyVaultVersions.Enabled(
                allVersions, "key", options.KeyIdentifier.Name, options.KeyIdentifier.VaultUri);

            var keys = new List<SourceKey>(enabled.Count);
            foreach (var version in enabled)
                keys.Add(await ToSourceKeyAsync(version, options, cancellationToken).ConfigureAwait(false));

            // Committed only after nothing can throw any more, so a failed read can never leave a
            // signer openable for a version that was never listed.
            _listedVersions = enabled.ToDictionary(v => v.Version, v => v.Id, StringComparer.Ordinal);
            return _keySet = keys;
        }
        finally
        {
            _readGate.Release();
        }
    }

    /// <inheritdoc/>
    public Task<ISigner> CreateSignerAsync(SourceKeyId id, CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();

        // An id this source never listed, or one arriving before any successful read, is a defect in
        // the caller rather than a request this source should honour.
        if (_listedVersions is not { } listed || !listed.TryGetValue(id.Value, out var keyVersionUri))
        {
            throw new InvalidOperationException(
                $"{nameof(CreateSignerAsync)} was called for key '{id.Value}', which is not a Key Vault " +
                "key version this source listed. This source reads the vault exactly once, so the listed " +
                "versions cannot change after startup.");
        }

        return Task.FromResult<ISigner>(new KeyVaultRemoteSigner(
            _signer, keyVersionUri, id.Value, _options.Value.Algorithm));
    }

    /// <summary>
    /// Fetches <paramref name="version"/>'s public material from the vault and maps it to a
    /// <see cref="SourceKey"/>. Only public halves are ever fetched — Key Vault's
    /// <c>GetKey</c> cannot return private material for a non-exportable key at all.
    /// </summary>
    private async ValueTask<SourceKey> ToSourceKeyAsync(
        KeyVaultKeyVersionInfo version, AzureKeyVaultRemoteSigningOptions options, CancellationToken cancellationToken)
    {
        var (rawPublicKey, keyType) = await keyReader
            .GetKeyMaterialAsync(version.Version, cancellationToken).ConfigureAwait(false);

        using var publicKey = rawPublicKey;

        return new SourceKey(
            new SourceKeyId(version.Version),
            options.Algorithm,
            ToPublicKeyParameters(publicKey, keyType),
            notBefore: KeyVaultVersions.NotBefore(version),
            expiresAt: version.ExpiresOn);
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
        public Task<ReadOnlyMemory<byte>> SignAsync(
            ReadOnlyMemory<byte> signingInput, CancellationToken cancellationToken = default) =>
            signer.SignAsync(keyVersionUri, version, algorithm, signingInput.ToArray(), cancellationToken);

        public void Dispose()
        {
            // Intentionally empty — see the class remarks.
        }
    }
}
