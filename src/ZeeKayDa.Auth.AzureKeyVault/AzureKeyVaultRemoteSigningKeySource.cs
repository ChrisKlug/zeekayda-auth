using Microsoft.Extensions.Options;
using ZeeKayDa.Auth.Tokens;

namespace ZeeKayDa.Auth.AzureKeyVault;

/// <summary>
/// Lists the enabled versions of one Key Vault (or Managed HSM) key and signs inside the vault, so the
/// private key never enters the process.
/// </summary>
internal sealed class AzureKeyVaultRemoteSigningKeySource(
    IOptions<AzureKeyVaultRemoteSigningOptions> options,
    IKeyVaultKeyReader keyReader,
    IKeyVaultSigner signer) : ISigningKeySource
{
    private readonly IOptions<AzureKeyVaultRemoteSigningOptions> _options = options;
    private readonly IKeyVaultSigner _signer = signer;

    // volatile: CreateSignerAsync may run on another thread.
    private volatile IReadOnlyDictionary<string, Uri>? _listedVersions;

    // A version's material never changes, so a refresh fetches only versions it has not seen.
    private volatile IReadOnlyDictionary<string, PublicKeyParameters> _publicKeys =
        new Dictionary<string, PublicKeyParameters>(StringComparer.Ordinal);

    /// <inheritdoc/>
    public SigningAlgorithm Algorithm => _options.Value.Algorithm;

    /// <inheritdoc/>
    public async Task<SourceKeyListing> ReadAsync(CancellationToken cancellationToken = default)
    {
        var options = _options.Value;

        var allVersions = new List<KeyVaultKeyVersionInfo>();
        await foreach (var version in keyReader.GetKeyVersionsAsync(cancellationToken).ConfigureAwait(false))
            allVersions.Add(version);

        var listed = KeyVaultVersions.Newest(
            KeyVaultVersions.Enabled(allVersions, "key"),
            options.MaxVersions);

        var listing = await KeyVaultVersions
            .ListAsync(listed, version => ToSourceKeyAsync(version, cancellationToken)).ConfigureAwait(false);

        // A read the ring abandoned at its deadline must not replace the list of a later read.
        cancellationToken.ThrowIfCancellationRequested();

        // Committed last, so a failed read never makes an unlisted version openable.
        _listedVersions = listed
            .Where(v => listing.Keys.Any(key => key.Id.Value == v.Version))
            .ToDictionary(v => v.Version, v => v.Id, StringComparer.Ordinal);
        _publicKeys = KeyVaultVersions.RememberPublicKeys(_publicKeys, listing, allVersions);
        return listing;
    }

    /// <inheritdoc/>
    public Task<ISigner> CreateSignerAsync(SourceKeyId id, CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();

        if (_listedVersions is not { } listed || !listed.TryGetValue(id.Value, out var keyVersionUri))
        {
            throw new InvalidOperationException(
                $"{nameof(CreateSignerAsync)} was called for key '{id.Value}', which is not a Key Vault " +
                "key version this source listed.");
        }

        return Task.FromResult<ISigner>(new KeyVaultRemoteSigner(
            _signer, keyVersionUri, id.Value, _options.Value.Algorithm));
    }

    /// <summary>Maps a version to its key, fetching its public half unless an earlier read did.</summary>
    private async ValueTask<SourceKey> ToSourceKeyAsync(
        KeyVaultKeyVersionInfo version, CancellationToken cancellationToken) =>
        new(
            new SourceKeyId(version.Version),
            _publicKeys.TryGetValue(version.Version, out var known)
                ? known
                : await FetchPublicKeyAsync(version.Version, cancellationToken).ConfigureAwait(false),
            notBefore: KeyVaultVersions.NotBefore(version),
            expiresAt: version.ExpiresOn);

    private async ValueTask<PublicKeyParameters> FetchPublicKeyAsync(string version, CancellationToken cancellationToken)
    {
        var (rawPublicKey, keyType) = await keyReader
            .GetKeyMaterialAsync(version, cancellationToken).ConfigureAwait(false);

        using var publicKey = rawPublicKey;
        return KeyVaultVersions.ToPublicKeyParameters(publicKey, keyType);
    }

    /// <summary>Signs with one key version through the shared <see cref="IKeyVaultSigner"/>.</summary>
    private sealed class KeyVaultRemoteSigner(IKeyVaultSigner signer, Uri keyVersionUri, string version, SigningAlgorithm algorithm)
        : ISigner
    {
        public Task<ReadOnlyMemory<byte>> SignAsync(
            ReadOnlyMemory<byte> signingInput, CancellationToken cancellationToken = default) =>
            signer.SignAsync(keyVersionUri, version, algorithm, signingInput.ToArray(), cancellationToken);

        public void Dispose()
        {
            // The shared signer outlives this one; DI disposes it.
        }
    }
}
