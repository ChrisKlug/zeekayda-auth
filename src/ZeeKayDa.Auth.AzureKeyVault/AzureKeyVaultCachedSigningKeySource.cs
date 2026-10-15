using Microsoft.Extensions.Options;
using ZeeKayDa.Auth.Tokens;

namespace ZeeKayDa.Auth.AzureKeyVault;

/// <summary>
/// Lists the enabled versions of one Key Vault certificate from their public <c>Cer</c>, and downloads
/// a private key only in <see cref="CreateSignerAsync"/>, for the version chosen to sign, to sign in process.
/// </summary>
internal sealed class AzureKeyVaultCachedSigningKeySource(
    IOptions<AzureKeyVaultCachedSigningOptions> options,
    IKeyVaultCertificateReader certificateReader) : ISigningKeySource
{
    private readonly IOptions<AzureKeyVaultCachedSigningOptions> _options = options;

    // volatile: CreateSignerAsync may run on another thread.
    private volatile IReadOnlySet<string>? _listedVersions;

    // A version's material never changes, so a refresh fetches only versions it has not seen.
    private volatile IReadOnlyDictionary<string, PublicKeyParameters> _publicKeys =
        new Dictionary<string, PublicKeyParameters>(StringComparer.Ordinal);

    /// <inheritdoc/>
    public SigningAlgorithm Algorithm => _options.Value.Algorithm;

    /// <inheritdoc/>
    public async Task<SourceKeyListing> ReadAsync(CancellationToken cancellationToken = default)
    {
        var options = _options.Value;

        var allVersions = new List<KeyVaultCertificateVersionInfo>();
        await foreach (var version in certificateReader.GetCertificateVersionsAsync(cancellationToken).ConfigureAwait(false))
            allVersions.Add(version);

        var listed = KeyVaultVersions.Newest(
            KeyVaultVersions.Enabled(allVersions, "certificate"),
            options.MaxVersions);

        var listing = await KeyVaultVersions
            .ListAsync(listed, version => ToSourceKeyAsync(version, cancellationToken)).ConfigureAwait(false);

        // A read the ring abandoned at its deadline must not replace the list of a later read.
        cancellationToken.ThrowIfCancellationRequested();

        // Committed last, so a failed read never makes an unlisted version openable.
        _listedVersions = listing.Keys.Select(key => key.Id.Value).ToHashSet(StringComparer.Ordinal);
        _publicKeys = KeyVaultVersions.RememberPublicKeys(_publicKeys, listing, allVersions);
        return listing;
    }

    /// <inheritdoc/>
    public async Task<ISigner> CreateSignerAsync(SourceKeyId id, CancellationToken cancellationToken = default)
    {
        // Before any successful read, or for an unlisted id, no private key is downloaded.
        if (_listedVersions is not { } listed || !listed.Contains(id.Value))
        {
            throw new InvalidOperationException(
                $"{nameof(CreateSignerAsync)} was called for key '{id.Value}', which is not a Key Vault " +
                "certificate version this source listed.");
        }

        var (privateKey, _) = await certificateReader
            .GetPrivateKeyMaterialAsync(id.Value, cancellationToken).ConfigureAwait(false);

        return new LocalSigner(_options.Value.Algorithm, privateKey);
    }

    /// <summary>Maps a version to its key, fetching its public <c>Cer</c> unless an earlier read did.</summary>
    private async ValueTask<SourceKey> ToSourceKeyAsync(
        KeyVaultCertificateVersionInfo version, CancellationToken cancellationToken) =>
        new(
            new SourceKeyId(version.Version),
            _publicKeys.TryGetValue(version.Version, out var known)
                ? known
                : await FetchPublicKeyAsync(version.Version, cancellationToken).ConfigureAwait(false),
            notBefore: KeyVaultVersions.NotBefore(version),
            expiresAt: version.ExpiresOn);

    private async ValueTask<PublicKeyParameters> FetchPublicKeyAsync(string version, CancellationToken cancellationToken)
    {
        var (rawPublicKey, keyType) = await certificateReader
            .GetPublicKeyMaterialAsync(version, cancellationToken).ConfigureAwait(false);

        using var publicKey = rawPublicKey;
        return KeyVaultVersions.ToPublicKeyParameters(publicKey, keyType);
    }
}
