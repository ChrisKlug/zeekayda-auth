using System.Security.Cryptography;
using Microsoft.Extensions.Options;
using ZeeKayDa.Auth.Tokens;

namespace ZeeKayDa.Auth.AzureKeyVault;

/// <summary>
/// An <see cref="ISigningKeySource"/> that serves the versions of one Azure Key Vault certificate,
/// downloading the signing version's private key once and signing locally, in process, without a
/// Key Vault round trip per token. Unlike the remote-signing source, an attacker who achieves
/// process memory read gets a permanent copy of the signing key — see
/// <c>AddAzureKeyVaultCachedSigning</c>'s remarks for the full security tradeoff.
/// </summary>
/// <remarks>
/// <para>
/// Every enabled version is listed, or the newest
/// <see cref="AzureKeyVaultCachedSigningOptions.MaxVersions"/> of them, dated as
/// <see cref="KeyVaultVersions"/> describes; the framework decides which one signs. Disabling a
/// version excludes it entirely.
/// </para>
/// <para>
/// <b>Private material is downloaded for exactly one version: the signing one, and only in
/// <see cref="CreateSignerAsync"/>.</b> <see cref="ReadAsync"/> reads every published version —
/// the signing version included — as public-only <c>Cer</c> material via
/// <see cref="IKeyVaultCertificateReader.GetPublicKeyMaterialAsync"/>, which never needs the
/// <c>secrets/get</c> permission. A published-only version's private key is never fetched and is
/// never present in this process.
/// </para>
/// <para>
/// The downloaded private key and the published <c>Cer</c> come from separate Key Vault reads that
/// could in principle diverge. The ring's startup self-test verifies the signature against the
/// published public key, so a divergence fails startup there.
/// </para>
/// <para>
/// A failed or empty vault read always throws — never a partial key set. This source performs no
/// algorithm/key-type check of its own: <see cref="SigningKeySetBuilder"/> validates every reported
/// key, keyed on the source id (the Key Vault version string).
/// </para>
/// </remarks>
internal sealed class AzureKeyVaultCachedSigningKeySource(
    IOptions<AzureKeyVaultCachedSigningOptions> options,
    IKeyVaultCertificateReader certificateReader) : ISigningKeySource
{
    private readonly IOptions<AzureKeyVaultCachedSigningOptions> _options = options;

    // Every version the latest read listed, so a private key is downloaded only for a version that
    // was listed. volatile: CreateSignerAsync may run on another thread.
    private volatile IReadOnlySet<string>? _listedVersions;

    /// <inheritdoc/>
    public SigningAlgorithm Algorithm => _options.Value.Algorithm;

    /// <inheritdoc/>
    public async Task<IReadOnlyList<SourceKey>> ReadAsync(CancellationToken cancellationToken = default)
    {
        var options = _options.Value;

        var allVersions = new List<KeyVaultCertificateVersionInfo>();
        await foreach (var version in certificateReader.GetCertificateVersionsAsync(cancellationToken).ConfigureAwait(false))
            allVersions.Add(version);

        var listed = KeyVaultVersions.Newest(
            KeyVaultVersions.Enabled(allVersions, "certificate"),
            options.MaxVersions);

        var keys = new List<SourceKey>(listed.Count);
        foreach (var version in listed)
            keys.Add(await ToSourceKeyAsync(version, cancellationToken).ConfigureAwait(false));

        // A read the ring abandoned at its deadline must not replace the list of a later read.
        cancellationToken.ThrowIfCancellationRequested();

        // Committed only after nothing can throw any more, so a failed read can never leave a
        // signer openable for a version that was never listed.
        _listedVersions = listed.Select(v => v.Version).ToHashSet(StringComparer.Ordinal);
        return keys;
    }

    /// <inheritdoc/>
    /// <remarks>
    /// The single place private material enters this process: downloads the version's private key
    /// via the certificate's linked secret and hands it to a <see cref="LocalSigner"/> that owns and
    /// disposes it.
    /// </remarks>
    public async Task<ISigner> CreateSignerAsync(SourceKeyId id, CancellationToken cancellationToken = default)
    {
        // An id this source never listed, or one arriving before any successful read, is a defect in
        // the caller rather than a request this source should honour by downloading a private key.
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

    /// <summary>
    /// Fetches <paramref name="version"/>'s public material from the vault and maps it to a
    /// <see cref="SourceKey"/>. Only the public <c>Cer</c> is ever read here — never the linked
    /// secret — so no private material exists in the process during a read.
    /// </summary>
    private async ValueTask<SourceKey> ToSourceKeyAsync(
        KeyVaultCertificateVersionInfo version, CancellationToken cancellationToken)
    {
        var (rawPublicKey, keyType) = await certificateReader
            .GetPublicKeyMaterialAsync(version.Version, cancellationToken).ConfigureAwait(false);

        using var publicKey = rawPublicKey;

        return new SourceKey(
            new SourceKeyId(version.Version),
            ToPublicKeyParameters(publicKey, keyType),
            notBefore: KeyVaultVersions.NotBefore(version),
            expiresAt: version.ExpiresOn);
    }

    /// <summary>
    /// Exports <paramref name="publicKey"/>'s public parameters. The cast is safe:
    /// <see cref="IKeyVaultCertificateReader.GetPublicKeyMaterialAsync"/> only ever returns an
    /// <see cref="RSA"/> paired with <see cref="SigningKeyType.Rsa"/> or an <see cref="ECDsa"/>
    /// paired with <see cref="SigningKeyType.Ec"/>.
    /// </summary>
    private static PublicKeyParameters ToPublicKeyParameters(AsymmetricAlgorithm publicKey, SigningKeyType keyType) =>
        keyType == SigningKeyType.Rsa
            ? PublicKeyParameters.FromRsa(((RSA)publicKey).ExportParameters(false))
            : PublicKeyParameters.FromEc(((ECDsa)publicKey).ExportParameters(false));
}
