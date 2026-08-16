using System.Security.Cryptography;
using Microsoft.Extensions.Options;
using ZeeKayDa.Auth.Logging;
using ZeeKayDa.Auth.Tokens;

namespace ZeeKayDa.Auth.AzureKeyVault;

/// <summary>
/// <see cref="IJwtSigningService"/> that downloads its private key from Azure Key Vault at startup
/// (and on rotation) and signs locally, in process, without a Key Vault round trip per token. Unlike
/// the remote-signing provider, an attacker who achieves process memory read gets a permanent copy
/// of the signing key — see <c>AddAzureKeyVaultCachedSigning</c>'s remarks for the full security
/// tradeoff.
/// </summary>
/// <remarks>
/// <para>
/// <see cref="ListKeysAsync"/> re-asks Key Vault for the certificate's current version list once per
/// <see cref="KeySourceOptions.RefreshInterval"/> — Key Vault, not this provider, owns the
/// certificate's version history. Every returned <see cref="KeyListing.ActivateAt"/> is derived
/// entirely from Key Vault's own durable per-version <c>CreatedOn</c> timestamp
/// (<c>ActivateAt = CreatedOn + PublicationLead</c>), never from when this process first observed the
/// version — stateless, restart-safe, and identical across every replica. The certificate version
/// that was created first of all (by <c>CreatedOn</c>, tie-broken by version identifier) is eligible
/// from startup (<c>ActivateAt = null</c>), so the base class's ordinary activation-timeline logic
/// covers the "first ever version" bootstrap case with no special-case code here.
/// </para>
/// <para>
/// Kill-by-omission is entirely the base class's concern: this provider's only obligation is to list
/// currently-enabled versions and let a version silently drop out of the returned list once Key Vault
/// stops reporting it as enabled. There is no separate <c>Enabled</c> flag anywhere in this contract
/// — an operator disabling a version in Key Vault simply causes it to stop appearing in the next
/// <see cref="ListKeysAsync"/> result.
/// </para>
/// <para>
/// <c>kid</c> is the RFC 7638 JWK thumbprint of each version's public key, derived by the base class
/// from each <see cref="KeyListing.PublicKey"/> — never the raw Key Vault certificate/secret version
/// identifier, which is only this provider's own internal <see cref="KeyId"/>.
/// </para>
/// <para>
/// Every included version's <see cref="KeyListing.PublicKey"/> is built from
/// <see cref="IKeyVaultCertificateReader.GetPublicKeyMaterialAsync"/> — sourced from the
/// certificate's <c>Cer</c>, never the linked secret — so listing every included version never
/// requires the <c>secrets/get</c> permission. Only when <see cref="CreateSignerAsync"/> is called
/// for the currently active version does this provider additionally download real private key
/// material via <see cref="IKeyVaultCertificateReader.GetPrivateKeyMaterialAsync"/>, and only for
/// that one version.
/// </para>
/// </remarks>
internal sealed class AzureKeyVaultCachedSigningJwtSigningService : JwtSigningService<AzureKeyVaultCachedSigningOptions>
{
    private readonly IOptions<AzureKeyVaultCachedSigningOptions> _options;
    private readonly IKeyVaultCertificateReader _certificateReader;

    // Populated wholesale on every ListKeysAsync call. CreateSignerAsync uses this as a
    // defense-in-depth cross-check that the private key it downloads via GetPrivateKeyMaterialAsync
    // still matches the public key most recently
    // published for that same version via GetPublicKeyMaterialAsync — those are two separate Key
    // Vault reads (the certificate's linked secret versus its Cer) that could in principle diverge.
    // Replaced entirely on each refresh, never mutated in place, mirroring the base class's own
    // snapshot replacement.
    // volatile: ListKeysAsync writes this field under the base class's snapshot lock
    // (JwtSigningService{TOptions}.EnsureSnapshotAsync), while CreateSignerAsync reads it under the
    // base class's separate signer lock (EnsureActiveSignerAsync) — the same two-monitor,
    // no-happens-before-edge rationale as AzureKeyVaultRemoteSigningJwtSigningService's
    // _versionMetadataById field.
    private volatile IReadOnlyDictionary<string, PublicKeyParameters> _publicKeyByVersion =
        new Dictionary<string, PublicKeyParameters>(StringComparer.Ordinal);

    /// <summary>
    /// Initialises the service with its options, time source, and the Key Vault certificate seam it
    /// downloads private key material through.
    /// </summary>
    public AzureKeyVaultCachedSigningJwtSigningService(
        IOptions<AzureKeyVaultCachedSigningOptions> options,
        TimeProvider timeProvider,
        IKeyVaultCertificateReader certificateReader,
        ISigningKeyRetirementWindowProvider retirementWindowProvider,
        ISanitizingLogger<JwtSigningService<AzureKeyVaultCachedSigningOptions>> logger)
        : base(options, timeProvider, retirementWindowProvider, logger)
    {
        ArgumentNullException.ThrowIfNull(certificateReader);

        _options = options;
        _certificateReader = certificateReader;
    }

    /// <inheritdoc/>
    protected override async ValueTask<IReadOnlyList<KeyListing>> ListKeysAsync(CancellationToken cancellationToken)
    {
        var options = _options.Value;
        var certificateIdentifier = options.CertificateIdentifier;

        var allVersions = new List<KeyVaultCertificateVersionInfo>();
        await foreach (var version in _certificateReader.GetCertificateVersionsAsync(cancellationToken).ConfigureAwait(false))
            allVersions.Add(version);

        if (allVersions.Count == 0)
        {
            throw new ZeeKayDaConfigurationException(
                new ZeeKayDaConfigurationFailure(
                    "signing.azure_key_vault.no_certificate_versions",
                    $"Key Vault certificate '{certificateIdentifier.Name}' in vault '{certificateIdentifier.VaultUri}' " +
                    "has no versions. Create at least one certificate version before starting the host."));
        }

        // Computed over allVersions — every version this certificate has ever recorded, including
        // disabled ones — never over enabledVersions below. This is deliberate, not an oversight:
        // Key Vault's list-key-versions read is only eventually consistent during a rare
        // Microsoft-initiated regional failover, and a stale/incomplete read during exactly that
        // window could transiently omit the true first-ever version. Computing "first ever" only
        // over whatever subset happened to come back would then let version #2 masquerade as the
        // first-ever version and activate immediately (ActivateAt = null), bypassing
        // PublicationLead entirely and exposing relying parties to a key they never had a chance to
        // observe in the JWKS first. Computing over the full, unfiltered history instead means a
        // stale read can only affect this derivation by omitting every version outright, which
        // already fails closed via the "no certificate versions" check above rather than silently
        // promoting the wrong version. This mirrors the risk analysis accepted for the original Key
        // Vault provider.
        var firstEverVersion = allVersions
            .OrderBy(v => v.CreatedOn)
            .ThenBy(v => v.Version, StringComparer.Ordinal)
            .First()
            .Version;

        // Enabled is a Key Vault-side concept only — it is folded into "list enabled versions only"
        // here rather than surfaced as a flag anywhere in the KeyListing/options contract. A
        // disabled version simply never appears below, and the base class's own
        // kill-by-omission logic (EvaluateKillByOmission) takes it from there.
        var enabledVersions = allVersions.Where(v => v.Enabled).ToList();
        if (enabledVersions.Count == 0)
        {
            throw new ZeeKayDaConfigurationException(
                new ZeeKayDaConfigurationFailure(
                    "signing.azure_key_vault.no_active_key",
                    $"No enabled version of Key Vault certificate '{certificateIdentifier.Name}' in vault " +
                    $"'{certificateIdentifier.VaultUri}' exists. Verify the certificate has at least one " +
                    "enabled version."));
        }

        var listings = new List<KeyListing>(enabledVersions.Count);
        var publicKeyByVersion = new Dictionary<string, PublicKeyParameters>(enabledVersions.Count, StringComparer.Ordinal);

        foreach (var version in enabledVersions)
        {
            var (publicKey, keyType) = await _certificateReader
                .GetPublicKeyMaterialAsync(version.Version, cancellationToken).ConfigureAwait(false);

            // The parameters below are always exported before this handle goes out of scope — nothing
            // downstream ever needs the live AsymmetricAlgorithm itself, only its exported public
            // parameters.
            using var _ = publicKey;

            var publicKeyParameters = BuildValidatedPublicKey(publicKey, keyType, options);

            var activateAt = ComputeActivateAt(version, firstEverVersion, options.PublicationLead);
            var expiresAt = version.ExpiresOn ?? DateTimeOffset.MaxValue;

            listings.Add(new KeyListing(new KeyId(version.Version), options.Algorithm, publicKeyParameters, activateAt, expiresAt));
            publicKeyByVersion[version.Version] = publicKeyParameters;
        }

        _publicKeyByVersion = publicKeyByVersion;
        return listings;
    }

    /// <inheritdoc/>
    /// <remarks>
    /// After downloading the private key, cross-checks its public component against the
    /// <see cref="PublicKeyParameters"/> most recently published for <paramref name="id"/> in
    /// <see cref="ListKeysAsync"/> — a defense-in-depth tamper-evidence check, since the private key
    /// comes from the certificate's linked secret while
    /// the listed public key comes from its <c>Cer</c>, two separate Key Vault reads that could in
    /// principle diverge. This is not a substitute for <see cref="ListKeysAsync"/>'s own
    /// algorithm-compatibility validation over the public data it was given — that check is
    /// necessarily tautological (it only re-validates data sourced from a single read) — this check
    /// is the only place the two independently-read halves are ever compared against each other.
    /// </remarks>
    protected override async ValueTask<ISigner> CreateSignerAsync(KeyId id, CancellationToken cancellationToken)
    {
        var (privateKey, keyType) = await _certificateReader
            .GetPrivateKeyMaterialAsync(id.Value, cancellationToken).ConfigureAwait(false);

        if (_publicKeyByVersion.TryGetValue(id.Value, out var listedPublicKey))
        {
            try
            {
                VerifyPrivateKeyMatchesListedPublicKey(id.Value, privateKey, keyType, listedPublicKey);
            }
            catch
            {
                privateKey.Dispose();
                throw;
            }
        }

        return new LocalSigner(_options.Value.Algorithm, privateKey);
    }

    /// <summary>
    /// Derives a version's <see cref="KeyListing.ActivateAt"/> from Key Vault's own durable
    /// <c>CreatedOn</c> timestamp (never observed/first-seen time):
    /// <c>CreatedOn + publicationLead</c> for every version except the
    /// chronologically-first version ever recorded, which is eligible from startup (there is no
    /// prior published JWKS state any relying party could have cached). An explicit <c>NotBefore</c>
    /// floors the result when it schedules the version's go-live later than that.
    /// </summary>
    private static DateTimeOffset? ComputeActivateAt(
        KeyVaultCertificateVersionInfo version, string firstEverVersion, TimeSpan publicationLead)
    {
        if (version.Version == firstEverVersion && version.NotBefore is null)
            return null;

        var baseline = version.Version == firstEverVersion
            ? version.CreatedOn
            : version.CreatedOn + publicationLead;

        return version.NotBefore is { } notBefore && notBefore > baseline ? notBefore : baseline;
    }

    private static PublicKeyParameters BuildValidatedPublicKey(
        AsymmetricAlgorithm publicKey, SigningKeyType keyType, AzureKeyVaultCachedSigningOptions options)
    {
        var descriptor = KeyVaultSigningKeyDescriptorFactory.BuildDescriptor(
            publicKey, keyType, options.Algorithm, nameof(AzureKeyVaultCachedSigningOptions), "Key Vault certificate key");

        return descriptor.KeyType == SigningKeyType.Rsa
            ? PublicKeyParameters.FromRsa(descriptor.RsaPublicParameters!.Value)
            : PublicKeyParameters.FromEc(descriptor.EcPublicParameters!.Value);
    }

    /// <summary>
    /// Verifies that <paramref name="privateKey"/>'s public component matches
    /// <paramref name="listedPublicKey"/> — the public key most recently published for
    /// <paramref name="version"/> in the JWKS via <see cref="ListKeysAsync"/>. A cheap
    /// public-parameter comparison, not a full re-derivation: it
    /// exists to catch the two independent Key Vault reads (the linked secret versus the <c>Cer</c>)
    /// disagreeing, not to re-validate anything <see cref="ListKeysAsync"/> already validated.
    /// </summary>
    private static void VerifyPrivateKeyMatchesListedPublicKey(
        string version, AsymmetricAlgorithm privateKey, SigningKeyType keyType, PublicKeyParameters listedPublicKey)
    {
        var matches = keyType switch
        {
            SigningKeyType.Rsa when privateKey is RSA rsa && listedPublicKey.RsaPublicParameters is { } listedRsa =>
                RsaPublicParametersMatch(rsa.ExportParameters(includePrivateParameters: false), listedRsa),
            SigningKeyType.Ec when privateKey is ECDsa ec && listedPublicKey.EcPublicParameters is { } listedEc =>
                EcPublicParametersMatch(ec.ExportParameters(includePrivateParameters: false), listedEc),
            _ => false,
        };

        if (!matches)
        {
            throw new AzureKeyVaultSigningException(
                $"The private key downloaded for Key Vault certificate version '{version}' does not match " +
                "the public key most recently published for that version in the JWKS. The certificate's " +
                "linked secret and its Cer disagree — refusing to sign with a key that cannot be verified " +
                "against what relying parties were told to trust.");
        }
    }

    private static bool RsaPublicParametersMatch(RSAParameters actual, RSAParameters listed) =>
        actual.Modulus.AsSpan().SequenceEqual(listed.Modulus) &&
        actual.Exponent.AsSpan().SequenceEqual(listed.Exponent);

    private static bool EcPublicParametersMatch(ECParameters actual, ECParameters listed) =>
        string.Equals(actual.Curve.Oid.Value, listed.Curve.Oid.Value, StringComparison.Ordinal) &&
        actual.Q.X.AsSpan().SequenceEqual(listed.Q.X) &&
        actual.Q.Y.AsSpan().SequenceEqual(listed.Q.Y);
}
