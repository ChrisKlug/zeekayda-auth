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
/// <see cref="ListKeysAsync"/> re-asks Key Vault for the certificate's current version list once per
/// <see cref="KeySourceOptions.RefreshInterval"/>. Each <see cref="KeyListing.ActivateAt"/> is derived
/// from Key Vault's durable per-version <c>CreatedOn</c>, never from when this process first observed
/// the version, so activation timing is stateless and identical across replicas. A disabled version
/// simply stops appearing in the list; the base class handles kill-by-omission from there. Listing
/// versions only reads each certificate's <c>Cer</c> (via
/// <see cref="IKeyVaultCertificateReader.GetPublicKeyMaterialAsync"/>) and never needs
/// <c>secrets/get</c> — private key material is downloaded only for the active version, in
/// <see cref="CreateSignerAsync"/>.
/// </remarks>
internal sealed class AzureKeyVaultCachedSigningJwtSigningService : JwtSigningService<AzureKeyVaultCachedSigningOptions>
{
    private readonly IOptions<AzureKeyVaultCachedSigningOptions> _options;
    private readonly IKeyVaultCertificateReader _certificateReader;

    // Snapshot of each version's public key, replaced wholesale on every ListKeysAsync call.
    // CreateSignerAsync cross-checks the private key it downloads against this, since the two are
    // read from separate Key Vault sources (the linked secret vs. the Cer) that could diverge.
    // volatile: written under the base class's snapshot lock, read under its separate signer lock —
    // no happens-before edge otherwise connects the two.
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

        // "Enabled" is a Key Vault-side concept only; a disabled version simply never appears below,
        // and the base class's kill-by-omission logic takes it from there.
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
    /// After downloading the private key, cross-checks its public component against the key most
    /// recently published for <paramref name="id"/> in <see cref="ListKeysAsync"/> — a
    /// tamper-evidence check, since the two come from separate Key Vault reads (the linked secret
    /// vs. the <c>Cer</c>) that could in principle diverge.
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
    /// Derives a version's <see cref="KeyListing.ActivateAt"/> from Key Vault's durable
    /// <c>CreatedOn</c> timestamp: <c>CreatedOn + publicationLead</c>, except for the
    /// chronologically-first version ever recorded, which is eligible from startup. An explicit
    /// <c>NotBefore</c> pushes the result later when it is later than that baseline.
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
    /// <paramref name="listedPublicKey"/>, the key most recently published for
    /// <paramref name="version"/> via <see cref="ListKeysAsync"/>.
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
