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
/// Read once, never re-read: the ring reads this source exactly once at startup, and the read is
/// memoized here too, so a version added, disabled, or replaced after startup has no effect until
/// the host restarts. The version-to-slot mapping is
/// <see cref="KeyVaultVersionSelector.SelectVersions"/>, shared with the remote source: the newest
/// enabled version inside its own validity window that has existed for
/// <see cref="AzureKeyVaultCachedSigningOptions.PreActivationDelay"/> signs (the
/// chronologically-first version ever is exempt), every newer enabled version is published as
/// staged, and up to <see cref="AzureKeyVaultCachedSigningOptions.PreviousVersionsToPublish"/>
/// older enabled versions stay published. Disabling a version excludes it from every slot.
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
/// The downloaded private key is cross-checked against the public key the read published for that
/// version: the two come from separate Key Vault reads (the certificate's linked secret vs. its
/// <c>Cer</c>) that could in principle diverge, and signing with a key relying parties cannot
/// verify against the published JWKS must fail with the divergence named, not as a generic
/// self-test failure.
/// </para>
/// <para>
/// A failed or empty vault read always throws — never a partial key set. This source performs no
/// algorithm/key-type check of its own: <see cref="SigningKeySetBuilder"/> validates every reported
/// key, keyed on the source id (the Key Vault version string), and the ring's per-handoff self-test
/// is the pairing check.
/// </para>
/// </remarks>
internal sealed class AzureKeyVaultCachedSigningKeySource : ISigningKeySource
{
    private readonly IOptions<AzureKeyVaultCachedSigningOptions> _options;
    private readonly IKeyVaultCertificateReader _certificateReader;
    private readonly TimeProvider _timeProvider;

    // Serialises reads so the vault is read exactly once even if two callers read concurrently —
    // "only the ring calls this" is not something this type can enforce. Deliberately not disposed:
    // disposing it would make a read already in flight at shutdown throw from its own Release, and
    // would strand any reader queued behind it.
    private readonly SemaphoreSlim _readGate = new(1, 1);

    // The one key set this source ever reports. Assigned only after every selected version's public
    // material has been fetched, so a failed read is never cached and a retry re-reads the vault.
    private SourceKeySet? _keySet;

    // The signing version the memoized read selected, with the public key the read published for
    // it — the reference CreateSignerAsync cross-checks the downloaded private key against.
    // volatile: written under _readGate, read by CreateSignerAsync without it — no happens-before
    // edge otherwise connects the two.
    private volatile SigningVersion? _signingVersion;

    public AzureKeyVaultCachedSigningKeySource(
        IOptions<AzureKeyVaultCachedSigningOptions> options,
        IKeyVaultCertificateReader certificateReader,
        TimeProvider timeProvider)
    {
        ArgumentNullException.ThrowIfNull(options);
        ArgumentNullException.ThrowIfNull(certificateReader);
        ArgumentNullException.ThrowIfNull(timeProvider);

        _options = options;
        _certificateReader = certificateReader;
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

            var allVersions = new List<KeyVaultCertificateVersionInfo>();
            await foreach (var version in _certificateReader.GetCertificateVersionsAsync(cancellationToken).ConfigureAwait(false))
                allVersions.Add(version);

            if (allVersions.Count == 0)
            {
                throw new ZeeKayDaConfigurationException(
                    new ZeeKayDaConfigurationFailure(
                        "signing.azure_key_vault.no_certificate_versions",
                        $"Key Vault certificate '{options.CertificateIdentifier.Name}' in vault " +
                        $"'{options.CertificateIdentifier.VaultUri}' has no versions. Create at least one " +
                        "certificate version before starting the host."));
            }

            var (signing, published) = KeyVaultVersionSelector.SelectVersions(
                allVersions,
                options.PreviousVersionsToPublish,
                options.PreActivationDelay,
                _timeProvider.GetUtcNow(),
                KeyVaultVersionSelector.SelectionContext.ForCertificate(
                    options.CertificateIdentifier.Name, options.CertificateIdentifier.VaultUri));

            var signingKey = await ToSourceKeyAsync(signing, options, cancellationToken).ConfigureAwait(false);

            var alsoPublished = new List<SourceKey>(published.Count);
            foreach (var version in published)
                alsoPublished.Add(await ToSourceKeyAsync(version, options, cancellationToken).ConfigureAwait(false));

            // The key set is built first and the signing version committed only after nothing can
            // throw any more, so a failed read can never leave a signer openable for a version that
            // was never reported in a key set.
            var keySet = new SourceKeySet(signingKey, [.. alsoPublished]);
            _signingVersion = new SigningVersion(signing.Version, signingKey.PublicKey);
            return _keySet = keySet;
        }
        finally
        {
            _readGate.Release();
        }
    }

    /// <inheritdoc/>
    /// <remarks>
    /// The single place private material enters this process: downloads the signing version's
    /// private key via the certificate's linked secret, cross-checks its public component against
    /// the key the read published for that version, and hands it to a <see cref="LocalSigner"/>
    /// that owns and disposes it.
    /// </remarks>
    public async ValueTask<ISigner> CreateSignerAsync(SourceKeyId id, CancellationToken cancellationToken = default)
    {
        var signingVersion = _signingVersion;

        // Only the version the memoized read selected as the signing key is ever openable for
        // signing. Published-only versions never sign, so an id naming one of them — or an id
        // arriving before any successful read — is a defect in the caller rather than a request
        // this source should honour by downloading a private key it otherwise never touches.
        if (signingVersion is null || !string.Equals(signingVersion.Version, id.Value, StringComparison.Ordinal))
        {
            throw new InvalidOperationException(
                $"{nameof(CreateSignerAsync)} was called for key '{id.Value}', which is not the Key Vault " +
                "certificate version this source most recently reported as the signing key. This source " +
                "reads the vault exactly once, so the reported signing version cannot change after startup, " +
                "and only it ever signs — or has its private key downloaded at all.");
        }

        var (privateKey, keyType) = await _certificateReader
            .GetPrivateKeyMaterialAsync(signingVersion.Version, cancellationToken).ConfigureAwait(false);

        try
        {
            VerifyPrivateKeyMatchesPublishedPublicKey(signingVersion.Version, privateKey, keyType, signingVersion.PublishedPublicKey);
        }
        catch
        {
            privateKey.Dispose();
            throw;
        }

        return new LocalSigner(_options.Value.Algorithm, privateKey);
    }

    /// <summary>
    /// Fetches <paramref name="version"/>'s public material from the vault and maps it to a
    /// <see cref="SourceKey"/>. Only the public <c>Cer</c> is ever read here — never the linked
    /// secret — so no private material exists in the process during a read.
    /// </summary>
    private async ValueTask<SourceKey> ToSourceKeyAsync(
        KeyVaultCertificateVersionInfo version, AzureKeyVaultCachedSigningOptions options, CancellationToken cancellationToken)
    {
        var (rawPublicKey, keyType) = await _certificateReader
            .GetPublicKeyMaterialAsync(version.Version, cancellationToken).ConfigureAwait(false);

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
    /// <see cref="IKeyVaultCertificateReader.GetPublicKeyMaterialAsync"/> only ever returns an
    /// <see cref="RSA"/> paired with <see cref="SigningKeyType.Rsa"/> or an <see cref="ECDsa"/>
    /// paired with <see cref="SigningKeyType.Ec"/>.
    /// </summary>
    private static PublicKeyParameters ToPublicKeyParameters(AsymmetricAlgorithm publicKey, SigningKeyType keyType) =>
        keyType == SigningKeyType.Rsa
            ? PublicKeyParameters.FromRsa(((RSA)publicKey).ExportParameters(false))
            : PublicKeyParameters.FromEc(((ECDsa)publicKey).ExportParameters(false));

    /// <summary>
    /// Verifies that <paramref name="privateKey"/>'s public component matches
    /// <paramref name="publishedPublicKey"/>, the key the read published for
    /// <paramref name="version"/>. The two come from separate Key Vault reads — the certificate's
    /// linked secret vs. its <c>Cer</c> — that could in principle diverge, and a divergence must be
    /// named rather than surfacing as a generic self-test failure.
    /// </summary>
    private static void VerifyPrivateKeyMatchesPublishedPublicKey(
        string version, AsymmetricAlgorithm privateKey, SigningKeyType keyType, PublicKeyParameters publishedPublicKey)
    {
        var matches = keyType switch
        {
            SigningKeyType.Rsa when privateKey is RSA rsa && publishedPublicKey.RsaPublicParameters is { } publishedRsa =>
                RsaPublicParametersMatch(rsa.ExportParameters(includePrivateParameters: false), publishedRsa),
            SigningKeyType.Ec when privateKey is ECDsa ec && publishedPublicKey.EcPublicParameters is { } publishedEc =>
                EcPublicParametersMatch(ec.ExportParameters(includePrivateParameters: false), publishedEc),
            _ => false,
        };

        if (!matches)
        {
            // A ZeeKayDaConfigurationException, not AzureKeyVaultSigningException: the ring absorbs
            // configuration exceptions verbatim, so this — the sharpest tamper signal the provider
            // can produce — reaches the operator's startup output with the divergence named, rather
            // than flattened into a generic signer_unavailable that reads as transient.
            throw new ZeeKayDaConfigurationException(
                new ZeeKayDaConfigurationFailure(
                    "signing.azure_key_vault.secret_cer_mismatch",
                    $"The private key downloaded for Key Vault certificate version '{version}' does not match " +
                    "the public key published for that version. The certificate's linked secret and its Cer " +
                    "disagree — refusing to sign with a key that cannot be verified against what relying " +
                    "parties were told to trust."));
        }
    }

    private static bool RsaPublicParametersMatch(RSAParameters actual, RSAParameters published) =>
        actual.Modulus.AsSpan().SequenceEqual(published.Modulus) &&
        actual.Exponent.AsSpan().SequenceEqual(published.Exponent);

    // The null-conditional Oid access matters: an explicit-parameters EC curve carries no OID at
    // all, and a missing OID on either side must read as "cannot be verified to match" — never as
    // two nulls comparing equal.
    private static bool EcPublicParametersMatch(ECParameters actual, ECParameters published) =>
        actual.Curve.Oid?.Value is { } actualOid &&
        string.Equals(actualOid, published.Curve.Oid?.Value, StringComparison.Ordinal) &&
        actual.Q.X.AsSpan().SequenceEqual(published.Q.X) &&
        actual.Q.Y.AsSpan().SequenceEqual(published.Q.Y);

    /// <summary>
    /// The signing version a successful read selected: its version string (the source key id) and
    /// the public key the read published for it, against which the downloaded private key is
    /// cross-checked.
    /// </summary>
    private sealed record SigningVersion(string Version, PublicKeyParameters PublishedPublicKey);
}
