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
/// the host restarts. Every enabled version is listed, dated as <see cref="KeyVaultVersions"/>
/// describes; the framework decides which one signs. Disabling a version excludes it entirely.
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
internal sealed class AzureKeyVaultCachedSigningKeySource(
    IOptions<AzureKeyVaultCachedSigningOptions> options,
    IKeyVaultCertificateReader certificateReader) : ISigningKeySource
{
    private readonly IOptions<AzureKeyVaultCachedSigningOptions> _options = options;

    // Serialises reads so the vault is read exactly once even if two callers read concurrently —
    // "only the ring calls this" is not something this type can enforce. Deliberately not disposed:
    // disposing it would make a read already in flight at shutdown throw from its own Release, and
    // would strand any reader queued behind it.
    private readonly SemaphoreSlim _readGate = new(1, 1);

    // The one key set this source ever reports. Assigned only after every listed version's public
    // material has been fetched, so a failed read is never cached and a retry re-reads the vault.
    private IReadOnlyList<SourceKey>? _keySet;

    // The public key the memoized read listed for each version — the reference CreateSignerAsync
    // cross-checks the downloaded private key against. volatile: written under _readGate, read by
    // CreateSignerAsync without it.
    private volatile IReadOnlyDictionary<string, PublicKeyParameters>? _listedVersions;

    /// <inheritdoc/>
    public async Task<IReadOnlyList<SourceKey>> ReadAsync(CancellationToken cancellationToken = default)
    {
        await _readGate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            if (_keySet is not null)
                return _keySet;

            var options = _options.Value;

            var allVersions = new List<KeyVaultCertificateVersionInfo>();
            await foreach (var version in certificateReader.GetCertificateVersionsAsync(cancellationToken).ConfigureAwait(false))
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

            var enabled = KeyVaultVersions.Enabled(
                allVersions, "certificate", options.CertificateIdentifier.Name, options.CertificateIdentifier.VaultUri);

            var keys = new List<SourceKey>(enabled.Count);
            foreach (var version in enabled)
                keys.Add(await ToSourceKeyAsync(version, options, cancellationToken).ConfigureAwait(false));

            // Committed only after nothing can throw any more, so a failed read can never leave a
            // signer openable for a version that was never listed.
            _listedVersions = keys.ToDictionary(k => k.Id.Value, k => k.PublicKey, StringComparer.Ordinal);
            return _keySet = keys;
        }
        finally
        {
            _readGate.Release();
        }
    }

    /// <inheritdoc/>
    /// <remarks>
    /// The single place private material enters this process: downloads the version's private key via the certificate's linked secret, cross-checks its public component against
    /// the key the read published for that version, and hands it to a <see cref="LocalSigner"/>
    /// that owns and disposes it.
    /// </remarks>
    public async Task<ISigner> CreateSignerAsync(SourceKeyId id, CancellationToken cancellationToken = default)
    {
        // An id this source never listed, or one arriving before any successful read, is a defect in
        // the caller rather than a request this source should honour by downloading a private key.
        if (_listedVersions is not { } listed || !listed.TryGetValue(id.Value, out var publishedPublicKey))
        {
            throw new InvalidOperationException(
                $"{nameof(CreateSignerAsync)} was called for key '{id.Value}', which is not a Key Vault " +
                "certificate version this source listed. This source reads the vault exactly once, so the " +
                "listed versions cannot change after startup.");
        }

        var (privateKey, keyType) = await certificateReader
            .GetPrivateKeyMaterialAsync(id.Value, cancellationToken).ConfigureAwait(false);

        try
        {
            VerifyPrivateKeyMatchesPublishedPublicKey(id.Value, privateKey, keyType, publishedPublicKey);
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
        var (rawPublicKey, keyType) = await certificateReader
            .GetPublicKeyMaterialAsync(version.Version, cancellationToken).ConfigureAwait(false);

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
}
