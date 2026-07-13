using System.Security.Cryptography;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using ZeeKayDa.Auth.Logging;
using ZeeKayDa.Auth.Tokens;

namespace ZeeKayDa.Auth.AzureKeyVault;

/// <summary>
/// <see cref="IJwtSigningService"/> that downloads its private key from Azure Key Vault at
/// startup (and on rotation) and signs locally, in process, without a Key Vault round trip per
/// token. Unlike the remote-signing provider, an attacker who achieves process memory read gets a
/// permanent copy of the signing key — see <c>AddAzureKeyVaultCachedSigning</c>'s remarks for the
/// full security tradeoff.
/// </summary>
/// <remarks>
/// <para>
/// <see cref="LoadKeysAsync"/> derives the currently trusted key set entirely from Key Vault's own
/// durable per-version <c>CreatedOn</c> timestamps, exactly as
/// <c>AzureKeyVaultRemoteSigningJwtSigningService</c> does for keys — see that type's remarks for
/// the full rationale (restart-safety and multi-replica consistency). The material difference is
/// that the active version's <see cref="SigningKeyPair.PrivateKey"/> is genuine private key
/// material extracted from the downloaded certificate secret, so this class never overrides
/// <see cref="JwtSigningService{TOptions}.SignInputAsync"/> — the base class's default
/// local-signing implementation is exactly what this provider needs. Every other included version
/// (published-but-not-yet-active, or still within its retirement window) only ever gets a
/// public-only handle, exactly like the remote-signing provider — it is never used to sign, only
/// exposed via the JWKS, so keeping real private key material for it in process memory would be
/// pure liability with no functional benefit (ADR 0011 §3.3(c)).
/// </para>
/// <para>
/// Every included version's <see cref="SigningKeyDescriptor"/> — including the active version's —
/// is built from the exact same public-only source (<see cref="IKeyVaultCertificateReader.GetPublicKeyMaterialAsync"/>,
/// sourced from the certificate's <c>Cer</c>, never the secret) rather than from two different
/// code paths that happened to be mathematically guaranteed to agree. For the active version only,
/// the real private key is additionally downloaded via
/// <see cref="IKeyVaultCertificateReader.GetPrivateKeyMaterialAsync"/> purely to have something to
/// sign with; the public-only handle used to build its descriptor is disposed immediately once the
/// descriptor is built, since it is otherwise redundant with the private key's own public
/// component.
/// </para>
/// <para>
/// <c>kid</c> is the RFC 7638 JWK thumbprint of each version's public key (via
/// <see cref="JwkThumbprint.Compute(RSAParameters)"/> / <see cref="JwkThumbprint.Compute(ECParameters)"/>),
/// not the raw Key Vault certificate/secret version URI — a kid is always public, so embedding
/// the vault/certificate name in it would leak real Azure resource identifiers for no functional
/// benefit.
/// </para>
/// </remarks>
internal sealed class AzureKeyVaultCachedSigningJwtSigningService : JwtSigningService<AzureKeyVaultCachedSigningOptions>
{
    private readonly IOptions<AzureKeyVaultCachedSigningOptions> _options;
    private readonly TimeProvider _timeProvider;
    private readonly IKeyVaultCertificateReader _certificateReader;
    private readonly ISigningKeyRetirementWindowProvider _retirementWindowProvider;
    private readonly ISanitizingLogger<AzureKeyVaultCachedSigningJwtSigningService> _logger;

    // Kid -> Key Vault certificate version, as of the previous successful LoadKeysAsync call. Kept
    // purely to log ADR 0011 §3.5's "kid vanished early" anomaly warning when a previously-
    // published kid's underlying certificate version disappears from Key Vault entirely (not
    // merely disabled, and not a normal retirement-window expiry) before it should have. Losing
    // this across a process restart only means possibly missing one log line — it never gates a
    // trust decision.
    private IReadOnlyDictionary<string, string> _previouslyPublishedKidVersions =
        new Dictionary<string, string>(StringComparer.Ordinal);

    // The included version set (by version identifier, Enabled state, and whether the entry was
    // the active version) as of the previous successful LoadKeysAsync call. IsActive has to be
    // part of the comparison, not just membership and Enabled — see
    // KeyVaultSigningKeyRotation.ToChangeDetectionSet's remarks. Null
    // means "no successful LoadKeysAsync has run yet" — a state HasKeySetChangedAsync never
    // actually observes, since the base class only calls it once a previous SigningKeySet already
    // exists (ADR 0011 §3.2), which itself implies at least one successful LoadKeysAsync already
    // populated this field.
    private IReadOnlySet<(string Version, bool Enabled, bool IsActive)>? _previouslyIncludedVersions;

    /// <summary>
    /// Initialises the service with its options, time source, and the Key Vault certificate seam
    /// it downloads private key material through.
    /// </summary>
    public AzureKeyVaultCachedSigningJwtSigningService(
        IOptions<AzureKeyVaultCachedSigningOptions> options,
        TimeProvider timeProvider,
        IKeyVaultCertificateReader certificateReader,
        ISigningKeyRetirementWindowProvider retirementWindowProvider,
        ISanitizingLogger<AzureKeyVaultCachedSigningJwtSigningService> logger)
        : base(options, timeProvider)
    {
        ArgumentNullException.ThrowIfNull(options);
        ArgumentNullException.ThrowIfNull(timeProvider);
        ArgumentNullException.ThrowIfNull(certificateReader);
        ArgumentNullException.ThrowIfNull(retirementWindowProvider);
        ArgumentNullException.ThrowIfNull(logger);

        _options = options;
        _timeProvider = timeProvider;
        _certificateReader = certificateReader;
        _retirementWindowProvider = retirementWindowProvider;
        _logger = logger;
    }

    /// <inheritdoc/>
    protected override async ValueTask<SigningKeySet> LoadKeysAsync(CancellationToken cancellationToken)
    {
        var (allVersions, included) = await ComputeIncludedVersionsAsync(cancellationToken).ConfigureAwait(false);

        // SelectIncludedVersions always places the active version first.
        var activeVersion = included[0].Version.Version;

        var keyPairs = new List<SigningKeyPair>(included.Count);
        var newKidVersions = new Dictionary<string, string>(included.Count, StringComparer.Ordinal);

        try
        {
            foreach (var entry in included)
            {
                var isActive = entry.Version.Version == activeVersion;

                // Every included version's descriptor — active or not — is always built from the
                // same public-only source, never from the real private key: this keeps a single
                // code path (and a single Key Vault API response) responsible for kid derivation
                // for every version, rather than two paths that happen to be mathematically
                // guaranteed to agree.
                var (publicKey, keyType) = await _certificateReader
                    .GetPublicKeyMaterialAsync(entry.Version.Version, cancellationToken).ConfigureAwait(false);

                SigningKeyDescriptor descriptor;
                try
                {
                    descriptor = KeyVaultSigningKeyDescriptorFactory.BuildDescriptor(
                        publicKey,
                        keyType,
                        _options.Value.Algorithm,
                        nameof(AzureKeyVaultCachedSigningOptions),
                        "Key Vault certificate key");
                }
                catch
                {
                    // The key handle just obtained above was never added to keyPairs, so the outer
                    // catch below would not dispose it — do so here before rethrowing, otherwise a
                    // descriptor-build failure (e.g. an algorithm/key-type mismatch or an
                    // unsupported curve) would leak a live key handle.
                    publicKey.Dispose();
                    throw;
                }

                // Only the active version's SigningKeyPair.PrivateKey ever needs to hold genuine
                // private key material: the base class's default SignInputAsync always signs with
                // set.GetPrivateKey(0), i.e. the active key (index 0 — see SelectIncludedVersions).
                // Every other included version (published-but-not-yet-active, or still within its
                // retirement window) is only ever exposed via the JWKS, never used to sign, so the
                // public-only handle already obtained above is reused as-is — it never even
                // required the secrets/get permission for those versions. See ADR 0011 §3.3(c):
                // keeping a retired private key alive in process memory when it can never sign
                // again is pure liability.
                AsymmetricAlgorithm signingKey;
                if (isActive)
                {
                    try
                    {
                        (signingKey, _) = await _certificateReader
                            .GetPrivateKeyMaterialAsync(entry.Version.Version, cancellationToken).ConfigureAwait(false);
                    }
                    catch
                    {
                        // The descriptor was already built successfully at this point, but the
                        // public-only handle used to build it is still live and was never added to
                        // keyPairs — dispose it here before rethrowing so a private-key download
                        // failure for the active version cannot leak it.
                        publicKey.Dispose();
                        throw;
                    }

                    // The public-only handle is now redundant: the private key just downloaded
                    // carries the same public component, and only ever the private key is used
                    // (as SigningKeyPair.PrivateKey) from this point on.
                    publicKey.Dispose();
                }
                else
                {
                    signingKey = publicKey;
                }

                keyPairs.Add(new SigningKeyPair { Descriptor = descriptor, PrivateKey = signingKey });
                newKidVersions[descriptor.Kid] = entry.Version.Version;
            }
        }
        catch
        {
            // Key material — real private key material for the active version, public-only
            // handles for everything else — has already been downloaded and extracted for any
            // keys built before the failure. Leaving these undisposed on a partial failure would
            // leak live key handles (and, for the active version specifically, a live private key).
            foreach (var pair in keyPairs)
                pair.PrivateKey.Dispose();
            throw;
        }

        WarnIfPreviouslyPublishedKidVanished(newKidVersions.Keys, allVersions);
        _previouslyPublishedKidVersions = newKidVersions;
        _previouslyIncludedVersions = KeyVaultSigningKeyRotation.ToChangeDetectionSet(included);

        return new SigningKeySet(keyPairs);
    }

    /// <inheritdoc/>
    /// <remarks>
    /// <para>
    /// Recomputes the included version set from the same cheap, metadata-only enumeration
    /// (<see cref="IKeyVaultCertificateReader.GetCertificateVersionsAsync"/> — no secret or
    /// private-key download) and rotation-timeline derivation that <see cref="LoadKeysAsync"/>
    /// itself performs (<see cref="ComputeIncludedVersionsAsync"/>), and compares it — by version
    /// identifier, <see cref="KeyVaultCertificateVersionInfo.Enabled"/> state, and which entry is
    /// active — against what was included as of the last successful <see cref="LoadKeysAsync"/>
    /// cycle. The comparison covers the whole included set, not merely the active version: a
    /// non-active version's <c>Enabled</c> flag flipping, or a version entering or leaving its
    /// retirement window purely from elapsed time, must still be reported as a change even when
    /// the active version is unchanged.
    /// </para>
    /// <para>
    /// Active-version identity has to be part of the comparison, not just membership and
    /// <c>Enabled</c> state, or a normal scheduled rotation silently stalls. Because
    /// <c>KeySourceRefreshInterval</c> is both the poll cadence and the publish-then-activate lead
    /// time (ADR 0011 §3.5), a rotation typically spans two polls: at poll N, v2 is published but
    /// not yet active (included set becomes v1 active + v2 not-active — a membership change, so
    /// this method correctly reports a change and v2's public-only handle gets loaded). At poll
    /// N+1, v2 becomes active while v1 (still within its retirement window) remains included — the
    /// same two version identifiers and <c>Enabled</c> states as poll N, just with the active slot
    /// swapped. Comparing only version identifier and <c>Enabled</c> state would see no change and
    /// skip the reload, leaving the service signing with v1 indefinitely — past the intended
    /// handoff, and potentially past v1's own expiry. See ADR 0011 §3.5 "Metadata-only change
    /// detection for cached-key providers."
    /// </para>
    /// </remarks>
    protected override async ValueTask<bool> HasKeySetChangedAsync(CancellationToken cancellationToken)
    {
        var (_, included) = await ComputeIncludedVersionsAsync(cancellationToken).ConfigureAwait(false);
        var currentVersions = KeyVaultSigningKeyRotation.ToChangeDetectionSet(included);

        // The base class only ever calls this once a previous SigningKeySet already exists (ADR
        // 0011 §3.2), which itself implies at least one successful LoadKeysAsync already ran and
        // populated _previouslyIncludedVersions — the null-forgiving operator relies on that
        // guarantee rather than re-checking it.
        return !currentVersions.SetEquals(_previouslyIncludedVersions!);
    }

    /// <summary>
    /// Enumerates every certificate version Key Vault has ever recorded and derives the currently
    /// included version set (active version first, per <see cref="KeyVaultSigningKeyRotation.SelectIncludedVersions{T}"/>)
    /// from it. Shared by <see cref="LoadKeysAsync"/> and <see cref="HasKeySetChangedAsync"/> so the
    /// metadata-only "ask" step in front of a reload uses the exact same rotation-timeline
    /// derivation as the reload itself.
    /// </summary>
    private async ValueTask<(
        List<KeyVaultCertificateVersionInfo> AllVersions,
        List<KeyVaultSigningKeyRotation.ActivationEntry<KeyVaultCertificateVersionInfo>> Included)>
        ComputeIncludedVersionsAsync(CancellationToken cancellationToken)
    {
        var certificateIdentifier = _options.Value.CertificateIdentifier;

        // See AzureKeyVaultRemoteSigningJwtSigningService.ComputeIncludedVersionsAsync for the full
        // research and rationale (issue #300 / ADR 0011 Amendment 3) behind treating this list as a
        // complete, consistent view of every certificate version Key Vault has ever recorded during
        // normal operation — the same Key Vault reliability model applies to certificates as to keys.
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

        var now = _timeProvider.GetUtcNow();

        // AzureKeyVaultCachedSigningOptionsValidator rejects null (static-source mode is not
        // supported by this provider), so the value is guaranteed non-null by the time this runs.
        var timeline = KeyVaultSigningKeyRotation.BuildActivationTimeline(allVersions, _options.Value.KeySourceRefreshInterval!.Value);

        var active = KeyVaultSigningKeyRotation.SelectActiveVersion(timeline, now) ?? throw new ZeeKayDaConfigurationException(
            new ZeeKayDaConfigurationFailure(
                "signing.azure_key_vault.no_active_key",
                $"No enabled, time-eligible version of Key Vault certificate '{certificateIdentifier.Name}' in " +
                $"vault '{certificateIdentifier.VaultUri}' has activated yet. Verify the certificate has at " +
                "least one enabled version whose NotBefore/ExpiresOn window includes the current time."));

        var retirementWindow = _retirementWindowProvider.GetRetirementWindow();
        var included = KeyVaultSigningKeyRotation.SelectIncludedVersions(timeline, active, now, retirementWindow);

        return (allVersions, included);
    }

    private void WarnIfPreviouslyPublishedKidVanished(
        IEnumerable<string> newKids, IReadOnlyList<KeyVaultCertificateVersionInfo> currentRawVersions)
    {
        foreach (var (kid, version) in KeyVaultSigningKeyRotation.FindVanishedKids(
            _previouslyPublishedKidVersions, newKids, currentRawVersions))
        {
            _logger.LogWarning(
                "Azure Key Vault signing certificate with kid {Kid} (Key Vault version {Version}) is no longer " +
                "present in Key Vault at all. It was previously published and may still be cached in a relying " +
                "party's JWKS; an unexpected disappearance (as opposed to a normal retirement-window expiry) may " +
                "cause token validation failures. See ADR 0011 §3.5.",
                kid, version);
        }
    }
}
