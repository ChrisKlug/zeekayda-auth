using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using ZeeKayDa.Auth.Logging;
using ZeeKayDa.Auth.Tokens;

namespace ZeeKayDa.Auth.AzureKeyVault;

/// <summary>
/// <see cref="IJwtSigningService"/> that signs remotely inside Azure Key Vault. The private key
/// never leaves the vault and is never held in process memory — every <see cref="IJwtSigningService.SignAsync"/>
/// call is a network round trip to Key Vault's <c>CryptographyClient</c>.
/// </summary>
/// <remarks>
/// <para>
/// <see cref="LoadKeysAsync"/> derives the currently trusted key set entirely from Key Vault's own
/// durable per-version <c>CreatedOn</c> timestamps, rather than tracking "when did this kid first
/// appear" in local, in-memory state. That in-memory-history approach breaks on every process
/// restart and is inconsistent across load-balanced replicas; deriving from <c>CreatedOn</c>
/// instead is stateless, restart-safe, and identical across every replica. See ADR 0011 §3.5 and
/// the accompanying design notes for the full derivation.
/// </para>
/// <para>
/// <c>kid</c> is the RFC 7638 JWK thumbprint of each version's public key (via
/// <see cref="JwkThumbprint.Compute(System.Security.Cryptography.RSAParameters)"/> /
/// <see cref="JwkThumbprint.Compute(System.Security.Cryptography.ECParameters)"/>),
/// not the raw Key Vault version URI — a kid is always public (every issued token header, and the
/// public JWKS), so embedding the vault/key name in it would leak real Azure resource identifiers
/// for no functional benefit.
/// </para>
/// </remarks>
internal sealed class AzureKeyVaultRemoteSigningJwtSigningService : JwtSigningService<AzureKeyVaultRemoteSigningOptions>
{
    private readonly IOptions<AzureKeyVaultRemoteSigningOptions> _options;
    private readonly TimeProvider _timeProvider;
    private readonly IKeyVaultKeyReader _keyReader;
    private readonly IKeyVaultSigner _signer;
    private readonly ISigningKeyRetirementWindowProvider _retirementWindowProvider;
    private readonly ISanitizingLogger<AzureKeyVaultRemoteSigningJwtSigningService> _logger;

    // Kid -> Key Vault versioned key URI. Rebuilt wholesale on every LoadKeysAsync call and
    // assigned atomically (a single field write) right before the new SigningKeySet is returned
    // to the base class. LoadKeysAsync is single-flighted by the base class's own refresh lock, so
    // this field's generation is always the one that produced whichever SigningKeySet is "current"
    // by the time any SignAsync call observes it.
    //
    // There is a narrow, deliberately-accepted theoretical window: a SignAsync call that borrowed
    // the OLD SigningKeySet an instant before a concurrent refresh both computes a new mapping and
    // replaces this field would look up its kid in the NEW mapping. This is harmless because (a) a
    // kid is a thumbprint of immutable public key material, so the same kid always resolves to the
    // same underlying Key Vault key version for as long as that kid exists in either mapping, and
    // (b) a kid is only ever removed from the mapping once its SigningKeySet generation has been
    // fully retired and disposed, at which point it can no longer be borrowed for signing anyway.
    // An alternative that avoids this side-channel field entirely — e.g. wrapping the Key Vault URI
    // inside a custom AsymmetricAlgorithm-derived handle passed as SigningKeyPair.PrivateKey — was
    // considered and rejected: it would require subclassing RSA/ECDsa (a large, brittle surface to
    // fake convincingly) or inventing a sentinel type, either of which would need special-casing in
    // the base class's ValidateKeyAlgorithmCompatibility/ValidateKeyStrength checks, which only ever
    // call ExportParameters(false) against a real RSA/ECDsa today.
    private volatile IReadOnlyDictionary<string, Uri>? _kidToKeyVersionUri;

    // Kid -> Key Vault version, as of the previous successful LoadKeysAsync call. Kept purely to
    // log ADR 0011 §3.5's "kid vanished early" anomaly warning when a previously-published kid's
    // underlying key version disappears from Key Vault entirely (not merely disabled, and not a
    // normal retirement-window expiry) before it should have. Losing this across a process restart
    // only means possibly missing one log line — it never gates a trust decision.
    private IReadOnlyDictionary<string, string> _previouslyPublishedKidVersions =
        new Dictionary<string, string>(StringComparer.Ordinal);

    // The included version set (by version identifier, Enabled state, and whether the entry was
    // the active version) as of the previous successful LoadKeysAsync call. IsActive has to be
    // part of the comparison, not just membership and Enabled — see ToVersionSet's remarks. Null
    // means "no successful LoadKeysAsync has run yet" — a state HasKeySetChangedAsync never
    // actually observes, since the base class only calls it once a previous SigningKeySet already
    // exists (ADR 0011 §3.2), which itself implies at least one successful LoadKeysAsync already
    // populated this field.
    private IReadOnlySet<(string Version, bool Enabled, bool IsActive)>? _previouslyIncludedVersions;

    /// <summary>
    /// Initialises the service with its options, time source, and the Key Vault seams it signs
    /// and reads key metadata through.
    /// </summary>
    public AzureKeyVaultRemoteSigningJwtSigningService(
        IOptions<AzureKeyVaultRemoteSigningOptions> options,
        TimeProvider timeProvider,
        IKeyVaultKeyReader keyReader,
        IKeyVaultSigner signer,
        ISigningKeyRetirementWindowProvider retirementWindowProvider,
        ISanitizingLogger<AzureKeyVaultRemoteSigningJwtSigningService> logger)
        : base(options, timeProvider)
    {
        ArgumentNullException.ThrowIfNull(options);
        ArgumentNullException.ThrowIfNull(timeProvider);
        ArgumentNullException.ThrowIfNull(keyReader);
        ArgumentNullException.ThrowIfNull(signer);
        ArgumentNullException.ThrowIfNull(retirementWindowProvider);
        ArgumentNullException.ThrowIfNull(logger);

        _options = options;
        _timeProvider = timeProvider;
        _keyReader = keyReader;
        _signer = signer;
        _retirementWindowProvider = retirementWindowProvider;
        _logger = logger;
    }

    /// <inheritdoc/>
    protected override async ValueTask<SigningKeySet> LoadKeysAsync(CancellationToken cancellationToken)
    {
        var (allVersions, included) = await ComputeIncludedVersionsAsync(cancellationToken).ConfigureAwait(false);

        var keyPairs = new List<SigningKeyPair>(included.Count);
        var kidToUri = new Dictionary<string, Uri>(included.Count, StringComparer.Ordinal);
        var newKidVersions = new Dictionary<string, string>(included.Count, StringComparer.Ordinal);

        try
        {
            foreach (var entry in included)
            {
                var (publicKey, keyType) = await _keyReader
                    .GetKeyMaterialAsync(entry.Version.Version, cancellationToken)
                    .ConfigureAwait(false);

                SigningKeyDescriptor descriptor;
                try
                {
                    descriptor = KeyVaultSigningKeyDescriptorFactory.BuildDescriptor(
                        publicKey,
                        keyType,
                        _options.Value.Algorithm,
                        nameof(AzureKeyVaultRemoteSigningOptions),
                        "Key Vault key");
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

                keyPairs.Add(new SigningKeyPair { Descriptor = descriptor, PrivateKey = publicKey });
                kidToUri[descriptor.Kid] = entry.Version.Id;
                newKidVersions[descriptor.Kid] = entry.Version.Version;
            }
        }
        catch
        {
            // Every key handle obtained for a version processed before the failure — this provider
            // only ever holds public-only handles, never real private key material — has already
            // been added to keyPairs. Leaving these undisposed on a partial failure would leak live
            // key handles until GC finalization.
            foreach (var pair in keyPairs)
                pair.PrivateKey.Dispose();
            throw;
        }

        WarnIfPreviouslyPublishedKidVanished(kidToUri.Keys, allVersions);
        _previouslyPublishedKidVersions = newKidVersions;
        _previouslyIncludedVersions = ToVersionSet(included);

        var set = new SigningKeySet(keyPairs);

        // Atomic wholesale replacement, deliberately assigned only right before returning the new
        // set — see the field's own doc comment above for the consistency trade-off this implies.
        _kidToKeyVersionUri = kidToUri;

        return set;
    }

    /// <inheritdoc/>
    protected override async ValueTask<ReadOnlyMemory<byte>> SignInputAsync(
        SigningKeyPair activeKey, byte[] signingInput, CancellationToken cancellationToken)
    {
        var mapping = _kidToKeyVersionUri;
        if (mapping is null || !mapping.TryGetValue(activeKey.Descriptor.Kid, out var keyVersionUri))
        {
            throw new AzureKeyVaultSigningException(
                $"No Key Vault key version is registered for kid '{activeKey.Descriptor.Kid}'. This should not " +
                "happen under normal operation; retrying the request should self-heal once the next key refresh " +
                "completes.");
        }

        return await _signer
            .SignAsync(keyVersionUri, activeKey.Descriptor.Kid, activeKey.Descriptor.Algorithm, signingInput, cancellationToken)
            .ConfigureAwait(false);
    }

    /// <inheritdoc/>
    /// <remarks>
    /// <para>
    /// Recomputes the included version set from the same cheap, metadata-only enumeration
    /// (<see cref="IKeyVaultKeyReader.GetKeyVersionsAsync"/> — no key material download) and
    /// rotation-timeline derivation that <see cref="LoadKeysAsync"/> itself performs
    /// (<see cref="ComputeIncludedVersionsAsync"/>), and compares it — by version identifier,
    /// <see cref="KeyVaultKeyVersionInfo.Enabled"/> state, and which entry is active — against what
    /// was included as of the last successful <see cref="LoadKeysAsync"/> cycle. The comparison
    /// covers the whole included set, not merely the active version: a non-active version's
    /// <c>Enabled</c> flag flipping, or a version entering or leaving its retirement window purely
    /// from elapsed time, must still be reported as a change even when the active version is
    /// unchanged.
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
        var currentVersions = ToVersionSet(included);

        // The base class only ever calls this once a previous SigningKeySet already exists (ADR
        // 0011 §3.2), which itself implies at least one successful LoadKeysAsync already ran and
        // populated _previouslyIncludedVersions — the null-forgiving operator relies on that
        // guarantee rather than re-checking it.
        return !currentVersions.SetEquals(_previouslyIncludedVersions!);
    }

    /// <summary>
    /// Enumerates every key version Key Vault has ever recorded and derives the currently included
    /// version set (active version first, per <see cref="KeyVaultSigningKeyRotation.SelectIncludedVersions{T}"/>)
    /// from it. Shared by <see cref="LoadKeysAsync"/> and <see cref="HasKeySetChangedAsync"/> so the
    /// metadata-only "ask" step in front of a reload uses the exact same rotation-timeline
    /// derivation as the reload itself.
    /// </summary>
    private async ValueTask<(
        List<KeyVaultKeyVersionInfo> AllVersions,
        List<KeyVaultSigningKeyRotation.ActivationEntry<KeyVaultKeyVersionInfo>> Included)>
        ComputeIncludedVersionsAsync(CancellationToken cancellationToken)
    {
        var keyIdentifier = _options.Value.KeyIdentifier;

        // Confirmed, not assumed (issue #300; see ADR 0011 Amendment 3 for the full research and
        // rationale): GetKeyVersionsAsync returns a complete, consistent view of every version Key
        // Vault has ever recorded for this key name during normal operation — this is what makes
        // the FirstEverVersion immediate-activation exemption in BuildActivationTimeline safe. Per
        // Microsoft's documented Key Vault reliability model, all reads and writes are served from
        // a single active region with synchronous zone-redundant replication, so under steady
        // state there is no lagging read replica that a list call could observe. The only
        // documented staleness window is a Microsoft-triggered regional failover, during which the
        // vault runs read-only against an asynchronously-replicated secondary that may be missing
        // very recent writes — a rare, best-effort event that can take hours to occur, not a
        // per-request consistency knob a caller can trigger or race. The only scenario this could
        // affect is a genuinely brand-new key (created less than KeySourceRefreshInterval ago) whose true
        // first version is transiently missing from the list during such a failover — a narrow
        // window that fails toward a transient relying-party rejection, not toward forging a token
        // with an unauthorized key, and one that self-heals on the next refresh cycle once the
        // primary region recovers. Accepted as-is rather than mitigated: mitigating it would
        // require reintroducing exactly the kind of process-local "have I seen this before" state
        // that was deliberately eliminated elsewhere in this method for restart/multi-replica
        // correctness, to guard against an outage-recovery mode that already self-heals.
        var allVersions = new List<KeyVaultKeyVersionInfo>();
        await foreach (var version in _keyReader.GetKeyVersionsAsync(cancellationToken).ConfigureAwait(false))
            allVersions.Add(version);

        if (allVersions.Count == 0)
        {
            throw new ZeeKayDaConfigurationException(
                new ZeeKayDaConfigurationFailure(
                    "signing.azure_key_vault.no_key_versions",
                    $"Key Vault key '{keyIdentifier.Name}' in vault '{keyIdentifier.VaultUri}' has no versions. " +
                    "Create at least one key version before starting the host."));
        }

        var now = _timeProvider.GetUtcNow();

        // AzureKeyVaultRemoteSigningOptionsValidator rejects null (static-source mode is not
        // supported by this provider), so the value is guaranteed non-null by the time this runs.
        var timeline = KeyVaultSigningKeyRotation.BuildActivationTimeline(allVersions, _options.Value.KeySourceRefreshInterval!.Value);

        var active = KeyVaultSigningKeyRotation.SelectActiveVersion(timeline, now) ?? throw new ZeeKayDaConfigurationException(
            new ZeeKayDaConfigurationFailure(
                "signing.azure_key_vault.no_active_key",
                $"No enabled, time-eligible version of Key Vault key '{keyIdentifier.Name}' in vault " +
                $"'{keyIdentifier.VaultUri}' has activated yet. Verify the key has at least one enabled " +
                "version whose NotBefore/ExpiresOn window includes the current time."));

        var retirementWindow = _retirementWindowProvider.GetRetirementWindow();
        var included = KeyVaultSigningKeyRotation.SelectIncludedVersions(timeline, active, now, retirementWindow);

        return (allVersions, included);
    }

    /// <summary>
    /// Projects an included version list into a set suitable for change comparison in
    /// <see cref="HasKeySetChangedAsync"/>. Includes an <c>IsActive</c> bit — keyed by position,
    /// since <see cref="KeyVaultSigningKeyRotation.SelectIncludedVersions{T}"/> always places the
    /// active version at index 0 — alongside version identifier and <c>Enabled</c> state.
    /// </summary>
    /// <remarks>
    /// Comparing only version identifier and <c>Enabled</c> state (without <c>IsActive</c>) misses
    /// the moment a rotation actually completes: because <c>KeySourceRefreshInterval</c> is both
    /// the poll cadence and the publish-then-activate lead time, the poll where v2 is published
    /// (not yet active alongside active v1) and the later poll where v2 becomes active (v1 still
    /// retiring) both produce the identical <c>{v1, v2}</c> version-identifier/<c>Enabled</c> set —
    /// so the activation poll would be indistinguishable from "nothing changed" and the reload that
    /// promotes v2 to active would be skipped indefinitely. See <see cref="HasKeySetChangedAsync"/>'s
    /// remarks for the full two-poll failure mode.
    /// </remarks>
    private static HashSet<(string Version, bool Enabled, bool IsActive)> ToVersionSet(
        IEnumerable<KeyVaultSigningKeyRotation.ActivationEntry<KeyVaultKeyVersionInfo>> included) =>
        included.Select((entry, i) => (entry.Version.Version, entry.Version.Enabled, IsActive: i == 0)).ToHashSet();

    private void WarnIfPreviouslyPublishedKidVanished(
        IEnumerable<string> newKids, IReadOnlyList<KeyVaultKeyVersionInfo> currentRawVersions)
    {
        foreach (var (kid, version) in KeyVaultSigningKeyRotation.FindVanishedKids(
            _previouslyPublishedKidVersions, newKids, currentRawVersions))
        {
            _logger.LogWarning(
                "Azure Key Vault signing key with kid {Kid} (Key Vault version {Version}) is no longer present " +
                "in Key Vault at all. It was previously published and may still be cached in a relying party's " +
                "JWKS; an unexpected disappearance (as opposed to a normal retirement-window expiry) may cause " +
                "token validation failures. See ADR 0011 §3.5.",
                kid, version);
        }
    }
}
