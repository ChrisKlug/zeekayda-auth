using System.Security.Cryptography;
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
/// <see cref="JwkThumbprint.Compute(RSAParameters)"/> / <see cref="JwkThumbprint.Compute(ECParameters)"/>),
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
        var keyIdentifier = _options.Value.KeyIdentifier;

        // Assumes GetKeyVersionsAsync returns a complete, consistent view of every version Key
        // Vault has ever recorded for this key name — this is what makes the FirstEverVersion
        // immediate-activation exemption in BuildActivationTimeline safe. A single-region vault
        // gives strongly-consistent listing; a cross-region failover with replication lag could in
        // principle return an incomplete list. The only scenario this could affect is a genuinely
        // brand-new key (created less than RefreshInterval ago) whose true first version is
        // transiently missing from the list during such a failover — a narrow window that fails
        // toward a transient relying-party rejection, not toward forging a token with an
        // unauthorized key. Not treated as a defect to guard against here: doing so would require
        // reintroducing exactly the kind of process-local "have I seen this before" state that was
        // deliberately eliminated elsewhere in this method for restart/multi-replica correctness.
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
        var timeline = BuildActivationTimeline(allVersions, _options.Value.RefreshInterval);

        var active = SelectActiveVersion(timeline, now) ?? throw new ZeeKayDaConfigurationException(
            new ZeeKayDaConfigurationFailure(
                "signing.azure_key_vault.no_active_key",
                $"No enabled, time-eligible version of Key Vault key '{keyIdentifier.Name}' in vault " +
                $"'{keyIdentifier.VaultUri}' has activated yet. Verify the key has at least one enabled " +
                "version whose NotBefore/ExpiresOn window includes the current time."));

        var retirementWindow = _retirementWindowProvider.GetRetirementWindow();
        var included = SelectIncludedVersions(timeline, active, now, retirementWindow);

        var keyPairs = new List<SigningKeyPair>(included.Count);
        var kidToUri = new Dictionary<string, Uri>(included.Count, StringComparer.Ordinal);
        var newKidVersions = new Dictionary<string, string>(included.Count, StringComparer.Ordinal);

        foreach (var entry in included)
        {
            var (publicKey, keyType) = await _keyReader
                .GetKeyMaterialAsync(entry.Version.Version, cancellationToken)
                .ConfigureAwait(false);

            var descriptor = BuildDescriptor(publicKey, keyType, _options.Value.Algorithm);
            keyPairs.Add(new SigningKeyPair { Descriptor = descriptor, PrivateKey = publicKey });
            kidToUri[descriptor.Kid] = entry.Version.Id;
            newKidVersions[descriptor.Kid] = entry.Version.Version;
        }

        WarnIfPreviouslyPublishedKidVanished(kidToUri.Keys, allVersions);
        _previouslyPublishedKidVersions = newKidVersions;

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

    private static List<ActivationEntry> BuildActivationTimeline(
        IReadOnlyList<KeyVaultKeyVersionInfo> allVersions, TimeSpan refreshInterval)
    {
        var firstEverVersion = allVersions
            .OrderBy(v => v.CreatedOn)
            .ThenBy(v => v.Version, StringComparer.Ordinal)
            .First()
            .Version;

        // ActivatesAt is the earliest instant a version could ever legitimately win
        // SelectActiveVersion's selection — the publish-then-activate delay (or the immediate
        // bootstrap exemption for the very first version ever created), floored by NotBefore when
        // the operator has explicitly scheduled the version's go-live later than that. Folding
        // NotBefore in here (rather than treating it as a separate check applied only at "now")
        // means every downstream computation that orders by, or reasons about, ActivatesAt
        // automatically accounts for it correctly — there is no other point in this method that
        // needs to know about NotBefore specially.
        var ordered = allVersions
            .Select(v => new
            {
                Version = v,
                ActivatesAt = Max(
                    v.Version == firstEverVersion ? v.CreatedOn : v.CreatedOn + refreshInterval,
                    v.NotBefore ?? DateTimeOffset.MinValue),
            })
            .OrderBy(x => x.ActivatesAt)
            .ThenBy(x => x.Version.CreatedOn)
            .ThenBy(x => x.Version.Version, StringComparer.Ordinal)
            .ToList();

        // RetiredAt(v) must be the ActivatesAt of whichever version *actually* superseded v as the
        // active signer — i.e. the next entry, in ActivatesAt order, that could ever legitimately
        // win SelectActiveVersion's selection. A version that is disabled, or that is already
        // outside its own ExpiresOn window at the instant it would activate, can never win that
        // selection (see IsEligibleAt / SelectActiveVersion), so it must be skipped when looking for
        // a predecessor's real successor — it is simply never anyone's successor. Naively using the
        // positionally-next entry regardless of eligibility lets a chronologically-intervening but
        // never-actually-active version's ActivatesAt gate a real predecessor's retirement window far
        // too early, silently dropping a still-legitimately-active (or still-within-window) key out
        // of GetSigningKeysAsync()/the JWKS before its already-issued tokens have stopped being
        // relied upon — exactly the trust-boundary regression ADR 0011 §3.3 exists to prevent.
        //
        // Eligibility here is evaluated at the *candidate's own* ActivatesAt. Because ActivatesAt
        // already incorporates NotBefore (above), IsEligibleAt's NotBefore check is satisfied by
        // construction at that point — what remains to test is exactly Enabled and "already past
        // ExpiresOn by the time it would activate", both permanent, non-time-varying disqualifications:
        // such a version can never win SelectActiveVersion at any "now", so skipping it here is
        // unconditionally correct. There is no residual imprecision left in this derivation.
        var entries = new ActivationEntry[ordered.Count];
        DateTimeOffset? nextEligibleSuccessorActivatesAt = null;
        for (var i = ordered.Count - 1; i >= 0; i--)
        {
            entries[i] = new ActivationEntry(ordered[i].Version, ordered[i].ActivatesAt, nextEligibleSuccessorActivatesAt);

            if (IsEligibleAt(ordered[i].Version, ordered[i].ActivatesAt))
                nextEligibleSuccessorActivatesAt = ordered[i].ActivatesAt;
        }

        return [.. entries];
    }

    private static ActivationEntry? SelectActiveVersion(IReadOnlyList<ActivationEntry> ascendingTimeline, DateTimeOffset now)
    {
        // The timeline is sorted ascending by ActivatesAt, so the last eligible match encountered
        // while scanning forward is always the one with the greatest ActivatesAt <= now.
        ActivationEntry? active = null;
        foreach (var entry in ascendingTimeline)
        {
            if (entry.ActivatesAt > now)
                continue;

            if (!IsEligibleAt(entry.Version, now))
                continue;

            active = entry;
        }

        return active;
    }

    private static List<ActivationEntry> SelectIncludedVersions(
        IReadOnlyList<ActivationEntry> timeline, ActivationEntry active, DateTimeOffset now, TimeSpan retirementWindow)
    {
        // Active goes first — the base class treats index 0 as the active signing key.
        var included = new List<ActivationEntry> { active };

        foreach (var entry in timeline)
        {
            if (entry.Version.Version == active.Version.Version)
                continue;

            // Disabled is an immediate, unconditional exclusion — bypasses the retirement window
            // entirely, so an operator disabling a suspected-compromised key takes effect at once.
            if (!entry.Version.Enabled)
                continue;

            var notYetActive = entry.ActivatesAt > now;
            var stillWithinRetirementWindow = entry.RetiredAt is { } retiredAt && now - retiredAt <= retirementWindow;

            if (notYetActive || stillWithinRetirementWindow)
                included.Add(entry);
        }

        return included;
    }

    // Named generically ("At", not "Now") because this same Enabled/NotBefore/ExpiresOn check is
    // evaluated at two different kinds of point in time: the current wall-clock time (from
    // SelectActiveVersion, to pick today's active signer) and each candidate's own ActivatesAt
    // (from BuildActivationTimeline, to decide whether that candidate could ever legitimately have
    // won that same selection once it activated). The NotBefore half of this check is, by the time
    // BuildActivationTimeline calls it, already guaranteed true against ActivatesAt — see that
    // method's comments — but it is left in place because SelectActiveVersion still needs it
    // checked against the real wall-clock "now".
    private static bool IsEligibleAt(KeyVaultKeyVersionInfo version, DateTimeOffset pointInTime) =>
        version.Enabled
        && (version.NotBefore is not { } notBefore || notBefore <= pointInTime)
        && (version.ExpiresOn is not { } expiresOn || pointInTime <= expiresOn);

    private static DateTimeOffset Max(DateTimeOffset a, DateTimeOffset b) => a >= b ? a : b;

    private static SigningKeyDescriptor BuildDescriptor(
        AsymmetricAlgorithm publicKey, SigningKeyType keyType, SigningAlgorithm algorithm)
    {
        ValidateAlgorithmFamilyMatchesKeyType(keyType, algorithm);

        return keyType switch
        {
            SigningKeyType.Rsa => BuildRsaDescriptor((RSA)publicKey, algorithm),
            SigningKeyType.Ec => BuildEcDescriptor((ECDsa)publicKey, algorithm),
            _ => throw new NotSupportedException($"Signing key type {keyType} is not supported."),
        };
    }

    private static SigningKeyDescriptor BuildRsaDescriptor(RSA rsa, SigningAlgorithm algorithm)
    {
        var parameters = rsa.ExportParameters(includePrivateParameters: false);
        var kid = JwkThumbprint.Compute(parameters);
        return new SigningKeyDescriptor(kid, algorithm, parameters);
    }

    private static SigningKeyDescriptor BuildEcDescriptor(ECDsa ecdsa, SigningAlgorithm algorithm)
    {
        var parameters = ecdsa.ExportParameters(includePrivateParameters: false);
        var kid = JwkThumbprint.Compute(parameters);
        return new SigningKeyDescriptor(kid, algorithm, parameters);
    }

    /// <summary>
    /// Fails fast with a clear, Key-Vault-specific message when the configured
    /// <see cref="AzureKeyVaultRemoteSigningOptions.Algorithm"/> does not match the actual Key
    /// Vault key's type. Without this check the mismatch would only surface later as a more
    /// generic <c>ZeeKayDaConfigurationException</c> from the base class's
    /// <c>ValidateKeyAlgorithmCompatibility</c>, with no Key-Vault-specific remediation guidance.
    /// </summary>
    private static void ValidateAlgorithmFamilyMatchesKeyType(SigningKeyType keyType, SigningAlgorithm algorithm)
    {
        var isRsaAlgorithm = algorithm is
            SigningAlgorithm.RS256 or SigningAlgorithm.RS384 or SigningAlgorithm.RS512
            or SigningAlgorithm.PS256 or SigningAlgorithm.PS384 or SigningAlgorithm.PS512;

        if (keyType == SigningKeyType.Rsa && !isRsaAlgorithm)
        {
            throw new ZeeKayDaConfigurationException(
                new ZeeKayDaConfigurationFailure(
                    "signing.azure_key_vault.algorithm_key_type_mismatch",
                    $"AzureKeyVaultRemoteSigningOptions.Algorithm is {algorithm}, but the Key Vault key is an " +
                    "RSA key. Use an RSA algorithm (RS256, RS384, RS512, PS256, PS384, or PS512)."));
        }

        if (keyType == SigningKeyType.Ec && isRsaAlgorithm)
        {
            throw new ZeeKayDaConfigurationException(
                new ZeeKayDaConfigurationFailure(
                    "signing.azure_key_vault.algorithm_key_type_mismatch",
                    $"AzureKeyVaultRemoteSigningOptions.Algorithm is {algorithm}, but the Key Vault key is an " +
                    "EC key. Use an EC algorithm (ES256, ES384, or ES512)."));
        }
    }

    private void WarnIfPreviouslyPublishedKidVanished(
        IEnumerable<string> newKids, IReadOnlyList<KeyVaultKeyVersionInfo> currentRawVersions)
    {
        if (_previouslyPublishedKidVersions.Count == 0)
            return;

        var newKidSet = new HashSet<string>(newKids, StringComparer.Ordinal);
        var currentVersionStrings = new HashSet<string>(
            currentRawVersions.Select(v => v.Version), StringComparer.Ordinal);

        foreach (var (kid, version) in _previouslyPublishedKidVersions)
        {
            if (newKidSet.Contains(kid))
                continue;

            if (currentVersionStrings.Contains(version))
                continue; // Still in Key Vault — excluded for an expected reason (disabled or fully retired).

            _logger.LogWarning(
                "Azure Key Vault signing key with kid {Kid} (Key Vault version {Version}) is no longer present " +
                "in Key Vault at all. It was previously published and may still be cached in a relying party's " +
                "JWKS; an unexpected disappearance (as opposed to a normal retirement-window expiry) may cause " +
                "token validation failures. See ADR 0011 §3.5.",
                kid, version);
        }
    }

    private readonly record struct ActivationEntry(
        KeyVaultKeyVersionInfo Version, DateTimeOffset ActivatesAt, DateTimeOffset? RetiredAt);
}
