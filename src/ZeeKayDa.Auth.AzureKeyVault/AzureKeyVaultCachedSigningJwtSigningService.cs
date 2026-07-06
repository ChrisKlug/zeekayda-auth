using System.Linq;
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
        var certificateIdentifier = _options.Value.CertificateIdentifier;

        // See AzureKeyVaultRemoteSigningJwtSigningService.LoadKeysAsync for the full research and
        // rationale (issue #300 / ADR 0011 Amendment 3) behind treating this list as a complete,
        // consistent view of every certificate version Key Vault has ever recorded during normal
        // operation — the same Key Vault reliability model applies to certificates as to keys.
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
        var timeline = BuildActivationTimeline(allVersions, _options.Value.RefreshInterval);

        var active = SelectActiveVersion(timeline, now) ?? throw new ZeeKayDaConfigurationException(
            new ZeeKayDaConfigurationFailure(
                "signing.azure_key_vault.no_active_key",
                $"No enabled, time-eligible version of Key Vault certificate '{certificateIdentifier.Name}' in " +
                $"vault '{certificateIdentifier.VaultUri}' has activated yet. Verify the certificate has at " +
                "least one enabled version whose NotBefore/ExpiresOn window includes the current time."));

        var retirementWindow = _retirementWindowProvider.GetRetirementWindow();
        var included = SelectIncludedVersions(timeline, active, now, retirementWindow);

        var keyPairs = new List<SigningKeyPair>(included.Count);
        var newKidVersions = new Dictionary<string, string>(included.Count, StringComparer.Ordinal);

        try
        {
            foreach (var entry in included)
            {
                var isActive = entry.Version.Version == active.Version.Version;

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
                    descriptor = BuildDescriptor(publicKey, keyType, _options.Value.Algorithm);
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

        return new SigningKeySet(keyPairs);
    }

    private static List<ActivationEntry> BuildActivationTimeline(
        IReadOnlyList<KeyVaultCertificateVersionInfo> allVersions, TimeSpan refreshInterval)
    {
        var firstEverVersion = allVersions
            .OrderBy(v => v.CreatedOn)
            .ThenBy(v => v.Version, StringComparer.Ordinal)
            .First()
            .Version;

        // See AzureKeyVaultRemoteSigningJwtSigningService.BuildActivationTimeline for the full
        // derivation and rationale — the algorithm is identical here, applied to certificate
        // versions instead of key versions.
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
        foreach (var entry in ascendingTimeline.Where(entry => entry.ActivatesAt <= now && IsEligibleAt(entry.Version, now)))
        {
            active = entry;
        }

        return active;
    }

    private static List<ActivationEntry> SelectIncludedVersions(
        IReadOnlyList<ActivationEntry> timeline, ActivationEntry active, DateTimeOffset now, TimeSpan retirementWindow)
    {
        // Active goes first — the base class treats index 0 as the active signing key.
        var included = new List<ActivationEntry> { active };

        foreach (var entry in timeline
            .Where(entry => entry.Version.Version != active.Version.Version)
            // Disabled is an immediate, unconditional exclusion — bypasses the retirement window
            // entirely, so an operator disabling a suspected-compromised certificate takes effect
            // at once.
            .Where(entry => entry.Version.Enabled))
        {
            var notYetActive = entry.ActivatesAt > now;
            var stillWithinRetirementWindow = entry.RetiredAt is { } retiredAt && now - retiredAt <= retirementWindow;

            if (notYetActive || stillWithinRetirementWindow)
                included.Add(entry);
        }

        return included;
    }

    private static bool IsEligibleAt(KeyVaultCertificateVersionInfo version, DateTimeOffset pointInTime) =>
        version.Enabled
        && (version.NotBefore is not { } notBefore || notBefore <= pointInTime)
        && (version.ExpiresOn is not { } expiresOn || pointInTime <= expiresOn);

    private static DateTimeOffset Max(DateTimeOffset a, DateTimeOffset b) => a >= b ? a : b;

    /// <summary>
    /// Builds a <see cref="SigningKeyDescriptor"/> — and therefore its <c>kid</c> — from a
    /// public-only key. Always called with the handle from
    /// <see cref="IKeyVaultCertificateReader.GetPublicKeyMaterialAsync"/>, for every included
    /// version including the active one, so every version's <c>kid</c> is derived through the same
    /// single code path.
    /// </summary>
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
        // Exporting only the public parameters here is always permitted — unlike exporting the
        // private components, it never requires an "exportable" capability on the key handle. rsa
        // is always public-only in practice (see BuildDescriptor's remarks), but includePrivateParameters:
        // false is kept explicit regardless, since exporting private material was never needed here.
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
    /// <see cref="AzureKeyVaultCachedSigningOptions.Algorithm"/> does not match the actual
    /// certificate key's type. Without this check the mismatch would only surface later as a more
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
                    $"AzureKeyVaultCachedSigningOptions.Algorithm is {algorithm}, but the Key Vault certificate " +
                    "key is an RSA key. Use an RSA algorithm (RS256, RS384, RS512, PS256, PS384, or PS512)."));
        }

        if (keyType == SigningKeyType.Ec && isRsaAlgorithm)
        {
            throw new ZeeKayDaConfigurationException(
                new ZeeKayDaConfigurationFailure(
                    "signing.azure_key_vault.algorithm_key_type_mismatch",
                    $"AzureKeyVaultCachedSigningOptions.Algorithm is {algorithm}, but the Key Vault certificate " +
                    "key is an EC key. Use an EC algorithm (ES256, ES384, or ES512)."));
        }
    }

    private void WarnIfPreviouslyPublishedKidVanished(
        IEnumerable<string> newKids, IReadOnlyList<KeyVaultCertificateVersionInfo> currentRawVersions)
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
                "Azure Key Vault signing certificate with kid {Kid} (Key Vault version {Version}) is no longer " +
                "present in Key Vault at all. It was previously published and may still be cached in a relying " +
                "party's JWKS; an unexpected disappearance (as opposed to a normal retirement-window expiry) may " +
                "cause token validation failures. See ADR 0011 §3.5.",
                kid, version);
        }
    }

    private readonly record struct ActivationEntry(
        KeyVaultCertificateVersionInfo Version, DateTimeOffset ActivatesAt, DateTimeOffset? RetiredAt);
}
