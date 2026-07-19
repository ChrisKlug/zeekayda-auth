using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using ZeeKayDa.Auth.Logging;
using ZeeKayDa.Auth.Tokens;

namespace ZeeKayDa.Auth.Windows;

/// <summary>
/// <see cref="IJwtSigningService"/> that loads one or more X.509 certificates from a Windows
/// Certificate Store by thumbprint and signs locally, in process, using each certificate's CNG/CAPI
/// private-key handle.
/// </summary>
/// <remarks>
/// <para>
/// <see cref="LoadKeysAsync"/> derives the currently trusted certificate set from the certificates'
/// own <c>NotBefore</c>/<c>NotAfter</c> fields, mapped onto <see cref="RotationKey.ActivatesAt"/>/
/// <see cref="RotationKey.ExpiresAt"/> and passed to the shared, anchor-agnostic
/// <see cref="SigningKeyRotation"/> component — see that type's remarks for the full rationale (why
/// the anchor differs from the Key Vault providers' <c>CreatedOn</c>-based derivation). Only the
/// active certificate's private key is ever held: every other included certificate
/// (published-but-not-yet-active, or still within its retirement window) gets only a public-only
/// handle, since it is never used to sign — only exposed via the JWKS (ADR 0011 §3.3(c)).
/// </para>
/// <para>
/// This class does not override <see cref="JwtSigningService{TOptions}.SignInputAsync"/> — per ADR
/// 0011 Amendment 2(a), this provider signs with local key handles exactly like the development
/// provider and the Azure Key Vault *cached* signing provider, so the base class's default
/// local-crypto implementation is exactly what it needs. There is also no
/// <c>WindowsCertificateStoreSigningException</c> transport type: unlike Key Vault, there is no
/// network round trip at sign time, so there is no transient-fault surface to wrap.
/// </para>
/// <para>
/// <c>kid</c> is the RFC 7638 JWK thumbprint of each certificate's public key (via the shared
/// <see cref="SigningKeyDescriptorFactory"/>), never the certificate's own X.509 thumbprint — a
/// <c>kid</c> is always public, so using the store thumbprint directly would be exactly the kind of
/// external-identifier leak <see cref="JwkThumbprint"/> exists to avoid.
/// </para>
/// </remarks>
internal sealed class WindowsCertificateStoreSigningJwtSigningService : JwtSigningService<WindowsCertificateStoreSigningOptions>
{
    // Bound once (IOptions<T>, not IOptionsMonitor<T>) — HasKeySetChangedAsync's zero-store-access
    // shortcut relies on the registered thumbprint set being fixed for the process lifetime.
    // Revisit that override if the thumbprint set ever becomes hot-reloadable.
    private readonly IOptions<WindowsCertificateStoreSigningOptions> _options;
    private readonly TimeProvider _timeProvider;
    private readonly ICertificateStoreReader _storeReader;
    private readonly ISigningKeyRetirementWindowProvider _retirementWindowProvider;
    private readonly ISanitizingLogger<WindowsCertificateStoreSigningJwtSigningService> _logger;

    // The registered RotationKeys (thumbprint + NotBefore/NotAfter) as of the last successful
    // LoadKeysAsync call. An X.509 thumbprint is a SHA-1 hash of the certificate's DER encoding —
    // content-addressed — so a fixed thumbprint's NotBefore/NotAfter cannot change without the
    // thumbprint itself changing, and the configured thumbprint set is fixed for the lifetime of
    // the process (IOptions<T>, not IOptionsMonitor<T> — see AddWindowsCertificateStoreSigning's
    // remarks: adding, removing, or replacing a registered certificate requires a host restart).
    // Caching this list therefore lets HasKeySetChangedAsync recompute the rotation timeline with
    // zero store access — see that method's remarks. Null means "no successful LoadKeysAsync has
    // run yet," a state HasKeySetChangedAsync never actually observes (ADR 0011 §3.2: the base
    // class only calls it once a previous SigningKeySet already exists).
    private IReadOnlyList<RotationKey>? _rotationKeys;

    // The included key set (by thumbprint and whether the entry was active) as of the last
    // successful LoadKeysAsync call. IsActive has to be part of the comparison, not just
    // membership — see SigningKeyRotation.ToChangeDetectionSet's remarks.
    private IReadOnlySet<(string Id, bool IsActive)>? _previouslyIncludedKeys;

    public WindowsCertificateStoreSigningJwtSigningService(
        IOptions<WindowsCertificateStoreSigningOptions> options,
        TimeProvider timeProvider,
        ICertificateStoreReader storeReader,
        ISigningKeyRetirementWindowProvider retirementWindowProvider,
        ISanitizingLogger<WindowsCertificateStoreSigningJwtSigningService> logger)
        : base(options, timeProvider)
    {
        ArgumentNullException.ThrowIfNull(options);
        ArgumentNullException.ThrowIfNull(timeProvider);
        ArgumentNullException.ThrowIfNull(storeReader);
        ArgumentNullException.ThrowIfNull(retirementWindowProvider);
        ArgumentNullException.ThrowIfNull(logger);

        _options = options;
        _timeProvider = timeProvider;
        _storeReader = storeReader;
        _retirementWindowProvider = retirementWindowProvider;
        _logger = logger;
    }

    /// <inheritdoc/>
    protected override ValueTask<SigningKeySet> LoadKeysAsync(CancellationToken cancellationToken)
    {
        var options = _options.Value;
        var thumbprints = new List<string>(1 + options.AdditionalThumbprints.Count) { options.Thumbprint };
        thumbprints.AddRange(options.AdditionalThumbprints);

        // Fetch every registered certificate up front — the timeline needs every registered
        // certificate's NotBefore/NotAfter, not just the ones that end up "included", to correctly
        // compute retirement anchors.
        var certificatesByThumbprint = new Dictionary<string, X509Certificate2>(thumbprints.Count, StringComparer.Ordinal);
        // GetRSAPrivateKey()/GetECDsaPrivateKey()/GetRSAPublicKey()/GetECDsaPublicKey() return
        // handle objects that remain valid after the parent X509Certificate2 is disposed
        // (CNG/CAPI key handle duplication, .NET Core 3.0+) — safe to dispose every fetched
        // certificate once all needed handles have been extracted below.
        using var certificateLease = new CertificateCollectionLease(certificatesByThumbprint.Values);

        foreach (var thumbprint in thumbprints)
            certificatesByThumbprint[thumbprint] = _storeReader.GetCertificate(thumbprint, options.StoreLocation, options.StoreName);

        var now = _timeProvider.GetUtcNow();
        var rotationKeys = certificatesByThumbprint
            .Select(kvp => new RotationKey(
                kvp.Key, new DateTimeOffset(kvp.Value.NotBefore), new DateTimeOffset(kvp.Value.NotAfter)))
            .ToList();

        var timeline = SigningKeyRotation.BuildActivationTimeline(rotationKeys);
        var active = SigningKeyRotation.SelectActiveKey(timeline, now)
            ?? throw new ZeeKayDaConfigurationException(new ZeeKayDaConfigurationFailure(
                "signing.windows_certificate_store.no_active_certificate",
                "No registered certificate is currently eligible to sign. Verify at least one " +
                "registered certificate's NotBefore has arrived and its NotAfter has not yet passed."));

        var retirementWindow = _retirementWindowProvider.GetRetirementWindow();
        var included = SigningKeyRotation.SelectIncludedKeys(timeline, active, now, retirementWindow);

        // WindowsCertificateStoreSigningOptionsValidator rejects null (static-source mode is
        // not supported by this provider), so this is guaranteed non-null.
        LogCertificateStatuses(timeline, active, included, now, options.KeySourceRefreshInterval!.Value, retirementWindow, certificatesByThumbprint);

        // HasKeySetChangedAsync itself repeats this same check on every ask cycle once a
        // previous load exists (see that method's remarks), so only the cold-start call needs
        // it here too: the very first LoadKeysAsync call, before any ask has ever run against
        // this instance. _rotationKeys is still null only on that first call — every other
        // call to LoadKeysAsync was preceded, in the same cycle, by an ask that already
        // performed this check, so repeating it here would double-log.
        if (_rotationKeys is null)
            WarnIfActiveCertificateExpiringSoon(active, now);

        var keyPairs = new List<SigningKeyPair>(included.Count);
        try
        {
            foreach (var thumbprint in included.Select(entry => entry.Key.Id))
            {
                var certificate = certificatesByThumbprint[thumbprint];
                var isActive = string.Equals(thumbprint, active.Key.Id, StringComparison.Ordinal);

                var (publicKey, keyType) = WindowsCertificateKeyExtractor.ExtractPublicKey(certificate, thumbprint);
                SigningKeyDescriptor descriptor;
                try
                {
                    descriptor = SigningKeyDescriptorFactory.BuildDescriptor(
                        publicKey,
                        keyType,
                        options.Algorithm,
                        "signing.windows_certificate_store.algorithm_key_type_mismatch",
                        mismatchedKeyType => mismatchedKeyType == SigningKeyType.Rsa
                            ? $"WindowsCertificateStoreSigningOptions.Algorithm is {options.Algorithm}, but certificate " +
                              $"'{thumbprint}' is an RSA certificate. Use an RSA algorithm (RS256, RS384, RS512, PS256, PS384, or PS512)."
                            : $"WindowsCertificateStoreSigningOptions.Algorithm is {options.Algorithm}, but certificate " +
                              $"'{thumbprint}' is an EC certificate. Use an EC algorithm (ES256, ES384, or ES512).");
                }
                catch
                {
                    // The key handle just obtained above was never added to keyPairs, so the
                    // outer catch below would not dispose it — do so here before rethrowing.
                    publicKey.Dispose();
                    throw;
                }

                AsymmetricAlgorithm signingKey;
                if (isActive)
                {
                    try
                    {
                        (signingKey, _) = WindowsCertificateKeyExtractor.ExtractPrivateKey(certificate, thumbprint);
                    }
                    catch
                    {
                        publicKey.Dispose();
                        throw;
                    }

                    // The public-only handle is now redundant: the private key just extracted
                    // carries the same public component.
                    publicKey.Dispose();
                }
                else
                {
                    signingKey = publicKey;
                }

                keyPairs.Add(new SigningKeyPair { Descriptor = descriptor, PrivateKey = signingKey });
            }
        }
        catch
        {
            // Key material for any certificate already processed before the failure would
            // otherwise leak live handles.
            foreach (var pair in keyPairs)
                pair.PrivateKey.Dispose();
            throw;
        }

        // Recorded only now — after the SigningKeySet has actually been built successfully —
        // never from HasKeySetChangedAsync's ask itself. See that method's remarks and ADR
        // 0011 §3.5's "change-detection baseline is captured only on a successful load" rule.
        _rotationKeys = rotationKeys;
        _previouslyIncludedKeys = SigningKeyRotation.ToChangeDetectionSet(included);

        // `included` (and therefore `keyPairs`, built from it above) is active-first, so
        // splitting off the first entry as the named active key is safe.
        return new ValueTask<SigningKeySet>(new SigningKeySet(keyPairs[0], keyPairs.Skip(1)));
    }

    /// <inheritdoc/>
    /// <remarks>
    /// <para>
    /// Unlike the Azure Key Vault providers' <c>HasKeySetChangedAsync</c> overrides, this override
    /// never re-opens a certificate store handle — it needs none. An X.509 thumbprint is a SHA-1
    /// hash of the certificate's own DER encoding: for a fixed thumbprint, <c>NotBefore</c>/
    /// <c>NotAfter</c> cannot change without the thumbprint itself changing, and the configured
    /// thumbprint set (<see cref="WindowsCertificateStoreSigningOptions.Thumbprint"/>/
    /// <see cref="WindowsCertificateStoreSigningOptions.AdditionalThumbprints"/>) is fixed for the
    /// lifetime of the process — it is bound once from <see cref="IOptions{TOptions}"/>, not
    /// <c>IOptionsMonitor&lt;TOptions&gt;</c>, and <c>AddWindowsCertificateStoreSigning</c>'s own
    /// remarks already document that adding, removing, or replacing a registered certificate
    /// requires a host restart. A restart is a cold start, and a cold start always calls
    /// <see cref="LoadKeysAsync"/> directly — this method is never consulted then (ADR 0011 §3.2).
    /// So, for a thumbprint that remains present and accessible in the store, the only input that
    /// can genuinely change between two calls to this method, within the same process, is elapsed
    /// time moving a certificate in or out of its active/included/retirement window — see this
    /// class's own remarks (and ADR 0011 §3.5) for the accepted, deliberate consequence that
    /// follows: an out-of-band deletion of a registered certificate from the store is not one of
    /// the things this method can ever notice. This override therefore recomputes
    /// <see cref="SigningKeyRotation.BuildActivationTimeline"/> purely from the
    /// <see cref="RotationKey"/> list recorded at the last successful <see cref="LoadKeysAsync"/>
    /// call, re-evaluated against the current time — no store access at all, which is cheaper than
    /// even the Key Vault providers' still-necessary metadata-only network call (a Key Vault
    /// version's <c>Enabled</c> flag or expiry can mutate independently of its identity between
    /// polls, so Key Vault must re-poll; a certificate's thumbprint-keyed facts cannot).
    /// </para>
    /// <para>
    /// The comparison covers the whole included set, keyed by thumbprint and which entry is
    /// active — not merely "did the active thumbprint change" — via
    /// <see cref="SigningKeyRotation.ToChangeDetectionSet"/>, exactly mirroring the Key Vault
    /// providers' comparison shape and the lesson behind it (ADR 0011 §3.5): a normal rotation
    /// between two overlapping certificates can cross a poll boundary where the included
    /// thumbprint set does not change but which entry is active does, and comparing membership
    /// alone would silently skip the reload that promotes the new active certificate.
    /// </para>
    /// <para>
    /// This method also re-evaluates <see cref="WarnIfActiveCertificateExpiringSoon"/> against the
    /// cached active entry, on every call — not only when it goes on to report a change. The base
    /// class only calls <see cref="LoadKeysAsync"/> when this method reports a change, so a
    /// long-running process with a single, stable certificate can otherwise go the rest of the
    /// process lifetime without a single reload once bootstrapped, and the warning would never
    /// re-fire even after the certificate crosses into its 30-day expiry window.
    /// <see cref="LoadKeysAsync"/> only repeats the same check for the cold-start call, before any
    /// previous load exists for this method to have run against; every other call to
    /// <see cref="LoadKeysAsync"/> was preceded, in the same cycle, by a call to this method that
    /// already performed the check, so the warning never double-logs for the same cycle.
    /// </para>
    /// <para>
    /// If no registered certificate is currently eligible to sign (every one has expired since the
    /// last load), this method reports a change rather than failing itself — the subsequent
    /// <see cref="LoadKeysAsync"/> call is what fails closed with its usual, actionable
    /// <c>signing.windows_certificate_store.no_active_certificate</c> error; this method's own
    /// contract is only ever "did the trusted set change," never "is the configuration currently
    /// valid."
    /// </para>
    /// </remarks>
    protected override ValueTask<bool> HasKeySetChangedAsync(CancellationToken cancellationToken)
    {
        // The base class only calls this once a previous SigningKeySet already exists (ADR 0011
        // §3.2), which itself implies at least one successful LoadKeysAsync already ran and
        // populated these fields — the null-forgiving operators rely on that guarantee rather than
        // re-checking it.
        var timeline = SigningKeyRotation.BuildActivationTimeline(_rotationKeys!);
        var now = _timeProvider.GetUtcNow();

        var active = SigningKeyRotation.SelectActiveKey(timeline, now);
        if (active is null)
            return new ValueTask<bool>(true);

        // Fired on every ask cycle, whether or not this cycle goes on to report a change — see
        // this method's remarks and WarnIfActiveCertificateExpiringSoon's own remarks.
        WarnIfActiveCertificateExpiringSoon(active.Value, now);

        var retirementWindow = _retirementWindowProvider.GetRetirementWindow();
        var included = SigningKeyRotation.SelectIncludedKeys(timeline, active.Value, now, retirementWindow);
        var currentIncludedKeys = SigningKeyRotation.ToChangeDetectionSet(included);

        return new ValueTask<bool>(!currentIncludedKeys.SetEquals(_previouslyIncludedKeys!));
    }

    private void LogCertificateStatuses(
        IReadOnlyList<RotationEntry> timeline,
        RotationEntry active,
        IReadOnlyList<RotationEntry> included,
        DateTimeOffset now, TimeSpan refreshInterval, TimeSpan retirementWindow,
        IReadOnlyDictionary<string, X509Certificate2> certificatesByThumbprint)
    {
        // Unlike a purely static config fact (thumbprint/subject/expiry never change once a
        // certificate is loaded), each certificate's active/included/excluded status is a function
        // of `now` and genuinely changes over the lifetime of a long-running process as a rotation
        // progresses — so, unlike a one-shot log, this is re-evaluated and logged on every
        // LoadKeysAsync call (at most once per KeySourceRefreshInterval) rather than only at first load.
        // Logging every registered certificate on every cycle — not just the currently-included
        // ones — is deliberate: it lets an operator see exactly what the current configuration
        // resolves to, including a certificate that is configured but has fallen out of the trusted
        // set entirely (its retirement window has elapsed) and can now safely be removed.
        var includedThumbprints = new HashSet<string>(
            included.Select(e => e.Key.Id), StringComparer.Ordinal);

        foreach (var entry in timeline)
        {
            var certificate = certificatesByThumbprint[entry.Key.Id];
            var status = DescribeStatus(entry, active, includedThumbprints, now, retirementWindow);

            _logger.LogInformation(
                "ZeeKayDa.Auth: Windows Certificate Store signing certificate '{Thumbprint}' " +
                "(subject '{Subject}', expires {NotAfter:O}) is {Status}.",
                entry.Key.Id, certificate.Subject, entry.Key.ExpiresAt, status);
        }

        if (SigningKeyRotation.HasTooSoonPendingActivation(timeline, active, now, refreshInterval, out var soonestPending))
        {
            _logger.LogWarning(
                "ZeeKayDa.Auth: certificate '{Thumbprint}' activates at {ActivatesAt:O}, which is less " +
                "than KeySourceRefreshInterval ({KeySourceRefreshInterval}) away from now. A relying party polling the " +
                "JWKS at KeySourceRefreshInterval cadence may not have observed this certificate's public key " +
                "before it starts signing. Set this certificate's NotBefore at least KeySourceRefreshInterval in " +
                "the future next time (see ADR 0011 §3.5 / issue #282).",
                soonestPending!.Value.Key.Id, soonestPending.Value.ActivatesAt, refreshInterval);
        }
    }

    private static string DescribeStatus(
        RotationEntry entry,
        RotationEntry active,
        HashSet<string> includedThumbprints, DateTimeOffset now, TimeSpan retirementWindow)
    {
        if (string.Equals(entry.Key.Id, active.Key.Id, StringComparison.Ordinal))
            return "the active signer";

        if (!includedThumbprints.Contains(entry.Key.Id))
        {
            return "NOT included in the JWKS - its retirement window has fully elapsed; safe to remove " +
                "from configuration";
        }

        if (entry.ActivatesAt > now)
            return $"included in the JWKS, not yet active (activates at {entry.ActivatesAt:O})";

        return "included in the JWKS, retired but still within its retirement window (until " +
            $"{entry.RetiredAt!.Value + retirementWindow:O})";
    }

    private void WarnIfActiveCertificateExpiringSoon(RotationEntry active, DateTimeOffset now)
    {
        // Called from HasKeySetChangedAsync on every ask cycle once a previous load exists — not
        // only LogCertificateStatuses's more limited "on every LoadKeysAsync call" cadence — plus
        // once directly from LoadKeysAsync for the cold-start case, before any ask has ever run.
        // Whether the active certificate is within 30 days of expiry is genuinely time-varying — a
        // long-running process can cross into that window mid-lifetime — and an unchanged refresh
        // cycle that skips LoadKeysAsync entirely must not also skip this check, or the warning
        // could go unraised for the rest of the process's life. Repeats at most once per
        // KeySourceRefreshInterval (the ask cadence) for as long as the condition holds, never
        // twice for the same cycle — see the two call sites' own remarks for how that is enforced.
        if (active.Key.ExpiresAt - now <= TimeSpan.FromDays(30))
        {
            _logger.LogWarning(
                "ZeeKayDa.Auth: the active Windows Certificate Store signing certificate '{Thumbprint}' " +
                "expires at {NotAfter:O}, within 30 days. Rotate in a new certificate (via AddCertificate) " +
                "before it expires.",
                active.Key.Id, active.Key.ExpiresAt);
        }
    }

    private sealed class CertificateCollectionLease : IDisposable
    {
        private readonly Dictionary<string, X509Certificate2>.ValueCollection _certificates;

        public CertificateCollectionLease(Dictionary<string, X509Certificate2>.ValueCollection certificates)
        {
            _certificates = certificates;
        }

        public void Dispose()
        {
            foreach (var certificate in _certificates)
                certificate.Dispose();
        }
    }
}
