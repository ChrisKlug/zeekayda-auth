using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using ZeeKayDa.Auth.Logging;
using ZeeKayDa.Auth.Tokens;

namespace ZeeKayDa.Auth.FileSystem;

/// <summary>
/// Shared <see cref="IJwtSigningService"/> logic for both the PEM and PFX file-based signing
/// providers: loading every registered file, deriving the rotation timeline from each certificate's
/// own <c>NotBefore</c>/<c>NotAfter</c>, per-file logging, and disposal discipline. Subclasses
/// provide only the format-specific pieces — which paths are registered, and how to turn one path
/// into an <see cref="X509Certificate2"/>.
/// </summary>
/// <remarks>
/// <para>
/// <see cref="LoadKeysAsync"/> is adapted from
/// <c>WindowsCertificateStoreSigningJwtSigningService.LoadKeysAsync</c>, with <c>RotationKey.Id</c>
/// being a file path rather than a certificate-store thumbprint. Only the active file's private key
/// is ever held; every other included file (published-but-not-yet-active, or still within its
/// retirement window) gets only a public-only handle, since it is never used to sign — only exposed
/// via the JWKS (ADR 0011 §3.3(c)).
/// </para>
/// <para>
/// This class does not override <see cref="JwtSigningService{TOptions}.SignInputAsync"/> — per ADR
/// 0011 Amendment 2(a), this provider signs with local key handles exactly like the development
/// provider and the Windows Certificate Store provider, so the base class's default local-crypto
/// implementation is exactly what it needs.
/// </para>
/// <para>
/// <c>kid</c> is the RFC 7638 JWK thumbprint of each certificate's public key (via the shared
/// <see cref="SigningKeyDescriptorFactory"/>), never the file path — a <c>kid</c> is always public,
/// so using the operator-supplied path directly could leak local filesystem layout.
/// </para>
/// </remarks>
/// <typeparam name="TOptions">The format-specific options type (PEM or PFX).</typeparam>
internal abstract class FileSigningJwtSigningService<TOptions> : JwtSigningService<TOptions>
    where TOptions : FileSigningOptions
{
    private readonly IOptions<TOptions> _options;
    private readonly TimeProvider _timeProvider;
    private readonly ISigningKeyRetirementWindowProvider _retirementWindowProvider;
    private readonly ISanitizingLogger<FileSigningJwtSigningService<TOptions>> _logger;

    // Every filesystem path backing every registered entry (each entry's Id plus its
    // AdditionalPaths — see RegisteredSigningFile's remarks), mapped to that file's last-write
    // timestamp (a cheap stat, never a content read) as of the last successful LoadKeysAsync call.
    // Flattened across entries (rather than nested per entry) so a change to *either* an entry's Id
    // path or one of its AdditionalPaths (e.g. cert-manager rotating a separately-registered
    // private-key file while the certificate file's mtime is untouched, or vice versa) is detected
    // as "this entry changed" by the same membership/timestamp comparison HasKeySetChangedAsync
    // already does per path. Null means "no successful LoadKeysAsync has run yet" — a state
    // HasKeySetChangedAsync never actually observes, since the base class only calls it once a
    // previous SigningKeySet already exists (ADR 0011 §3.2), which itself implies at least one
    // successful LoadKeysAsync already populated this field.
    private IReadOnlyDictionary<string, DateTimeOffset>? _previouslyLoadedFileTimestamps;

    // Per registered entry (keyed by RegisteredSigningFile.Id), the certificate's own
    // NotBefore/NotAfter, as of the last successful LoadKeysAsync call. Lets HasKeySetChangedAsync
    // recompute the rotation timeline without re-reading or re-parsing anything.
    private IReadOnlyDictionary<string, (DateTimeOffset NotBefore, DateTimeOffset NotAfter)>? _previouslyLoadedEntryValidity;

    // The included path set (by path and whether the entry was active) as of the last successful
    // LoadKeysAsync call. IsActive has to be part of the comparison, not just membership — see
    // SigningKeyRotation.ToChangeDetectionSet's remarks.
    private IReadOnlySet<(string Id, bool IsActive)>? _previouslyIncludedPaths;

    /// <summary>
    /// Initialises the shared base class.
    /// </summary>
    protected FileSigningJwtSigningService(
        IOptions<TOptions> options,
        TimeProvider timeProvider,
        ISigningKeyRetirementWindowProvider retirementWindowProvider,
        ISanitizingLogger<FileSigningJwtSigningService<TOptions>> logger)
        : base(options, timeProvider)
    {
        ArgumentNullException.ThrowIfNull(options);
        ArgumentNullException.ThrowIfNull(timeProvider);
        ArgumentNullException.ThrowIfNull(retirementWindowProvider);
        ArgumentNullException.ThrowIfNull(logger);

        _options = options;
        _timeProvider = timeProvider;
        _retirementWindowProvider = retirementWindowProvider;
        _logger = logger;
    }

    /// <summary>
    /// Returns every entry registered on <paramref name="options"/> — the primary entry plus any
    /// registered via <c>options.AddFile(...)</c>, in registration order.
    /// </summary>
    protected abstract IReadOnlyList<RegisteredSigningFile> GetRegisteredFiles(TOptions options);

    /// <summary>
    /// Loads and parses the certificate for <paramref name="file"/>. Implementations are responsible
    /// for reading every path in <see cref="RegisteredSigningFile.AllPaths"/> via
    /// <c>FileSigningKeyReader</c> (never any other I/O path, so every file gets the same
    /// permission/symlink validation) and wrapping format-specific parse failures in
    /// <see cref="ZeeKayDaConfigurationException"/>.
    /// </summary>
    protected abstract ValueTask<X509Certificate2> LoadCertificateAsync(RegisteredSigningFile file, TOptions options, CancellationToken cancellationToken);

    /// <summary>
    /// Returns the configured JWS algorithm — <c>PemFileSigningOptions.Algorithm</c> or
    /// <c>PfxFileSigningOptions.Algorithm</c>. The base class cannot read this itself: per ADR 0011
    /// §3.4/§3.5, <see cref="FileSigningOptions"/> carries only <c>KeyRotationCheckInterval</c> and
    /// <c>AssumedJwksPropagationDelay</c>, so <c>Algorithm</c> exists only on the derived,
    /// format-specific options types.
    /// </summary>
    protected abstract SigningAlgorithm GetAlgorithm(TOptions options);

    /// <summary>
    /// Builds the public key descriptor for a loaded file, validating that the configured algorithm
    /// matches the certificate's actual key type, via the shared
    /// <see cref="SigningKeyDescriptorFactory.BuildDescriptor"/>. The mismatch message names
    /// <typeparamref name="TOptions"/> by its runtime type name, so both
    /// <c>PemFileSigningOptions</c>/<c>PfxFileSigningOptions</c> get a correctly-named message from
    /// this one shared implementation rather than each duplicating near-identical wording.
    /// </summary>
    private SigningKeyDescriptor BuildKeyDescriptor(
        AsymmetricAlgorithm publicKey, SigningKeyType keyType, string path, TOptions options)
    {
        var algorithm = GetAlgorithm(options);
        var optionsTypeName = typeof(TOptions).Name;

        return SigningKeyDescriptorFactory.BuildDescriptor(
            publicKey,
            keyType,
            algorithm,
            "signing.file_signing.algorithm_key_type_mismatch",
            mismatchedKeyType => mismatchedKeyType == SigningKeyType.Rsa
                ? $"{optionsTypeName}.Algorithm is {algorithm}, but the certificate at '{path}' is an " +
                  "RSA certificate. Use an RSA algorithm (RS256, RS384, RS512, PS256, PS384, or PS512)."
                : $"{optionsTypeName}.Algorithm is {algorithm}, but the certificate at '{path}' is an " +
                  "EC certificate. Use an EC algorithm (ES256, ES384, or ES512).");
    }

    /// <inheritdoc/>
    protected override async ValueTask<SigningKeySet> LoadKeysAsync(CancellationToken cancellationToken)
    {
        var options = _options.Value;
        var files = GetRegisteredFiles(options);

        // Load every registered entry up front — the timeline needs every registered entry's
        // NotBefore/NotAfter, not just the ones that end up "included", to correctly compute
        // retirement anchors.
        var certificatesByPath = new Dictionary<string, X509Certificate2>(files.Count, StringComparer.Ordinal);
        var entryValidity = new Dictionary<string, (DateTimeOffset NotBefore, DateTimeOffset NotAfter)>(files.Count, StringComparer.Ordinal);
        var pathTimestamps = new Dictionary<string, DateTimeOffset>(StringComparer.Ordinal);
        try
        {
            foreach (var file in files)
            {
                // Stat *before* reading/parsing the file's contents, not after: if a write races this
                // load, this ordering fails toward "the stat is now stale, so the very next
                // HasKeySetChangedAsync ask sees a further mtime change and reloads again" (an extra,
                // harmless reload) rather than "the content read is stale relative to what the mtime
                // implies" (a missed reload that could persist indefinitely) — see this method's
                // remarks and HasKeySetChangedAsync's for the full failure mode this ordering avoids.
                // Every path backing this entry (the identity path and any AdditionalPaths, e.g. a
                // separately-registered private-key file) is stat'd, so a change to either is
                // detected as this entry changing.
                foreach (var path in file.AllPaths)
                    pathTimestamps[path] = new DateTimeOffset(File.GetLastWriteTimeUtc(path), TimeSpan.Zero);

                var certificate = await LoadCertificateAsync(file, options, cancellationToken).ConfigureAwait(false);
                certificatesByPath[file.Id] = certificate;
                entryValidity[file.Id] = (
                    new DateTimeOffset(certificate.NotBefore),
                    new DateTimeOffset(certificate.NotAfter));
            }

            var now = _timeProvider.GetUtcNow();

            var rotationKeys = entryValidity
                .Select(kvp => new RotationKey(kvp.Key, kvp.Value.NotBefore, kvp.Value.NotAfter))
                .ToList();

            var timeline = SigningKeyRotation.BuildActivationTimeline(rotationKeys);
            var active = SigningKeyRotation.SelectActiveKey(timeline, now)
                ?? throw new ZeeKayDaConfigurationException(new ZeeKayDaConfigurationFailure(
                    "signing.file_signing.no_active_certificate",
                    "No registered signing key file is currently eligible to sign. Verify at least " +
                    "one registered file's certificate NotBefore has arrived and its NotAfter has not " +
                    "yet passed."));

            var retirementWindow = _retirementWindowProvider.GetRetirementWindow();
            var included = SigningKeyRotation.SelectIncludedKeys(timeline, active, now, retirementWindow);

            var assumedJwksPropagationDelay = options.AssumedJwksPropagationDelay ?? options.KeyRotationCheckInterval;
            LogCertificateStatuses(timeline, active, included, now, assumedJwksPropagationDelay, retirementWindow, certificatesByPath);
            WarnIfActiveCertificateExpiringSoon(active, now);

            var keyPairs = new List<SigningKeyPair>(included.Count);
            try
            {
                foreach (var path in included.Select(entry => entry.Key.Id))
                {
                    var certificate = certificatesByPath[path];
                    var isActive = string.Equals(path, active.Key.Id, StringComparison.Ordinal);

                    var (publicKey, keyType) = FileSigningKeyExtractor.ExtractPublicKey(certificate, path);
                    SigningKeyDescriptor descriptor;
                    try
                    {
                        descriptor = BuildKeyDescriptor(publicKey, keyType, path, options);
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
                            (signingKey, _) = FileSigningKeyExtractor.ExtractPrivateKey(certificate, path);
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
                // Key material for any file already processed before the failure would otherwise
                // leak live handles.
                foreach (var pair in keyPairs)
                    pair.PrivateKey.Dispose();
                throw;
            }

            // Recorded only now — after the SigningKeySet has actually been built successfully —
            // never from HasKeySetChangedAsync's ask itself. See that method's remarks and ADR 0011
            // §3.5's "change-detection baseline is captured only on a successful load" rule.
            _previouslyLoadedFileTimestamps = pathTimestamps;
            _previouslyLoadedEntryValidity = entryValidity;
            _previouslyIncludedPaths = SigningKeyRotation.ToChangeDetectionSet(included);

            // `included` (and therefore `keyPairs`, built from it above) is active-first, so
            // splitting off the first entry as the named active key is safe.
            return new SigningKeySet(keyPairs[0], keyPairs.Skip(1));
        }
        finally
        {
            // GetRSAPrivateKey()/GetECDsaPrivateKey()/GetRSAPublicKey()/GetECDsaPublicKey() return
            // handle objects that remain valid after the parent X509Certificate2 is disposed
            // (.NET Core 3.0+) — safe to dispose every loaded certificate here, after all needed
            // handles have already been extracted above. Dictionary<TKey,TValue> is not itself
            // IDisposable — a "using var" on the dictionary (as a prior automated code-review
            // suggestion proposed) does not compile and, even if it somehow did, would not dispose
            // the certificate *values* it holds; each certificate must be disposed explicitly.
            DisposeCertificates(certificatesByPath.Values);
        }
    }

    /// <inheritdoc/>
    /// <remarks>
    /// <para>
    /// Never re-reads or re-parses a registered file. Three distinct triggers are checked, all
    /// against the metadata recorded at the last successful <see cref="LoadKeysAsync"/> call
    /// (<see cref="_previouslyLoadedFileTimestamps"/> / <see cref="_previouslyLoadedEntryValidity"/> /
    /// <see cref="_previouslyIncludedPaths"/>), never against whatever a previous call to this method
    /// itself computed — see ADR 0011 §3.5's "change detection baseline is captured only on a
    /// successful load" rule.
    /// </para>
    /// <para>
    /// First, whether an entry (by <see cref="RegisteredSigningFile.Id"/>) was added or removed from
    /// <see cref="GetRegisteredFiles"/> since the last load — checked before touching the filesystem
    /// at all. Second, whether the flattened set of every path backing every entry (each entry's
    /// <see cref="RegisteredSigningFile.Id"/> plus its <see cref="RegisteredSigningFile.AdditionalPaths"/>
    /// — for example a PEM entry's separately-registered private-key file) was added to or removed
    /// from — this independently catches a companion path being added to or removed from an
    /// otherwise-unchanged entry. Third, for every path still registered, whether its contents
    /// changed, via the cheap <see cref="File.GetLastWriteTimeUtc(string)"/> stat call (never a
    /// content read) compared against the timestamp recorded at the last load — checked for
    /// <em>every</em> path in an entry's <see cref="RegisteredSigningFile.AllPaths"/>, so either the
    /// entry's identity path or a companion path changing is treated as the entry having changed
    /// (e.g. cert-manager rotating a separately-registered private-key file while the certificate
    /// file's mtime is untouched, or vice versa). <see cref="LoadKeysAsync"/> stats each file
    /// immediately before reading and parsing its contents (not afterward), so the recorded timestamp
    /// always precedes the content it is meant to represent: a write that races a load can only make
    /// the recorded timestamp stale relative to a later write, which this method (or the next one)
    /// will then correctly detect as a further change — it can never make the timestamp understate a
    /// change that already happened, which would otherwise cause this method to report "unchanged"
    /// indefinitely. A missing file's <see cref="File.GetLastWriteTimeUtc(string)"/> returns a
    /// sentinel value rather than throwing, which will not match the recorded real timestamp and so
    /// correctly reports a change (outright removal is also independently caught by the path-set
    /// check above). Fourth, whether elapsed time alone moved a certificate in or out of its
    /// retirement window, even with zero file changes —
    /// <see cref="SigningKeyRotation.SelectActiveKey"/>/<see cref="SigningKeyRotation.SelectIncludedKeys"/>
    /// are functions of <c>now</c>, so this recomputes the rotation timeline from the recorded
    /// <c>NotBefore</c>/<c>NotAfter</c> metadata (safe to reuse without re-reading the file: it cannot
    /// change without the mtime also changing, which the third check above already covers) against
    /// the current time, and compares the resulting active entry and included entry set — via
    /// <see cref="SigningKeyRotation.ToChangeDetectionSet"/>, exactly mirroring the Windows
    /// Certificate Store and Key Vault providers' comparison shape — against what was recorded at
    /// the last load. Comparing membership alone would miss the moment a rotation actually completes
    /// (see that method's remarks for the full two-poll failure mode).
    /// </para>
    /// <para>
    /// If no registered file is currently eligible to sign (every one has expired since the last
    /// load), this method reports a change rather than failing itself — the subsequent
    /// <see cref="LoadKeysAsync"/> call is what fails closed with its usual, actionable
    /// <c>signing.file_signing.no_active_certificate</c> error; this method's own contract is only
    /// ever "did the trusted set change," never "is the configuration currently valid."
    /// </para>
    /// </remarks>
    protected override ValueTask<bool> HasKeySetChangedAsync(CancellationToken cancellationToken)
    {
        var currentFiles = GetRegisteredFiles(_options.Value);

        // The base class only calls this once a previous SigningKeySet already exists (ADR 0011
        // §3.2), which itself implies at least one successful LoadKeysAsync already ran and
        // populated these fields — the null-forgiving operators below rely on that guarantee rather
        // than re-checking it.
        if (currentFiles.Count != _previouslyLoadedEntryValidity!.Count ||
            currentFiles.Any(file => !_previouslyLoadedEntryValidity.ContainsKey(file.Id)))
        {
            return new ValueTask<bool>(true);
        }

        var currentPaths = currentFiles.SelectMany(file => file.AllPaths).ToList();
        if (currentPaths.Count != _previouslyLoadedFileTimestamps!.Count ||
            currentPaths.Any(path => !_previouslyLoadedFileTimestamps.ContainsKey(path)))
        {
            return new ValueTask<bool>(true);
        }

        foreach (var path in currentPaths)
        {
            var currentLastWriteTimeUtc = new DateTimeOffset(File.GetLastWriteTimeUtc(path), TimeSpan.Zero);
            if (currentLastWriteTimeUtc != _previouslyLoadedFileTimestamps[path])
                return new ValueTask<bool>(true);
        }

        var rotationKeys = currentFiles
            .Select(file =>
            {
                var validity = _previouslyLoadedEntryValidity[file.Id];
                return new RotationKey(file.Id, validity.NotBefore, validity.NotAfter);
            })
            .ToList();

        var timeline = SigningKeyRotation.BuildActivationTimeline(rotationKeys);
        var now = _timeProvider.GetUtcNow();

        var active = SigningKeyRotation.SelectActiveKey(timeline, now);
        if (active is null)
            return new ValueTask<bool>(true);

        var retirementWindow = _retirementWindowProvider.GetRetirementWindow();
        var included = SigningKeyRotation.SelectIncludedKeys(timeline, active.Value, now, retirementWindow);
        var currentIncludedPaths = SigningKeyRotation.ToChangeDetectionSet(included);

        return new ValueTask<bool>(!currentIncludedPaths.SetEquals(_previouslyIncludedPaths!));
    }

    private static void DisposeCertificates(IEnumerable<X509Certificate2> certificates)
    {
        foreach (var certificate in certificates)
            certificate.Dispose();
    }

    private void LogCertificateStatuses(
        IReadOnlyList<RotationEntry> timeline,
        RotationEntry active,
        IReadOnlyList<RotationEntry> included,
        DateTimeOffset now, TimeSpan assumedJwksPropagationDelay, TimeSpan retirementWindow,
        IReadOnlyDictionary<string, X509Certificate2> certificatesByPath)
    {
        // Re-evaluated on every LoadKeysAsync call (at most once per KeyRotationCheckInterval) rather than
        // only at first load, since active/included/excluded status is a function of `now` and
        // genuinely changes over the lifetime of a long-running process as a rotation progresses.
        // Every registered file is logged, not just the currently-included ones, so an operator can
        // see a file that is configured but has fallen out of the trusted set entirely (its
        // retirement window has elapsed) and can now safely be removed.
        var includedPaths = new HashSet<string>(included.Select(e => e.Key.Id), StringComparer.Ordinal);

        foreach (var entry in timeline)
        {
            var certificate = certificatesByPath[entry.Key.Id];
            var (keyType, keySizeBits) = FileSigningKeyExtractor.DescribeKeyForLogging(certificate);
            var status = DescribeStatus(entry, active, includedPaths, now, retirementWindow);

            // Path, key type, and key size only — never key material or a PFX password (issue #291's
            // explicit requirement).
            _logger.LogInformation(
                "ZeeKayDa.Auth: file-based signing key '{Path}' ({KeyType}, {KeySizeBits}-bit, " +
                "expires {NotAfter:O}) is {Status}.",
                entry.Key.Id, keyType, keySizeBits, entry.Key.ExpiresAt, status);
        }

        if (SigningKeyRotation.HasTooSoonPendingActivation(timeline, active, now, assumedJwksPropagationDelay, out var soonestPending))
        {
            _logger.LogWarning(
                "ZeeKayDa.Auth: signing key file '{Path}' activates at {ActivatesAt:O}, which is less " +
                "than AssumedJwksPropagationDelay ({AssumedJwksPropagationDelay}) away from now. A relying party polling the " +
                "JWKS at AssumedJwksPropagationDelay cadence may not have observed this key's public material " +
                "before it starts signing. Set this certificate's NotBefore at least AssumedJwksPropagationDelay " +
                "in the future next time (see ADR 0011 §3.5 / issue #282).",
                soonestPending!.Value.Key.Id, soonestPending.Value.ActivatesAt, assumedJwksPropagationDelay);
        }
    }

    private static string DescribeStatus(
        RotationEntry entry,
        RotationEntry active,
        HashSet<string> includedPaths, DateTimeOffset now, TimeSpan retirementWindow)
    {
        if (string.Equals(entry.Key.Id, active.Key.Id, StringComparison.Ordinal))
            return "the active signer";

        if (!includedPaths.Contains(entry.Key.Id))
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
        // Re-evaluated on every LoadKeysAsync call, exactly like LogCertificateStatuses above: this
        // condition is genuinely time-varying for a long-running process. Repeats at most once per
        // KeyRotationCheckInterval for as long as the condition holds.
        if (active.Key.ExpiresAt - now <= TimeSpan.FromDays(30))
        {
            _logger.LogWarning(
                "ZeeKayDa.Auth: the active file-based signing key '{Path}' expires at {NotAfter:O}, " +
                "within 30 days. Rotate in a new file (via options.AddFile) before it expires.",
                active.Key.Id, active.Key.ExpiresAt);
        }
    }
}
