using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using ZeeKayDa.Auth.Logging;
using ZeeKayDa.Auth.Tokens;

namespace ZeeKayDa.Auth.FileSystem;

/// <summary>
/// <see cref="IJwtSigningService"/> that loads one or more combined cert+key PEM files from the
/// filesystem and signs locally, in process, using each certificate's private-key handle.
/// </summary>
/// <remarks>
/// <para>
/// ADR 0015 Tier A (<see cref="KeySetOptions"/>, issue #422): the complete set of registered PEM
/// files is fixed at configuration time, so <see cref="ListKeysAsync"/> runs exactly once, ever, for
/// the lifetime of this service instance. Only the wall clock crossing each file's certificate
/// <c>NotBefore</c>/<c>NotAfter</c> — mapped onto each returned <see cref="KeyListing"/>'s
/// <see cref="KeyListing.ActivateAt"/>/<see cref="KeyListing.ExpiresAt"/> — drives which registered
/// file is the active signer; the base class recomputes that selection lazily on every call from the
/// one-time snapshot, so multi-file rotation (issue #282) still switches the active signer over time
/// with zero further filesystem I/O. Picking up a rotated-in or replaced file otherwise requires a
/// restart (ADR 0015 §10).
/// </para>
/// <para>
/// Least-privilege key loading (ADR 0015 §2/§5): <see cref="ListKeysAsync"/> extracts only each
/// file's public key and disposes the certificate immediately afterward, never retaining a private
/// handle. <see cref="CreateSignerAsync"/> re-reads and re-parses only the single file the base class
/// has selected as active, and only when that selection changes — every other registered file's
/// private key material is never loaded a second time.
/// </para>
/// <para>
/// <c>kid</c> is the RFC 7638 JWK thumbprint of each certificate's public key, derived by the base
/// class from each <see cref="KeyListing.PublicKey"/> — never the file path, which is only this
/// provider's own internal <see cref="KeyId"/> (ADR 0015 §2).
/// </para>
/// </remarks>
internal sealed class PemFileSigningJwtSigningService : JwtSigningService<PemFileSigningOptions>
{
    private readonly IOptions<PemFileSigningOptions> _options;
    private readonly FileSigningKeyReader _reader;
    private readonly TimeProvider _timeProvider;
    private readonly ISigningKeyRetirementWindowProvider _retirementWindowProvider;
    private readonly ISanitizingLogger<JwtSigningService<PemFileSigningOptions>> _logger;

    public PemFileSigningJwtSigningService(
        IOptions<PemFileSigningOptions> options,
        TimeProvider timeProvider,
        FileSigningKeyReader reader,
        ISigningKeyRetirementWindowProvider retirementWindowProvider,
        ISanitizingLogger<JwtSigningService<PemFileSigningOptions>> logger)
        : base(options, timeProvider, retirementWindowProvider, logger)
    {
        ArgumentNullException.ThrowIfNull(reader);

        _options = options;
        _reader = reader;
        _timeProvider = timeProvider;
        _retirementWindowProvider = retirementWindowProvider;
        _logger = logger;
    }

    /// <inheritdoc/>
    protected override async ValueTask<IReadOnlyList<KeyListing>> ListKeysAsync(CancellationToken cancellationToken)
    {
        var options = _options.Value;
        var files = GetRegisteredFiles(options);

        var listings = new List<KeyListing>(files.Count);
        var rotationKeys = new List<RotationKey>(files.Count);
        var keyDescriptionsById = new Dictionary<string, (string KeyType, int KeySizeBits)>(files.Count, StringComparer.Ordinal);

        foreach (var file in files)
        {
            using var certificate = await LoadCertificateAsync(file, cancellationToken).ConfigureAwait(false);

            var (publicKey, keyType) = FileSigningKeyExtractor.ExtractPublicKey(certificate, file.Id);
            PublicKeyParameters publicKeyParameters;
            try
            {
                publicKeyParameters = BuildValidatedPublicKey(publicKey, keyType, file.Id, options);
            }
            finally
            {
                publicKey.Dispose();
            }

            var activateAt = new DateTimeOffset(certificate.NotBefore);
            var expiresAt = new DateTimeOffset(certificate.NotAfter);

            listings.Add(new KeyListing(new KeyId(file.Id), options.Algorithm, publicKeyParameters, activateAt, expiresAt));
            rotationKeys.Add(new RotationKey(file.Id, activateAt, expiresAt));
            keyDescriptionsById[file.Id] = FileSigningKeyExtractor.DescribeKeyForLogging(certificate);
        }

        LogFileStatusesAndWarnings(rotationKeys, keyDescriptionsById, options);

        return listings;
    }

    /// <inheritdoc/>
    protected override async ValueTask<ISigner> CreateSignerAsync(KeyId id, CancellationToken cancellationToken)
    {
        var options = _options.Value;
        var files = GetRegisteredFiles(options);
        var file = FindRegisteredFile(files, id.Value);

        using var certificate = await LoadCertificateAsync(file, cancellationToken).ConfigureAwait(false);
        var (privateKey, _) = FileSigningKeyExtractor.ExtractPrivateKey(certificate, file.Id);

        return new LocalSigner(options.Algorithm, privateKey);
    }

    private static RegisteredSigningFile FindRegisteredFile(IReadOnlyList<RegisteredSigningFile> files, string id)
    {
        foreach (var file in files)
        {
            if (string.Equals(file.Id, id, StringComparison.Ordinal))
                return file;
        }

        throw new InvalidOperationException(
            $"{nameof(CreateSignerAsync)} was called for key '{id}', which is no longer a registered " +
            $"PEM file. {nameof(ListKeysAsync)} runs exactly once for this ADR 0015 Tier A provider, so " +
            "its registered files must not change after startup.");
    }

    private static IReadOnlyList<RegisteredSigningFile> GetRegisteredFiles(PemFileSigningOptions options)
    {
        var files = new List<RegisteredSigningFile>(1 + options.AdditionalFiles.Count)
        {
            ToRegisteredFile(options.Path, options.KeyPath),
        };
        files.AddRange(options.AdditionalFiles.Select(file => ToRegisteredFile(file.Path, file.KeyPath)));
        return files;
    }

    private static RegisteredSigningFile ToRegisteredFile(string path, string? keyPath) =>
        new(path, keyPath is null ? null : [keyPath]);

    private async ValueTask<X509Certificate2> LoadCertificateAsync(
        RegisteredSigningFile file, CancellationToken cancellationToken)
    {
        // Deliberately still reads both the certificate and key text through
        // FileSigningKeyReader.ReadPemTextAsync (one validated, single-open read per file) and calls
        // X509Certificate2.CreateFromPem(certPem, keyPem), rather than X509Certificate2.CreateFromPemFile
        // (which takes a path and performs its own, unvalidated file I/O). CreateFromPemFile would
        // bypass FileSigningKeyReader's permission/symlink validation and TOCTOU-closing discipline
        // (see that type's remarks) for both the combined and split cases — a regression this
        // provider's whole security model exists to prevent. CreateFromPem accepts the certificate
        // and key as independent PEM text, so it supports the split-file case exactly as well as
        // CreateFromPemFile would, without reopening either file outside the validated read path.
        var keyPath = file.AdditionalPaths.Count > 0 ? file.AdditionalPaths[0] : null;

        var certPem = await _reader.ReadPemTextAsync(file.Id, cancellationToken).ConfigureAwait(false);
        // With no separate key path, the combined file carries both PEM blocks, so the same text is
        // passed for both the certificate and the key source — byte-for-byte the same call this
        // provider has always made.
        var keyPem = keyPath is null
            ? certPem
            : await _reader.ReadPemTextAsync(keyPath, cancellationToken).ConfigureAwait(false);

        try
        {
            return X509Certificate2.CreateFromPem(certPem, keyPem);
        }
        catch (Exception ex) when (ex is CryptographicException or ArgumentException or FormatException)
        {
            var description = keyPath is null
                ? $"'{file.Id}'"
                : $"certificate '{file.Id}' / private key '{keyPath}'";

            throw new ZeeKayDaConfigurationException(new ZeeKayDaConfigurationFailure(
                "signing.file_signing.invalid_pem",
                $"The file(s) at {description} do not contain a valid PEM-encoded certificate and " +
                $"private key: {ex.Message}"));
        }
    }

    /// <summary>
    /// Validates that <see cref="PemFileSigningOptions.Algorithm"/>'s family matches the loaded
    /// certificate's actual key type, and returns the corresponding public-only key parameters —
    /// reusing the descriptor's already-exported parameters rather than exporting them a second time.
    /// </summary>
    private static PublicKeyParameters BuildValidatedPublicKey(
        AsymmetricAlgorithm publicKey, SigningKeyType keyType, string path, PemFileSigningOptions options)
    {
        var algorithm = options.Algorithm;

        var descriptor = SigningKeyDescriptorFactory.BuildDescriptor(
            publicKey,
            keyType,
            algorithm,
            "signing.file_signing.algorithm_key_type_mismatch",
            mismatchedKeyType => mismatchedKeyType == SigningKeyType.Rsa
                ? $"PemFileSigningOptions.Algorithm is {algorithm}, but the certificate at '{path}' is an " +
                  "RSA certificate. Use an RSA algorithm (RS256, RS384, RS512, PS256, PS384, or PS512)."
                : $"PemFileSigningOptions.Algorithm is {algorithm}, but the certificate at '{path}' is an " +
                  "EC certificate. Use an EC algorithm (ES256, ES384, or ES512).");

        return descriptor.KeyType == SigningKeyType.Rsa
            ? PublicKeyParameters.FromRsa(descriptor.RsaPublicParameters!.Value)
            : PublicKeyParameters.FromEc(descriptor.EcPublicParameters!.Value);
    }

    /// <summary>
    /// Logs a per-file status line for every registered file, and the two startup-only advisory
    /// warnings: a rotated-in file whose activation is scheduled too soon relative to
    /// <see cref="KeySetOptions.PublicationLead"/> (ADR 0015 §1), and the active file's certificate
    /// approaching expiry.
    /// </summary>
    /// <remarks>
    /// Runs exactly once, inside the single <see cref="ListKeysAsync"/> call this ADR 0015 Tier A
    /// provider ever makes — unlike the ADR 0011 predecessor, there is no periodic reload to
    /// re-evaluate these against as time passes.
    /// </remarks>
    private void LogFileStatusesAndWarnings(
        IReadOnlyList<RotationKey> rotationKeys,
        IReadOnlyDictionary<string, (string KeyType, int KeySizeBits)> keyDescriptionsById,
        PemFileSigningOptions options)
    {
        var timeline = SigningKeyRotation.BuildActivationTimeline(rotationKeys);
        var now = _timeProvider.GetUtcNow();
        var active = SigningKeyRotation.SelectActiveKey(timeline, now);

        if (active is null)
        {
            // No registered file is currently eligible to sign. The base class fails closed with its
            // own ZeeKayDaConfigurationException on the very next GetSigningKeysAsync/SignAsync call
            // (ADR 0015 Security Considerations item 6) — nothing further to log here.
            return;
        }

        var retirementWindow = _retirementWindowProvider.GetRetirementWindow();
        var included = SigningKeyRotation.SelectIncludedKeys(timeline, active.Value, now, retirementWindow);
        var includedPaths = new HashSet<string>(included.Select(entry => entry.Key.Id), StringComparer.Ordinal);

        // Every registered file is logged, not just the currently-included ones, so an operator can
        // see a file that is configured but has fallen out of the trusted set entirely (its
        // retirement window has elapsed) and can now safely be removed.
        foreach (var entry in timeline)
        {
            var (keyType, keySizeBits) = keyDescriptionsById[entry.Key.Id];
            var status = DescribeStatus(entry, active.Value, includedPaths, now, retirementWindow);

            // Path, key type, and key size only — never key material (issue #291's explicit requirement).
            _logger.LogInformation(
                "ZeeKayDa.Auth: file-based signing key '{Path}' ({KeyType}, {KeySizeBits}-bit, " +
                "expires {NotAfter:O}) is {Status}.",
                entry.Key.Id, keyType, keySizeBits, entry.Key.ExpiresAt, status);
        }

        if (SigningKeyRotation.HasTooSoonPendingActivation(timeline, active.Value, now, options.PublicationLead, out var soonestPending))
        {
            _logger.LogWarning(
                "ZeeKayDa.Auth: signing key file '{Path}' activates at {ActivatesAt:O}, which is less " +
                "than PublicationLead ({PublicationLead}) away from now. A relying party polling the " +
                "JWKS may not have observed this key's public material before it starts signing. Set " +
                "this certificate's NotBefore at least PublicationLead in the future next time (ADR 0015 §1).",
                soonestPending!.Value.Key.Id, soonestPending.Value.ActivatesAt, options.PublicationLead);
        }

        WarnIfActiveCertificateExpiringSoon(active.Value, now);
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
        if (active.Key.ExpiresAt - now <= TimeSpan.FromDays(30))
        {
            _logger.LogWarning(
                "ZeeKayDa.Auth: the active file-based signing key '{Path}' expires at {NotAfter:O}, " +
                "within 30 days. Rotate in a new file (via options.AddFile) before it expires.",
                active.Key.Id, active.Key.ExpiresAt);
        }
    }
}
