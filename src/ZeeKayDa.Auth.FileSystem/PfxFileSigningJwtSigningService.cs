using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Microsoft.Extensions.Options;
using ZeeKayDa.Auth.Logging;
using ZeeKayDa.Auth.Tokens;

namespace ZeeKayDa.Auth.FileSystem;

/// <summary>
/// <see cref="IJwtSigningService"/> that loads one or more PFX/PKCS#12 bundles from the filesystem
/// and signs locally, in process, using each certificate's private-key handle.
/// </summary>
/// <remarks>
/// <para>
/// ADR 0015 Tier A (<see cref="KeySetOptions"/>, issue #423): the complete set of registered PFX
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
/// <strong>Least-privilege loading for a bundled format (ADR 0015 §2/§5).</strong> PFX is a bundled
/// format: reading it yields the whole certificate, private half included — there is no way to open
/// the bundle for its public certificate alone. This provider therefore reads each bundle transiently
/// in <see cref="ListKeysAsync"/>, extracts and retains <em>only</em> the public
/// <see cref="PublicKeyParameters"/> in the returned <see cref="KeyListing"/>, and disposes the
/// certificate (releasing its private-key handle) immediately — no private material for any file, not
/// even the active one, is retained past that transient read. When the base class needs to sign, it
/// calls <see cref="CreateSignerAsync"/>, which re-reads and re-parses <em>only</em> the single file
/// currently selected as active; every other registered file's private key is never loaded a second
/// time. This is the concrete proof-point for ADR 0015 §2/§5's "provider obligation, not structural
/// guarantee" caveat: the base structurally requests private material only for the active key, but
/// keeping non-active private material out of the long-lived snapshot is this provider's own doing.
/// </para>
/// <para>
/// <c>kid</c> is the RFC 7638 JWK thumbprint of each certificate's public key, derived by the base
/// class from each <see cref="KeyListing.PublicKey"/> — never the file path, which is only this
/// provider's own internal <see cref="KeyId"/> (ADR 0015 §2), since a <c>kid</c> is always public and
/// the path could leak local filesystem layout.
/// </para>
/// </remarks>
internal sealed class PfxFileSigningJwtSigningService : JwtSigningService<PfxFileSigningOptions>
{
    private readonly IOptions<PfxFileSigningOptions> _options;
    private readonly FileSigningKeyReader _reader;

    // Populated by ListKeysAsync (Tier A: runs exactly once) so DescribeKeyMetadata can supply it
    // later, when the base class logs each key's status.
    private readonly Dictionary<string, string> _keyMetadataById = new(StringComparer.Ordinal);

    public PfxFileSigningJwtSigningService(
        IOptions<PfxFileSigningOptions> options,
        TimeProvider timeProvider,
        FileSigningKeyReader reader,
        ISigningKeyRetirementWindowProvider retirementWindowProvider,
        ISanitizingLogger<JwtSigningService<PfxFileSigningOptions>> logger)
        : base(options, timeProvider, retirementWindowProvider, logger)
    {
        ArgumentNullException.ThrowIfNull(reader);

        _options = options;
        _reader = reader;
    }

    /// <inheritdoc/>
    protected override async ValueTask<IReadOnlyList<KeyListing>> ListKeysAsync(CancellationToken cancellationToken)
    {
        var options = _options.Value;
        var files = GetRegisteredFiles(options);

        var listings = new List<KeyListing>(files.Count);

        foreach (var file in files)
        {
            // A bundled format leaves us no choice but to read the whole PFX (private half included)
            // to obtain its public certificate — but the private material is released the moment this
            // certificate is disposed at the end of the iteration, and only the exported public
            // parameters below survive into the returned listing.
            using var certificate = await LoadCertificateAsync(file, options, cancellationToken).ConfigureAwait(false);

            var (rawPublicKey, keyType) = FileSigningKeyExtractor.ExtractPublicKey(certificate, file.Id);
            using var publicKey = rawPublicKey;
            var publicKeyParameters = BuildValidatedPublicKey(publicKey, keyType, file.Id, options);

            var activateAt = new DateTimeOffset(certificate.NotBefore);
            var expiresAt = new DateTimeOffset(certificate.NotAfter);

            listings.Add(new KeyListing(new KeyId(file.Id), options.Algorithm, publicKeyParameters, activateAt, expiresAt));

            var (describedKeyType, keySizeBits) = FileSigningKeyExtractor.DescribeKeyForLogging(certificate);
            _keyMetadataById[file.Id] = $"{describedKeyType}, {keySizeBits}-bit";
        }

        return listings;
    }

    /// <inheritdoc/>
    protected override async ValueTask<ISigner> CreateSignerAsync(KeyId id, CancellationToken cancellationToken)
    {
        var options = _options.Value;
        var files = GetRegisteredFiles(options);
        var file = FindRegisteredFile(files, id.Value);

        using var certificate = await LoadCertificateAsync(file, options, cancellationToken).ConfigureAwait(false);
        var (privateKey, _) = FileSigningKeyExtractor.ExtractPrivateKey(certificate, file.Id);

        return new LocalSigner(options.Algorithm, privateKey);
    }

    /// <inheritdoc/>
    protected override string? DescribeKeyMetadata(string id) =>
        _keyMetadataById.GetValueOrDefault(id);

    private static RegisteredSigningFile FindRegisteredFile(IReadOnlyList<RegisteredSigningFile> files, string id)
    {
        var file = files.FirstOrDefault(file => string.Equals(file.Id, id, StringComparison.Ordinal));
        if (file.Id is not null)
            return file;

        throw new InvalidOperationException(
            $"{nameof(CreateSignerAsync)} was called for key '{id}', which is no longer a registered " +
            $"PFX file. {nameof(ListKeysAsync)} runs exactly once for this ADR 0015 Tier A provider, so " +
            "its registered files must not change after startup.");
    }

    private static IReadOnlyList<RegisteredSigningFile> GetRegisteredFiles(PfxFileSigningOptions options)
    {
        // The PFX format inherently bundles cert+key+chain in one file, so every entry here has only
        // a single backing path — issue #405's optional companion key path is PEM-only and does not
        // apply to this provider.
        var files = new List<RegisteredSigningFile>(1 + options.AdditionalFiles.Count) { new(options.Path) };
        files.AddRange(options.AdditionalFiles.Select(file => new RegisteredSigningFile(file.Path)));
        return files;
    }

    /// <summary>
    /// Reads and parses the PKCS#12 bundle at <paramref name="file"/>. The returned certificate
    /// carries its private key (a PFX cannot be opened without it), so callers must dispose it as soon
    /// as the material they need has been extracted — <see cref="ListKeysAsync"/> keeps only the
    /// public parameters, and <see cref="CreateSignerAsync"/> transfers the private key into the
    /// returned <see cref="LocalSigner"/>.
    /// </summary>
    /// <remarks>
    /// Loads with <see cref="X509KeyStorageFlags.DefaultKeySet"/>. Adopting
    /// <see cref="X509KeyStorageFlags.EphemeralKeySet"/> for the public-only <see cref="ListKeysAsync"/>
    /// read (so a non-active bundle's private half is never even transiently written to the Windows
    /// on-disk key store) is tracked as a follow-up — it is not portable (macOS, this provider's
    /// primary target per ADR 0011 Amendment 7, throws <see cref="PlatformNotSupportedException"/> for
    /// that flag) and needs platform-conditional handling plus Windows CI validation, out of scope for
    /// this contract migration.
    /// </remarks>
    /// <exception cref="ZeeKayDaConfigurationException">
    /// The file is not a valid PKCS#12 bundle, or the configured password is incorrect.
    /// </exception>
    private async ValueTask<X509Certificate2> LoadCertificateAsync(
        RegisteredSigningFile file, PfxFileSigningOptions options, CancellationToken cancellationToken)
    {
        var path = file.Id;
        var passwordSource = ResolvePasswordSource(path, options);
        var bytes = await _reader.ReadAllBytesAsync(path, cancellationToken).ConfigureAwait(false);
        var password = await passwordSource(cancellationToken).ConfigureAwait(false);

        try
        {
            return X509CertificateLoader.LoadPkcs12(bytes, password);
        }
        catch (CryptographicException ex)
        {
            // ex.Message comes from the BCL PKCS#12 parser and never echoes the supplied password —
            // still, the message is not further embellished with any secret-derived detail here.
            throw new ZeeKayDaConfigurationException(new ZeeKayDaConfigurationFailure(
                "signing.file_signing.invalid_pfx",
                $"The PFX/PKCS#12 file at '{path}' could not be loaded: {ex.Message}. Verify the file " +
                "is a valid PKCS#12 bundle and that the configured password is correct."));
        }
    }

    private static Func<CancellationToken, ValueTask<string>> ResolvePasswordSource(string path, PfxFileSigningOptions options)
    {
        if (string.Equals(path, options.Path, StringComparison.Ordinal))
            return options.PasswordSource!;

        var match = options.AdditionalFiles.FirstOrDefault(file => string.Equals(file.Path, path, StringComparison.Ordinal));

        // Unreachable in practice: `path` always comes from GetRegisteredFiles(options) (this
        // provider's own primary Path plus every AdditionalFiles entry), and
        // PfxFileSigningOptionsValidator rejects a null PasswordSource on both the primary and every
        // AddFile-registered entry before startup completes. InvalidOperationException (not
        // ZeeKayDaConfigurationException) is deliberate here — this guards an internal invariant that
        // "can't happen" given the two callers above, not a user-facing configuration failure a
        // relying operator could hit and needs to act on.
        return match.PasswordSource
            ?? throw new InvalidOperationException($"No password source is registered for path '{path}'.");
    }

    /// <summary>
    /// Validates that <see cref="PfxFileSigningOptions.Algorithm"/>'s family matches the loaded
    /// certificate's actual key type, and returns the corresponding public-only key parameters —
    /// reusing the descriptor's already-exported parameters rather than exporting them a second time.
    /// </summary>
    private static PublicKeyParameters BuildValidatedPublicKey(
        AsymmetricAlgorithm publicKey, SigningKeyType keyType, string path, PfxFileSigningOptions options)
    {
        var algorithm = options.Algorithm;

        var descriptor = SigningKeyDescriptorFactory.BuildDescriptor(
            publicKey,
            keyType,
            algorithm,
            "signing.file_signing.algorithm_key_type_mismatch",
            mismatchedKeyType => mismatchedKeyType == SigningKeyType.Rsa
                ? $"PfxFileSigningOptions.Algorithm is {algorithm}, but the certificate at '{path}' is an " +
                  "RSA certificate. Use an RSA algorithm (RS256, RS384, RS512, PS256, PS384, or PS512)."
                : $"PfxFileSigningOptions.Algorithm is {algorithm}, but the certificate at '{path}' is an " +
                  "EC certificate. Use an EC algorithm (ES256, ES384, or ES512).");

        return descriptor.KeyType == SigningKeyType.Rsa
            ? PublicKeyParameters.FromRsa(descriptor.RsaPublicParameters!.Value)
            : PublicKeyParameters.FromEc(descriptor.EcPublicParameters!.Value);
    }
}
