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
/// The set of registered PFX files is fixed at configuration time, so <see cref="ListKeysAsync"/>
/// runs exactly once for the lifetime of this service instance; the wall clock crossing each
/// certificate's <c>NotBefore</c>/<c>NotAfter</c> is what drives which file becomes the active
/// signer over time, with no further filesystem I/O. Picking up a rotated-in or replaced file
/// requires a restart.
/// <para>
/// PFX is a bundled format — there is no way to open it for the public certificate alone — so this
/// provider reads each bundle transiently, retains only the exported public
/// <see cref="PublicKeyParameters"/>, and disposes the certificate immediately. Only the currently
/// active file's private key is re-read and re-parsed, in <see cref="CreateSignerAsync"/>.
/// </para>
/// </remarks>
internal sealed class PfxFileSigningJwtSigningService : JwtSigningService<PfxFileSigningOptions>
{
    private readonly IOptions<PfxFileSigningOptions> _options;
    private readonly FileSigningKeyReader _reader;

    // Populated by ListKeysAsync (KeySetOptions: runs exactly once) so DescribeKeyMetadata can supply it
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
            // Private material is released the moment this certificate is disposed at the end of
            // the iteration; only the exported public parameters below survive into the listing.
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
            $"PFX file. {nameof(ListKeysAsync)} runs exactly once for this provider, so its registered " +
            "files must not change after startup.");
    }

    private static IReadOnlyList<RegisteredSigningFile> GetRegisteredFiles(PfxFileSigningOptions options)
    {
        // PFX bundles cert+key+chain in one file, so a companion key path (a PEM-only concept)
        // does not apply here.
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
    /// <see cref="X509KeyStorageFlags.EphemeralKeySet"/> for the public-only
    /// <see cref="ListKeysAsync"/> read is tracked as a follow-up — it is not portable to macOS.
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
            // ex.Message comes from the BCL PKCS#12 parser and never echoes the supplied password.
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

        // Unreachable in practice: PfxFileSigningOptionsValidator rejects a null PasswordSource
        // before startup completes. InvalidOperationException (not ZeeKayDaConfigurationException)
        // is deliberate — this guards an internal invariant, not a user-facing config failure.
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
