using System.Linq;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
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

    // Populated by ListKeysAsync (Tier A: runs exactly once) so DescribeKeyMetadata can supply it
    // later, when the base class logs each key's status.
    private readonly Dictionary<string, string> _keyMetadataById = new(StringComparer.Ordinal);

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
    }

    /// <inheritdoc/>
    protected override async ValueTask<IReadOnlyList<KeyListing>> ListKeysAsync(CancellationToken cancellationToken)
    {
        var options = _options.Value;
        var files = GetRegisteredFiles(options);

        var listings = new List<KeyListing>(files.Count);

        foreach (var file in files)
        {
            using var certificate = await LoadPublicCertificateAsync(file, cancellationToken).ConfigureAwait(false);

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

        using var certificate = await LoadSigningCertificateAsync(file, cancellationToken).ConfigureAwait(false);
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

    /// <summary>
    /// Parses only the certificate at <paramref name="file"/> — no private key material is ever read
    /// or parsed. Used to build the public listing in <see cref="ListKeysAsync"/>.
    /// </summary>
    /// <exception cref="ZeeKayDaConfigurationException">
    /// The file does not contain a valid PEM-encoded certificate.
    /// </exception>
    private async ValueTask<X509Certificate2> LoadPublicCertificateAsync(
        RegisteredSigningFile file, CancellationToken cancellationToken)
    {
        var certPem = await _reader.ReadPemTextAsync(file.Id, cancellationToken).ConfigureAwait(false);

        try
        {
            return X509Certificate2.CreateFromPem(certPem);
        }
        catch (Exception ex) when (ex is CryptographicException or ArgumentException or FormatException)
        {
            throw new ZeeKayDaConfigurationException(new ZeeKayDaConfigurationFailure(
                "signing.file_signing.invalid_pem",
                $"The file at '{file.Id}' does not contain a valid PEM-encoded certificate: {ex.Message}"));
        }
    }

    /// <summary>
    /// Parses the certificate and private key at <paramref name="file"/>. Used only by
    /// <see cref="CreateSignerAsync"/>, for the single file the base class has selected as the
    /// active signer.
    /// </summary>
    /// <exception cref="ZeeKayDaConfigurationException">
    /// The file(s) do not contain a valid PEM-encoded certificate and private key.
    /// </exception>
    private async ValueTask<X509Certificate2> LoadSigningCertificateAsync(
        RegisteredSigningFile file, CancellationToken cancellationToken)
    {
        // Reads through FileSigningKeyReader.ReadPemTextAsync and calls X509Certificate2.CreateFromPem
        // rather than X509Certificate2.CreateFromPemFile, which performs its own unvalidated file I/O
        // and would bypass FileSigningKeyReader's permission/symlink validation.
        var keyPath = file.AdditionalPaths.Count > 0 ? file.AdditionalPaths[0] : null;

        var certPem = await _reader.ReadPemTextAsync(file.Id, cancellationToken).ConfigureAwait(false);
        // With no separate key path, the combined file carries both PEM blocks, so the same text is
        // passed for both the certificate and the key source.
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
}
