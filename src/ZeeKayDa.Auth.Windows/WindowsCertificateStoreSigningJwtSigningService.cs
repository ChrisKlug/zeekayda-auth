using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
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
/// The set of registered thumbprints is fixed at configuration time, so <see cref="ListKeysAsync"/>
/// runs exactly once for the lifetime of this service instance; the wall clock crossing each
/// certificate's <c>NotBefore</c>/<c>NotAfter</c> is what drives which one becomes the active
/// signer over time, with no further store access to list keys. Picking up a rotated-in, removed,
/// or replaced certificate requires a restart.
/// <para>
/// A store entry is a bundled format exactly like PFX — there is no way to open it for the public
/// half alone — so this provider reads each certificate transiently, retains only the exported
/// public <see cref="PublicKeyParameters"/>, and disposes the certificate immediately. Only the
/// currently active thumbprint's private key is re-read, in <see cref="CreateSignerAsync"/>, at
/// the handoff.
/// </para>
/// <para>
/// Uses only <see cref="WindowsCertificateKeyExtractor.ExtractPublicKey"/>/
/// <see cref="WindowsCertificateKeyExtractor.ExtractPrivateKey"/> — never <c>.PrivateKey</c> or
/// <c>ExportParameters(true)</c> — preferring CNG/CAPI-backed handles over exporting raw key bytes.
/// </para>
/// </remarks>
internal sealed class WindowsCertificateStoreSigningJwtSigningService : JwtSigningService<WindowsCertificateStoreSigningOptions>
{
    private readonly IOptions<WindowsCertificateStoreSigningOptions> _options;
    private readonly ICertificateStoreReader _storeReader;
    private readonly ICertificateKeyExtractor _keyExtractor;

    // Populated by ListKeysAsync (Tier A: runs exactly once) so DescribeKeyMetadata can supply it
    // later, when the base class logs each key's status.
    private readonly Dictionary<string, string> _keyMetadataById = new(StringComparer.Ordinal);

    public WindowsCertificateStoreSigningJwtSigningService(
        IOptions<WindowsCertificateStoreSigningOptions> options,
        TimeProvider timeProvider,
        ICertificateStoreReader storeReader,
        ICertificateKeyExtractor keyExtractor,
        ISigningKeyRetirementWindowProvider retirementWindowProvider,
        ISanitizingLogger<JwtSigningService<WindowsCertificateStoreSigningOptions>> logger)
        : base(options, timeProvider, retirementWindowProvider, logger)
    {
        ArgumentNullException.ThrowIfNull(storeReader);
        ArgumentNullException.ThrowIfNull(keyExtractor);

        _options = options;
        _storeReader = storeReader;
        _keyExtractor = keyExtractor;
    }

    /// <inheritdoc/>
    protected override ValueTask<IReadOnlyList<KeyListing>> ListKeysAsync(CancellationToken cancellationToken)
    {
        var options = _options.Value;
        var thumbprints = GetRegisteredThumbprints(options);

        var listings = new List<KeyListing>(thumbprints.Count);

        foreach (var thumbprint in thumbprints)
        {
            // Private material is released the moment this certificate is disposed at the end of
            // the iteration; only the exported public parameters below survive into the listing.
            using var certificate = _storeReader.GetCertificate(thumbprint, options.StoreLocation, options.StoreName);

            var (publicKey, keyType) = _keyExtractor.ExtractPublicKey(certificate, thumbprint);
            using var publicKeyHandle = publicKey;
            var publicKeyParameters = BuildValidatedPublicKey(publicKeyHandle, keyType, thumbprint, options);

            var activateAt = new DateTimeOffset(certificate.NotBefore);
            var expiresAt = new DateTimeOffset(certificate.NotAfter);

            listings.Add(new KeyListing(new KeyId(thumbprint), options.Algorithm, publicKeyParameters, activateAt, expiresAt));

            _keyMetadataById[thumbprint] = DescribeCertificateForLogging(certificate);
        }

        return new ValueTask<IReadOnlyList<KeyListing>>(listings);
    }

    /// <inheritdoc/>
    /// <remarks>
    /// Not declared <see langword="async"/>: every step here is synchronous. The
    /// <see cref="FindRegisteredThumbprint"/> failure is captured into the returned task via
    /// <see cref="ValueTask.FromException{TResult}"/> so it still surfaces through the awaited task
    /// rather than synchronously from the call site, matching the base class's calling convention.
    /// </remarks>
    protected override ValueTask<ISigner> CreateSignerAsync(KeyId id, CancellationToken cancellationToken)
    {
        var options = _options.Value;
        var thumbprints = GetRegisteredThumbprints(options);

        string thumbprint;
        try
        {
            thumbprint = FindRegisteredThumbprint(thumbprints, id.Value);
        }
        catch (InvalidOperationException ex)
        {
            return ValueTask.FromException<ISigner>(ex);
        }

        using var certificate = _storeReader.GetCertificate(thumbprint, options.StoreLocation, options.StoreName);

        // Private/public key pairing is verified by the framework-owned handoff self-test in the
        // base class, not here.
        var (privateKey, _) = _keyExtractor.ExtractPrivateKey(certificate, thumbprint);

        return new ValueTask<ISigner>(new LocalSigner(options.Algorithm, privateKey));
    }

    /// <inheritdoc/>
    protected override string? DescribeKeyMetadata(string id) =>
        _keyMetadataById.GetValueOrDefault(id);

    private static string FindRegisteredThumbprint(IReadOnlyList<string> thumbprints, string id)
    {
        var thumbprint = thumbprints.FirstOrDefault(candidate => string.Equals(candidate, id, StringComparison.Ordinal));
        if (thumbprint is not null)
            return thumbprint;

        throw new InvalidOperationException(
            $"{nameof(CreateSignerAsync)} was called for key '{id}', which is no longer a registered " +
            $"certificate thumbprint. {nameof(ListKeysAsync)} runs exactly once for this provider, so " +
            "its registered thumbprints must not change after startup.");
    }

    private static IReadOnlyList<string> GetRegisteredThumbprints(WindowsCertificateStoreSigningOptions options)
    {
        var thumbprints = new List<string>(1 + options.AdditionalThumbprints.Count) { options.Thumbprint };
        thumbprints.AddRange(options.AdditionalThumbprints);
        return thumbprints;
    }

    /// <summary>
    /// Validates that <see cref="WindowsCertificateStoreSigningOptions.Algorithm"/>'s family matches
    /// the loaded certificate's actual key type, and returns the corresponding public-only key
    /// parameters — reusing the descriptor's already-exported parameters rather than exporting them
    /// a second time.
    /// </summary>
    private static PublicKeyParameters BuildValidatedPublicKey(
        AsymmetricAlgorithm publicKey, SigningKeyType keyType, string thumbprint, WindowsCertificateStoreSigningOptions options)
    {
        var algorithm = options.Algorithm;

        var descriptor = SigningKeyDescriptorFactory.BuildDescriptor(
            publicKey,
            keyType,
            algorithm,
            "signing.windows_certificate_store.algorithm_key_type_mismatch",
            mismatchedKeyType => mismatchedKeyType == SigningKeyType.Rsa
                ? $"WindowsCertificateStoreSigningOptions.Algorithm is {algorithm}, but certificate " +
                  $"'{thumbprint}' is an RSA certificate. Use an RSA algorithm (RS256, RS384, RS512, PS256, PS384, or PS512)."
                : $"WindowsCertificateStoreSigningOptions.Algorithm is {algorithm}, but certificate " +
                  $"'{thumbprint}' is an EC certificate. Use an EC algorithm (ES256, ES384, or ES512).");

        return descriptor.KeyType == SigningKeyType.Rsa
            ? PublicKeyParameters.FromRsa(descriptor.RsaPublicParameters!.Value)
            : PublicKeyParameters.FromEc(descriptor.EcPublicParameters!.Value);
    }

    private static string DescribeCertificateForLogging(X509Certificate2 certificate) =>
        $"subject '{certificate.Subject}'";
}
