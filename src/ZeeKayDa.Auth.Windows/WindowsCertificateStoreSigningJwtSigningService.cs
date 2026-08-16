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
/// <para>
/// ADR 0015 Tier A (<see cref="KeySetOptions"/>, issue #424): the complete set of registered
/// thumbprints is fixed at configuration time, so <see cref="ListKeysAsync"/> runs exactly once,
/// ever, for the lifetime of this service instance. Only the wall clock crossing each certificate's
/// <c>NotBefore</c>/<c>NotAfter</c> — mapped onto each returned <see cref="KeyListing"/>'s
/// <see cref="KeyListing.ActivateAt"/>/<see cref="KeyListing.ExpiresAt"/> — drives which registered
/// certificate is the active signer; the base class recomputes that selection lazily on every call
/// from the one-time snapshot, so multi-certificate rotation (issue #282) still switches the active
/// signer over time with zero further store access to <em>list</em> keys; the incoming active
/// certificate's entry is re-read once, transiently, by <see cref="CreateSignerAsync"/> at the
/// handoff. Picking up a rotated-in, removed, or replaced certificate otherwise requires a restart
/// (ADR 0015 §1/§4).
/// </para>
/// <para>
/// <strong>Least-privilege loading for a bundled format (ADR 0015 §2/§5).</strong> A Windows
/// Certificate Store entry is a bundled format exactly like PFX: <see cref="X509Store.Certificates"/>
/// hands back a certificate that carries its private key when one is installed alongside it — there
/// is no way to open the store for a certificate's public half alone. This provider therefore reads
/// every registered thumbprint transiently in <see cref="ListKeysAsync"/>, extracts and retains
/// <em>only</em> the public <see cref="PublicKeyParameters"/> in the returned <see cref="KeyListing"/>,
/// and disposes the certificate (releasing its private-key handle) immediately — no private
/// material for any thumbprint, not even the active one, is retained past that transient read. When
/// the base class needs to sign, it calls <see cref="CreateSignerAsync"/>, which re-reads only the
/// single thumbprint currently selected as active; every other registered certificate's private key
/// is never loaded a second time. This is the concrete proof-point for ADR 0015 §2/§5's "provider
/// obligation, not structural guarantee" caveat: the base structurally requests private material
/// only for the active key, but keeping non-active private material out of the long-lived snapshot
/// is this provider's own doing.
/// </para>
/// <para>
/// Uses only <see cref="WindowsCertificateKeyExtractor.ExtractPublicKey"/>/
/// <see cref="WindowsCertificateKeyExtractor.ExtractPrivateKey"/> — never <c>.PrivateKey</c>, never
/// <c>ExportParameters(true)</c> — per the issue's security requirement to prefer CNG/CAPI-backed
/// handles over exporting raw key bytes into managed memory.
/// </para>
/// <para>
/// <see cref="CreateSignerAsync"/> builds and returns a <see cref="LocalSigner"/> — this provider
/// signs with local key handles exactly like the development provider and the Azure Key Vault
/// *cached* signing provider, never implementing <see cref="ISigner"/> itself. There is also no
/// <c>WindowsCertificateStoreSigningException</c> transport type: unlike Key Vault, there is no
/// network round trip at sign time, so there is no transient-fault surface to wrap.
/// </para>
/// <para>
/// <c>kid</c> is the RFC 7638 JWK thumbprint of each certificate's public key, derived by the base
/// class from each <see cref="KeyListing.PublicKey"/> — never the certificate's own X.509
/// thumbprint, which is only this provider's own internal <see cref="KeyId"/> (ADR 0015 §2), since a
/// <c>kid</c> is always public and the store thumbprint could leak external identifier information.
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
            // A Windows Certificate Store entry is a bundled format exactly like PFX — reading it
            // yields the whole certificate (private half included, when installed) — but the
            // private material is released the moment this certificate is disposed at the end of
            // the iteration, and only the exported public parameters below survive into the
            // returned listing.
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
    /// Not declared <see langword="async"/>: every step here (the store read and key extraction) is
    /// synchronous, and an <see langword="async"/> method with no <c>await</c> would be a compiler
    /// warning (elevated to an error by this repository's <c>TreatWarningsAsErrors</c>). The
    /// defensive <see cref="FindRegisteredThumbprint"/> failure is therefore deliberately captured
    /// into the returned <see cref="ValueTask{TResult}"/> via <see cref="ValueTask.FromException{TResult}"/>
    /// rather than left to throw synchronously from this method — matching the base class's calling
    /// convention (every override's failure surfaces through the awaited task, never synchronously
    /// from the call site) exactly as an <see langword="async"/> override's compiler-generated state
    /// machine would.
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

        // The private-key/public-key pairing check that used to live here (VerifySigningKeyMatchesListing,
        // PR #436 security review) is superseded by the framework-owned ADR 0015 §11 self-test
        // (issue #437): JwtSigningService<TOptions>'s own handoff logic signs with the signer this
        // method returns and verifies the signature against the same key's listed public key on
        // every handoff (initial materialization and every rotation, not only at process start),
        // which structurally proves the same pairing invariant for every provider, not just this
        // one.
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
            $"certificate thumbprint. {nameof(ListKeysAsync)} runs exactly once for this ADR 0015 Tier A " +
            "provider, so its registered thumbprints must not change after startup.");
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
