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

    // Populated by ListKeysAsync (Tier A: runs exactly once) alongside _keyMetadataById, so
    // CreateSignerAsync can verify — at handoff — that the private key it just re-read from the
    // store still pairs with the public key that was captured (and whose kid the base class is
    // signing under) for that same thumbprint (L-3/M-1, PR #436 security review).
    private readonly Dictionary<string, PublicKeyParameters> _publicKeysByThumbprint = new(StringComparer.Ordinal);

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
            _publicKeysByThumbprint[thumbprint] = publicKeyParameters;
        }

        return new ValueTask<IReadOnlyList<KeyListing>>(listings);
    }

    /// <inheritdoc/>
    /// <remarks>
    /// Not declared <see langword="async"/>: every step here (the store read and key extraction) is
    /// synchronous, and an <see langword="async"/> method with no <c>await</c> would be a compiler
    /// warning (elevated to an error by this repository's <c>TreatWarningsAsErrors</c>). Both the
    /// defensive <see cref="FindRegisteredThumbprint"/> failure and the
    /// <see cref="VerifySigningKeyMatchesListing"/> mismatch failure are therefore deliberately
    /// captured into the returned <see cref="ValueTask{TResult}"/> via
    /// <see cref="ValueTask.FromException{TResult}"/> rather than left to throw synchronously from
    /// this method — matching the base class's calling convention (every override's failure surfaces
    /// through the awaited task, never synchronously from the call site) exactly as an
    /// <see langword="async"/> override's compiler-generated state machine would.
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

        var (privateKey, keyType) = _keyExtractor.ExtractPrivateKey(certificate, thumbprint);

        try
        {
            VerifySigningKeyMatchesListing(privateKey, keyType, thumbprint, options);
        }
        catch (Exception ex) when (ex is ZeeKayDaConfigurationException or CryptographicException
            or NotSupportedException or InvalidCastException)
        {
            // VerifySigningKeyMatchesListing's call chain (BuildValidatedPublicKey ->
            // SigningKeyDescriptorFactory.BuildDescriptor) can surface a ZeeKayDaConfigurationException
            // (algorithm/key-type mismatch or the pairing check itself), a CryptographicException (an
            // exotic KSP/HSM that refuses even public export), a NotSupportedException (an unsupported
            // SigningKeyType), or an InvalidCastException (publicKey/keyType disagreement) — every one
            // of those must still surface through the returned ValueTask, per this method's
            // <remarks>, not synchronously from this call site (L-7, PR #436 security review). The
            // private key handle is about to be handed to LocalSigner on the success path, which takes
            // ownership of disposing it; on every one of these failure paths nothing else owns it, so
            // it must be disposed here to avoid leaking the underlying CNG/CAPI handle.
            privateKey.Dispose();
            return ValueTask.FromException<ISigner>(ex);
        }

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

    /// <summary>
    /// Defence-in-depth check (L-3/M-1, PR #436 security review): derives the public half of
    /// <paramref name="privateKey"/> — the actual private key handle <see cref="CreateSignerAsync"/>
    /// is about to hand to <see cref="LocalSigner"/> — via <c>RSA.ExportParameters</c>/
    /// <c>ECDsa.ExportParameters</c> with <c>includePrivateParameters: false</c>, and compares that
    /// derived public half against the
    /// public key that <see cref="ListKeysAsync"/> captured for the same <paramref name="thumbprint"/>
    /// — the public key whose derived <c>kid</c> the base class is signing under.
    /// </summary>
    /// <remarks>
    /// This is deliberately <em>not</em> a comparison against the certificate's own
    /// <c>SubjectPublicKeyInfo</c> (re-reading a store entry by thumbprint, a hash of the whole
    /// certificate, always yields the same SPKI, making such a comparison a tautology that can never
    /// fire): the export above reads the public component the private key <em>container</em> actually
    /// holds, independently of the certificate's own advertised public key, so it can detect the case
    /// where the two have drifted apart. A mismatch means the store entry's key-container association
    /// changed after startup without the certificate's thumbprint changing (e.g. a botched
    /// <c>certutil -repairstore</c>); left uncaught, tokens would be signed under a <c>kid</c> that no
    /// longer matches the actual signing key — fail-closed for relying parties, but confusing to
    /// diagnose. <paramref name="privateKey"/> is never exported with its private components
    /// (<c>ExportParameters(true)</c>) — only the public half, which <see cref="RSA"/>/<see cref="ECDsa"/>
    /// permit exporting even for a non-exportable CNG-backed key, since only exporting the private
    /// components requires export permission on the key.
    /// </remarks>
    private void VerifySigningKeyMatchesListing(
        AsymmetricAlgorithm privateKey, SigningKeyType keyType, string thumbprint, WindowsCertificateStoreSigningOptions options)
    {
        var currentPublicKey = BuildValidatedPublicKey(privateKey, keyType, thumbprint, options);

        if (!_publicKeysByThumbprint.TryGetValue(thumbprint, out var listedPublicKey) ||
            !PublicKeysMatch(listedPublicKey, currentPublicKey))
        {
            throw new ZeeKayDaConfigurationException(new ZeeKayDaConfigurationFailure(
                "signing.windows_certificate_store.signing_key_mismatch",
                $"Certificate '{thumbprint}': the public key derived from the private key currently " +
                "backing this store entry does not match the public key captured for this thumbprint " +
                "during startup listing. This indicates the store entry's key-container association " +
                "changed after startup (for example, via 'certutil -repairstore') without the " +
                "certificate's thumbprint changing. Restart the process so the active signer is " +
                "re-selected against the current key pairing."));
        }
    }

    /// <summary>
    /// Structurally compares two sets of public key parameters (modulus/exponent for RSA,
    /// curve/point for EC) — never a reference or default record comparison, since
    /// <see cref="RSAParameters"/>/<see cref="ECParameters"/> carry <c>byte[]</c> fields that
    /// default equality would compare by reference, not content.
    /// </summary>
    private static bool PublicKeysMatch(PublicKeyParameters listed, PublicKeyParameters current)
    {
        if (listed.KeyType != current.KeyType)
            return false;

        return listed.KeyType == SigningKeyType.Rsa
            ? RsaParametersMatch(listed.RsaPublicParameters!.Value, current.RsaPublicParameters!.Value)
            : EcParametersMatch(listed.EcPublicParameters!.Value, current.EcPublicParameters!.Value);
    }

    private static bool RsaParametersMatch(RSAParameters listed, RSAParameters current) =>
        listed.Modulus.AsSpan().SequenceEqual(current.Modulus) &&
        listed.Exponent.AsSpan().SequenceEqual(current.Exponent);

    private static bool EcParametersMatch(ECParameters listed, ECParameters current) =>
        CurveIdentifiersMatch(listed.Curve, current.Curve) &&
        listed.Q.X.AsSpan().SequenceEqual(current.Q.X) &&
        listed.Q.Y.AsSpan().SequenceEqual(current.Q.Y);

    /// <summary>
    /// Compares two <see cref="ECCurve"/>s' identities via <see cref="Oid.Value"/>, falling back to
    /// <see cref="Oid.FriendlyName"/> when either curve's <see cref="Oid.Value"/> is unset (a known,
    /// platform-dependent possibility when a curve was resolved by friendly name rather than OID).
    /// Never treats a "both null or empty" pairing as a match on either property — doing so (e.g. a
    /// plain <see cref="string.Equals(string?, string?)"/> comparison of <see cref="Oid.Value"/>
    /// alone, where both <see langword="null"/> == <see langword="null"/> and <c>"" == ""</c> are
    /// <see langword="true"/>) would let two differently identified curves compare equal without
    /// actually validating that they are the same curve (L-6/L-8, PR #436 security review) — an empty
    /// string is exactly as invalid an identity signal as <see langword="null"/>, so both legs are
    /// guarded with <see cref="string.IsNullOrEmpty(string?)"/>, not a bare null check.
    /// </summary>
    private static bool CurveIdentifiersMatch(ECCurve listed, ECCurve current)
    {
        if (!string.IsNullOrEmpty(listed.Oid?.Value) && !string.IsNullOrEmpty(current.Oid?.Value))
            return string.Equals(listed.Oid.Value, current.Oid.Value, StringComparison.Ordinal);

        if (!string.IsNullOrEmpty(listed.Oid?.FriendlyName) && !string.IsNullOrEmpty(current.Oid?.FriendlyName))
            return string.Equals(listed.Oid.FriendlyName, current.Oid.FriendlyName, StringComparison.OrdinalIgnoreCase);

        return false;
    }
}
