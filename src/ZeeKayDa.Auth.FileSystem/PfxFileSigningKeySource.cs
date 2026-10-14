using System.Formats.Asn1;
using System.Security.Cryptography;
using System.Security.Cryptography.Pkcs;
using System.Security.Cryptography.X509Certificates;
using Microsoft.Extensions.Options;
using ZeeKayDa.Auth.Tokens;

namespace ZeeKayDa.Auth.FileSystem;

/// <summary>
/// An <see cref="ISigningKeySource"/> that lists the PFX/PKCS#12 bundles in
/// <see cref="PfxFileSigningOptions.Files"/> and signs locally, in process, with whichever of them
/// the framework chooses.
/// </summary>
/// <remarks>
/// <para>
/// <b>Listing never imports a private key into a key object.</b> <see cref="ReadAsync"/> walks each
/// bundle with <see cref="Pkcs12Info"/>: the password authenticates the file and decrypts the
/// authenticated safe, the certificate bag is read, and no key bag is decrypted or imported. One
/// residue is inherent to the format: an <i>unshrouded</i> key bag is plaintext PKCS#8 inside the
/// safe, so decrypting the safe puts those bytes in managed memory. They are never read and never
/// imported.
/// </para>
/// <para>
/// <b>Signing never builds an OS-backed certificate.</b> <see cref="CreateSignerAsync"/> runs the
/// same selection the listing ran and imports the key bag paired with the listed certificate
/// straight into an in-memory key, so the private key is never written to a platform key store.
/// </para>
/// <para>
/// Whether a key suits the configured algorithm is not checked here:
/// <see cref="SigningKeySetBuilder"/> validates every reported key, keyed on the source id — which
/// here is the configured file path, so its failures still name the offending bundle. The signer
/// checks only that the imported key is of the same type, RSA or EC, as its paired certificate.
/// </para>
/// </remarks>
internal sealed class PfxFileSigningKeySource(
    IOptions<PfxFileSigningOptions> options,
    FileSigningKeyReader reader) : ISigningKeySource
{
    private readonly IOptions<PfxFileSigningOptions> _options = options;

    /// <inheritdoc/>
    public SigningAlgorithm Algorithm => _options.Value.Algorithm;

    /// <inheritdoc/>
    public async Task<SourceKeyListing> ReadAsync(CancellationToken cancellationToken = default)
    {
        var options = _options.Value;
        var keys = new List<SourceKey>(options.Files.Count);
        var failures = new List<SourceKeyFailure>();

        foreach (var file in options.Files)
        {
            var id = new SourceKeyId(file.Path);
            try
            {
                // A deleted certificate file is no longer listed: deleting it revokes the key.
                using var certificate = await LoadPublicCertificateAsync(file, cancellationToken).ConfigureAwait(false);
                if (certificate is not null)
                    keys.Add(SourceKey.FromCertificate(certificate, id));
            }
            catch (Exception ex) when (ex is not OperationCanceledException)
            {
                failures.Add(SigningFileFailure.Of(file.Path, ex));
            }
        }

        return new SourceKeyListing(keys, failures);
    }

    /// <inheritdoc/>
    public async Task<ISigner> CreateSignerAsync(SourceKeyId id, CancellationToken cancellationToken = default)
    {
        var options = _options.Value;
        var file = options.Files.FirstOrDefault(f => string.Equals(f.Path, id.Value, StringComparison.Ordinal))
            ?? throw new InvalidOperationException(
                $"{nameof(CreateSignerAsync)} was called for key '{id.Value}', which is not a listed PFX file.");

        var bytes = await reader.ReadAllBytesAsync(file.Path, cancellationToken).ConfigureAwait(false);
        var password = await SigningFilePassword.ReadAsync(file.Path, file.PasswordSource, cancellationToken).ConfigureAwait(false);

        var privateKey = OpenSigningPair(bytes, file.Path, password, pair => ImportPairedKey(pair, file.Path, password));
        return new LocalSigner(options.Algorithm, privateKey);
    }

    /// <summary>
    /// Imports the key bag of <paramref name="pair"/> — the one call in this type that materialises a
    /// private key — and rejects a key whose type is not the certificate's.
    /// </summary>
    private static AsymmetricAlgorithm ImportPairedKey(SigningPair pair, string path, string password)
    {
        // Read before the import, so nothing that can throw stands between the import and its owner.
        string certificateKeyAlgorithm;
        using (var certificate = pair.Certificate.GetCertificate())
            certificateKeyAlgorithm = certificate.GetKeyAlgorithm();

        var privateKey = Pkcs12PrivateKey.Import(pair.Key, password)
            ?? throw InvalidPfx(path,
                "carries a private key that imports as neither an RSA nor an EC key. Verify the key is " +
                "RSA or EC and is encrypted under the same password as the bundle");

        var matchesCertificate = privateKey switch
        {
            RSA => certificateKeyAlgorithm == RsaOid,
            ECDsa => certificateKeyAlgorithm == EcOid,
            _ => false,
        };

        if (matchesCertificate)
            return privateKey;

        privateKey.Dispose();
        throw InvalidPfx(path,
            "pairs its certificate with a private key of a different type, so the published key could " +
            "never verify what it signs. Re-export the bundle from the keypair it is meant to hold");
    }

    /// <summary>
    /// Reads the signing certificate out of the PKCS#12 bundle <paramref name="file"/> without
    /// decrypting its key bag, so listing imports no private key into a key object. Returns
    /// <see langword="null"/> when the file does not exist.
    /// </summary>
    private async ValueTask<X509Certificate2?> LoadPublicCertificateAsync(
        PfxFile file, CancellationToken cancellationToken)
    {
        if (await reader.TryReadAllBytesAsync(file.Path, cancellationToken).ConfigureAwait(false) is not { } bytes)
            return null;

        var password = await SigningFilePassword.ReadAsync(file.Path, file.PasswordSource, cancellationToken).ConfigureAwait(false);

        return OpenSigningPair(bytes, file.Path, password, pair => pair.Certificate.GetCertificate());
    }

    /// <summary>
    /// Authenticates the PKCS#12 bundle <paramref name="bytes"/>, selects its signing certificate and
    /// the key bag paired with it, and hands the pair to <paramref name="use"/>. Listing and signing
    /// both go through here, so they cannot disagree about which key a bundle signs with.
    /// </summary>
    /// <exception cref="ZeeKayDaConfigurationException">
    /// The file is not a valid PKCS#12 bundle, is not MAC-protected, fails its integrity check
    /// (wrong password or tampering), uses an unsupported confidentiality mode, carries no private
    /// key, or does not identify exactly one signing certificate and key.
    /// </exception>
    private static T OpenSigningPair<T>(byte[] bytes, string path, string password, Func<SigningPair, T> use)
    {
        try
        {
            // skipCopy: the returned Pkcs12Info reads directly out of `bytes`, which the caller
            // allocated for this one call and never mutates.
            var info = Pkcs12Info.Decode(bytes, out _, skipCopy: true);

            VerifyIntegrity(info, path, password);

            return use(SelectSigningPair(info, path, password));
        }
        catch (Exception ex) when (ex is CryptographicException or AsnContentException or InvalidOperationException)
        {
            // The exception TYPE is named, never ex.Message: the parser's text is raised over a
            // bundle read under a configured password, and a failure message is a plain public-API
            // string that neither by-key redaction nor RedactedExceptionWrapper can reach. The root
            // cause travels as the inner exception instead.
            throw InvalidPfx(
                path,
                $"could not be loaded: {ex.GetType().FullName} was thrown. See the inner exception " +
                "for the root cause. Verify the file is a valid PKCS#12 bundle and that the " +
                "configured password is correct",
                ex);
        }
    }

    private const string RsaOid = "1.2.840.113549.1.1.1";
    private const string EcOid = "1.2.840.10045.2.1";

    private readonly record struct SigningPair(Pkcs12CertBag Certificate, Pkcs12SafeBag Key);

    /// <summary>
    /// Rejects a bundle whose MAC does not verify under the configured password, and one carrying no
    /// password MAC at all.
    /// </summary>
    /// <remarks>
    /// Without this, the password is not a control at all on this path: a bundle whose certificate
    /// sits in an unencrypted safe is never asked for one, so any password — and any substituted
    /// file — would be accepted. The ring's self-test covers only the key that signs, so every other
    /// listed bundle's public key would simply appear in the JWKS as a valid verification key. This
    /// is the check that makes the password the defense-in-depth the registration documents it as.
    /// </remarks>
    private static void VerifyIntegrity(Pkcs12Info info, string path, string password)
    {
        if (info.IntegrityMode != Pkcs12IntegrityMode.Password)
        {
            throw InvalidPfx(path,
                $"is not password-MAC-protected (integrity mode '{info.IntegrityMode}'), so its " +
                "contents cannot be authenticated against the configured password. Re-export it with " +
                "password integrity protection, which is what every mainstream PKCS#12 tool produces " +
                "by default");
        }

        if (!info.VerifyMac(password))
        {
            throw InvalidPfx(path,
                "failed its integrity check. Either the configured password is incorrect, or the " +
                "file has been modified since it was created");
        }
    }

    /// <summary>
    /// Returns the signing certificate and the key bag paired with it, decrypting each safe but never
    /// a key bag.
    /// </summary>
    /// <remarks>
    /// A bundle routinely carries chain certificates alongside the signing certificate, in no
    /// guaranteed order — PKCS#12 imposes none — so "the first certificate" is not the signing one.
    /// PKCS#12 pairs a certificate with its key through a shared <c>localKeyId</c> attribute, which
    /// is what is matched on here. Publishing a chain certificate's public key instead would put a
    /// key nothing can sign with into the JWKS, under a <c>kid</c> derived from it, while the tokens
    /// the real key signed carry a <c>kid</c> that is no longer published at all.
    /// </remarks>
    private static SigningPair SelectSigningPair(Pkcs12Info info, string path, string password)
    {
        var (certBags, keyBags) = ReadBags(info, path, password);

        if (certBags.Count == 0)
        {
            throw InvalidPfx(path,
                "contains no certificate. Verify the file is a complete PKCS#12 bundle carrying both " +
                "a certificate and its private key");
        }

        // Checked here, where it costs nothing, rather than when the bundle is first chosen to sign —
        // possibly long after it was deployed.
        if (keyBags.Count == 0)
        {
            throw InvalidPfx(path,
                "carries no private key. Every listed bundle must carry one, because any of them may " +
                "be chosen to sign");
        }

        // The normal case for any bundle carrying a chain: pair on localKeyId.
        if (keyBags.Any(keyBag => LocalKeyIdOf(keyBag) is not null))
            return PairOnLocalKeyId(certBags, keyBags, path);

        if (certBags.Count == 1 && keyBags.Count == 1)
            return new SigningPair(certBags[0], keyBags[0]);

        throw InvalidPfx(path,
            $"contains {certBags.Count} certificates and {keyBags.Count} private keys with nothing " +
            "identifying which one signs. PKCS#12 pairs a certificate with its key through a " +
            "localKeyId attribute; re-export the bundle with a tool that sets one, or supply a bundle " +
            "holding a single certificate and key");
    }

    private static (List<Pkcs12CertBag> CertBags, List<Pkcs12SafeBag> KeyBags) ReadBags(
        Pkcs12Info info, string path, string password)
    {
        var certBags = new List<Pkcs12CertBag>();
        var keyBags = new List<Pkcs12SafeBag>();

        foreach (var safe in info.AuthenticatedSafe)
        {
            OpenSafe(safe, path, password);

            foreach (var bag in safe.GetBags())
            {
                if (bag is Pkcs12CertBag certBag)
                    certBags.Add(certBag);
                else if (bag is Pkcs12KeyBag or Pkcs12ShroudedKeyBag)
                    keyBags.Add(bag);
            }
        }

        return (certBags, keyBags);
    }

    private static void OpenSafe(Pkcs12SafeContents safe, string path, string password)
    {
        switch (safe.ConfidentialityMode)
        {
            case Pkcs12ConfidentialityMode.None:
                break;

            // Decrypts the safe, not the key bag. A password-protected safe must be opened to reach
            // the certificate at all; the shrouded key bag inside it stays encrypted until the signer
            // imports it.
            case Pkcs12ConfidentialityMode.Password:
                safe.Decrypt(password);
                break;

            default:
                throw InvalidPfx(path,
                    $"uses the unsupported confidentiality mode '{safe.ConfidentialityMode}'. " +
                    "Only unencrypted and password-encrypted PKCS#12 safes are supported");
        }
    }

    private static SigningPair PairOnLocalKeyId(
        List<Pkcs12CertBag> certBags, List<Pkcs12SafeBag> keyBags, string path)
    {
        var paired = (
            from certBag in certBags
            from keyBag in keyBags
            where LocalKeyIdOf(certBag) is { } certId
                && LocalKeyIdOf(keyBag) is { } keyId
                && keyId.Span.SequenceEqual(certId.Span)
            select new SigningPair(certBag, keyBag)).ToList();

        if (paired.Count == 1)
            return paired[0];

        if (paired.Count > 1)
        {
            throw InvalidPfx(path,
                $"identifies {paired.Count} certificate and key pairs, so which one signs is " +
                "ambiguous. Export a bundle carrying a single signing certificate and its key");
        }

        // A private key whose certificate is not in the bundle. A lone certificate and a lone key are
        // still unambiguous; anything else is a bundle that cannot say what it signs with.
        if (certBags.Count == 1 && keyBags.Count == 1)
            return new SigningPair(certBags[0], keyBags[0]);

        throw InvalidPfx(path,
            "names a private key whose certificate is not among the certificates it carries, so " +
            "which one signs cannot be determined. Re-export the bundle from the keypair it is " +
            "meant to hold");
    }

    private static ReadOnlyMemory<byte>? LocalKeyIdOf(Pkcs12SafeBag bag)
    {
        foreach (var attribute in bag.Attributes)
        {
            foreach (var value in attribute.Values)
            {
                if (value is Pkcs9LocalKeyId localKeyId)
                    return localKeyId.KeyId;
            }
        }

        return null;
    }

    /// <summary>
    /// Builds the shared <c>invalid_pfx</c> failure. <paramref name="cause"/> is supplied only by
    /// the call site that catches a parser exception, and carries it as the inner exception
    /// because the failure message names its type rather than repeating its text.
    /// </summary>
    private static ZeeKayDaConfigurationException InvalidPfx(
        string path, string problem, Exception? cause = null)
    {
        var failure = new ZeeKayDaConfigurationFailure(
            "signing.file_signing.invalid_pfx",
            $"The PFX/PKCS#12 file at '{path}' {problem}.");

        return cause is null
            ? new ZeeKayDaConfigurationException(failure)
            : new ZeeKayDaConfigurationException(failure, cause);
    }
}
