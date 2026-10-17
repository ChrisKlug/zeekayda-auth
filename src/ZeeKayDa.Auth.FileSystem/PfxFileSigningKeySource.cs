using System.Collections.Concurrent;
using System.Formats.Asn1;
using System.Security.Cryptography;
using System.Security.Cryptography.Pkcs;
using System.Security.Cryptography.X509Certificates;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using ZeeKayDa.Auth.Logging;
using ZeeKayDa.Auth.Tokens;

namespace ZeeKayDa.Auth.FileSystem;

/// <summary>
/// Lists the configured PFX/PKCS#12 bundles and signs in process with the one the ring chooses.
/// Listing decrypts no key bag; signing imports the paired key bag into an in-memory key, never an
/// OS-backed certificate. A key encrypted under weak parameters, or in a key bag with no encryption of
/// its own, is still used, since that is what a default Windows export produces, and warned about once
/// per version of the file.
/// </summary>
internal sealed class PfxFileSigningKeySource(
    IOptions<PfxFileSigningOptions> options,
    FileSigningKeyReader reader,
    SanitizingLogger<PfxFileSigningKeySource> logger) : ISigningKeySource
{
    private const string WeakKeyEncryptionCode = "signing.file_signing.weak_key_encryption";

    private readonly IOptions<PfxFileSigningOptions> _options = options;

    // Keyed by Path: the hash of the bundle whose key encryption was last judged.
    private readonly ConcurrentDictionary<string, byte[]> _judgedVersions = new(StringComparer.Ordinal);

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

    /// <summary>Imports the pair's key bag, rejecting a key whose type is not the certificate's.</summary>
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

    /// <summary>The signing certificate, read without decrypting a key bag; <see langword="null"/> when the file does not exist.</summary>
    private async ValueTask<X509Certificate2?> LoadPublicCertificateAsync(
        PfxFile file, CancellationToken cancellationToken)
    {
        if (await reader.TryReadAllBytesAsync(file.Path, cancellationToken).ConfigureAwait(false) is not { } bytes)
            return null;

        var password = await SigningFilePassword.ReadAsync(file.Path, file.PasswordSource, cancellationToken).ConfigureAwait(false);

        return OpenSigningPair(bytes, file.Path, password, pair =>
        {
            WarnOfWeakKeyEncryptionOncePerVersion(file.Path, bytes, pair.Key);
            return pair.Certificate.GetCertificate();
        });
    }

    /// <summary>Warns when the key bag is unshrouded, or shrouded under weaker parameters than PEM accepts; a refresh of the same file stays quiet.</summary>
    private void WarnOfWeakKeyEncryptionOncePerVersion(string path, byte[] bytes, Pkcs12SafeBag keyBag)
    {
        var version = SHA256.HashData(bytes);
        if (_judgedVersions.TryGetValue(path, out var judged) && judged.AsSpan().SequenceEqual(version))
            return;

        if (KeyBagWeaknessOf(keyBag) is { } weakness)
        {
            logger.LogWarning(
                "ZeeKayDa.Auth: {ErrorCode}: the private key in PFX file '{Path}' {Weakness}. It is still used. " +
                "Re-export the bundle under PBES2 with AES and PBKDF2 at {MinimumIterations} or more iterations: " +
                "OpenSSL 3's 'openssl pkcs12 -export' does by default, as does Export-PfxCertificate " +
                "-CryptoAlgorithmOption AES256_SHA256.",
                WeakKeyEncryptionCode, path, weakness, KeyEncryptionStrength.MinimumIterations);
        }

        _judgedVersions[path] = version;
    }

    /// <summary>How the key bag's protection falls short, or <see langword="null"/> when it is shrouded strongly enough.</summary>
    private static string? KeyBagWeaknessOf(Pkcs12SafeBag keyBag)
    {
        if (keyBag is not Pkcs12ShroudedKeyBag shrouded)
            return "is stored in a key bag with no encryption of its own";

        return KeyEncryptionStrength.WeaknessOf(shrouded.EncryptedPkcs8PrivateKey) is { } weakness
            ? $"is encrypted with {weakness}, which is brute-forceable offline from a copy of the file"
            : null;
    }

    /// <summary>
    /// Authenticates the bundle and hands its signing pair to <paramref name="use"/>. Listing and
    /// signing both go through here, so they cannot disagree about which key a bundle signs with.
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
            // skipCopy: `bytes` is this call's own buffer and is never mutated.
            var info = Pkcs12Info.Decode(bytes, out _, skipCopy: true);

            VerifyIntegrity(info, path, password);

            return use(SelectSigningPair(info, path, password));
        }
        catch (Exception ex) when (ex is CryptographicException or AsnContentException or InvalidOperationException)
        {
            // Never ex.Message: a failure message is not redacted, so the cause travels as the inner exception.
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
    /// Rejects a bundle with no password MAC, or one that does not verify. Without it, a certificate in
    /// an unencrypted safe is read under any password, so a substituted file would be published.
    /// </summary>
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
    /// The signing certificate and its key bag, paired on <c>localKeyId</c>: a bundle carries chain
    /// certificates in no guaranteed order, so the first certificate is not necessarily the signing one.
    /// </summary>
    private static SigningPair SelectSigningPair(Pkcs12Info info, string path, string password)
    {
        var (certBags, keyBags) = ReadBags(info, path, password);

        if (certBags.Count == 0)
        {
            throw InvalidPfx(path,
                "contains no certificate. Verify the file is a complete PKCS#12 bundle carrying both " +
                "a certificate and its private key");
        }

        // Here, not when first chosen to sign, which may be long after deployment.
        if (keyBags.Count == 0)
        {
            throw InvalidPfx(path,
                "carries no private key. Every listed bundle must carry one, because any of them may " +
                "be chosen to sign");
        }

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

            // Decrypts the safe, not the shrouded key bag inside it.
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

        // The key's certificate is not in the bundle: only a lone certificate and key are unambiguous.
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

    /// <summary>Builds the shared <c>invalid_pfx</c> failure.</summary>
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
