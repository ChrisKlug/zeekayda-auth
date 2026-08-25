using System.Formats.Asn1;
using System.Security.Cryptography;
using System.Security.Cryptography.Pkcs;
using System.Security.Cryptography.X509Certificates;
using Microsoft.Extensions.Options;
using ZeeKayDa.Auth.Tokens;

namespace ZeeKayDa.Auth.FileSystem;

/// <summary>
/// An <see cref="ISigningKeySource"/> that reads the PFX/PKCS#12 bundles configured into
/// <see cref="PfxFileSigningOptions"/>'s three slots and signs locally, in process, with
/// <see cref="PfxFileSigningOptions.Current"/>'s private key.
/// </summary>
/// <remarks>
/// <para>
/// Read once, never re-read: the slots are fixed at configuration time and the ring reads this
/// source exactly once at startup. Picking up a replaced or rotated-in bundle requires a restart.
/// </para>
/// <para>
/// <b>A published-only slot's private key is never imported into a key object.</b> PKCS#12 is a
/// bundled format, so keeping non-active private material out of reach cannot be enforced by the
/// framework and is this provider's own obligation. <see cref="ReadAsync"/> discharges it by walking
/// the bundle with <see cref="Pkcs12Info"/>: the password authenticates the file and decrypts the
/// authenticated safe, the certificate bag is read, and no key bag is ever decrypted or imported.
/// <c>X509CertificateLoader.LoadPkcs12</c>, which would import one, is reached only from
/// <see cref="CreateSignerAsync"/>, only for <c>Current</c>. That holds on every platform, and is
/// what makes the transient key-container residue this provider used to risk unreachable for
/// <c>Previous</c> and <c>Next</c> rather than merely narrowed. One residue remains and is inherent
/// to the format: an <i>unshrouded</i> key bag is plaintext PKCS#8 inside the safe, so decrypting the
/// safe puts those bytes in managed memory. They are never read and never imported.
/// </para>
/// <para>
/// This source performs no algorithm/key-type check of its own.
/// <see cref="SigningKeySetBuilder"/> validates every reported key's algorithm against its key type
/// and EC curve, keyed on the source id — which here is the configured file path, so its failures
/// still name the offending bundle.
/// </para>
/// </remarks>
internal sealed class PfxFileSigningKeySource : ISigningKeySource
{
    private readonly IOptions<PfxFileSigningOptions> _options;
    private readonly FileSigningKeyReader _reader;

    // Serialises reads so the slots are parsed exactly once even if two callers read concurrently —
    // "only the ring calls this" is not something this type can enforce. Deliberately not disposed:
    // disposing it would make a read already in flight at shutdown throw from its own Release, and
    // would strand any reader queued behind it.
    private readonly SemaphoreSlim _readGate = new(1, 1);

    // The one key set this source ever reports. Assigned only once every slot has been read and
    // validated, so a failed read is never cached and a retry re-reads from disk; once a read has
    // succeeded, no later one can observe a bundle replaced after startup. Read-once is therefore a
    // property of this source, not only of the ring.
    private SourceKeySet? _keySet;

    public PfxFileSigningKeySource(IOptions<PfxFileSigningOptions> options, FileSigningKeyReader reader)
    {
        ArgumentNullException.ThrowIfNull(options);
        ArgumentNullException.ThrowIfNull(reader);

        _options = options;
        _reader = reader;
    }

    /// <inheritdoc/>
    public async ValueTask<SourceKeySet> ReadAsync(CancellationToken cancellationToken = default)
    {
        await _readGate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            if (_keySet is not null)
                return _keySet;

            var options = _options.Value;

            var previous = await ReadSlotAsync(options.Previous, options.Algorithm, cancellationToken).ConfigureAwait(false);
            var current = await ReadSlotAsync(options.Current, options.Algorithm, cancellationToken).ConfigureAwait(false);
            var next = await ReadSlotAsync(options.Next, options.Algorithm, cancellationToken).ConfigureAwait(false);

            return _keySet = SourceKeySet.Create(previous, current, next);
        }
        finally
        {
            _readGate.Release();
        }
    }

    /// <inheritdoc/>
    public async ValueTask<ISigner> CreateSignerAsync(SourceKeyId id, CancellationToken cancellationToken = default)
    {
        var options = _options.Value;
        var current = options.Current;

        // Only Current is ever openable for signing. Previous and Next are published, never signed
        // with, so an id naming either of them is a defect in the caller rather than a request this
        // source should honour by decrypting a key bag it otherwise never touches.
        if (current is null || !string.Equals(current.Path, id.Value, StringComparison.Ordinal))
        {
            throw new InvalidOperationException(
                $"{nameof(CreateSignerAsync)} was called for key '{id.Value}', which is not the " +
                $"configured {nameof(PfxFileSigningOptions.Current)} PFX file. This source reads its " +
                "slots exactly once, so they must not change after startup, and only Current ever " +
                "signs.");
        }

        // The one call in this type that materialises a private key.
        using var certificate = await LoadSigningCertificateAsync(current, cancellationToken).ConfigureAwait(false);
        var (privateKey, _) = FileSigningKeyExtractor.ExtractPrivateKey(certificate, current.Path);

        return new LocalSigner(options.Algorithm, privateKey);
    }

    private async ValueTask<SourceKey?> ReadSlotAsync(
        PfxFile? slot, SigningAlgorithm algorithm, CancellationToken cancellationToken)
    {
        if (slot is null)
            return null;

        using var certificate = await LoadPublicCertificateAsync(slot, cancellationToken).ConfigureAwait(false);

        return FileSigningKeyExtractor.ToSourceKey(certificate, slot.Path, algorithm);
    }

    /// <summary>
    /// Reads the signing certificate out of the PKCS#12 bundle at <paramref name="slot"/> without
    /// decrypting its key bag, so no private key is imported into a key object for any slot —
    /// including <c>Current</c>, whose private key is loaded separately and only when its signer is
    /// opened.
    /// </summary>
    /// <exception cref="ZeeKayDaConfigurationException">
    /// The file is not a valid PKCS#12 bundle, is not MAC-protected, fails its integrity check
    /// (wrong password or tampering), uses an unsupported confidentiality mode, or does not identify
    /// exactly one signing certificate.
    /// </exception>
    private async ValueTask<X509Certificate2> LoadPublicCertificateAsync(
        PfxFile slot, CancellationToken cancellationToken)
    {
        var bytes = await _reader.ReadAllBytesAsync(slot.Path, cancellationToken).ConfigureAwait(false);
        var password = await slot.PasswordSource(cancellationToken).ConfigureAwait(false);

        try
        {
            // skipCopy: the returned Pkcs12Info reads directly out of `bytes`, which is a freshly
            // allocated array owned by this method and alive for the whole of it. The certificate
            // returned below carries its own copy of the DER, so nothing outlives the buffer.
            var info = Pkcs12Info.Decode(bytes, out _, skipCopy: true);

            VerifyIntegrity(info, slot.Path, password);

            return SelectSigningCertificate(info, slot.Path, password);
        }
        catch (Exception ex) when (ex is CryptographicException or AsnContentException or InvalidOperationException)
        {
            // ex.Message comes from the BCL PKCS#12 parser and never echoes the supplied password.
            throw InvalidPfx(slot.Path, $"could not be loaded: {ex.Message}. Verify the file is a " +
                "valid PKCS#12 bundle and that the configured password is correct");
        }
    }

    /// <summary>
    /// Rejects a bundle whose MAC does not verify under the configured password, and one carrying no
    /// password MAC at all.
    /// </summary>
    /// <remarks>
    /// Without this, the password is not a control at all on this path: a bundle whose certificate
    /// sits in an unencrypted safe is never asked for one, so any password — and any substituted
    /// file — would be accepted. Since <c>Previous</c> and <c>Next</c> are published but never
    /// signed with, the ring's own self-test would not catch it either: their public keys would
    /// simply appear in the JWKS as valid verification keys. This is the check that makes the
    /// password the defense-in-depth the registration documents it as.
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
    /// Returns the certificate paired with the bundle's private key, decrypting each safe but never
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
    private static X509Certificate2 SelectSigningCertificate(Pkcs12Info info, string path, string password)
    {
        var certBags = new List<Pkcs12CertBag>();
        var keyLocalIds = new List<ReadOnlyMemory<byte>>();

        foreach (var safe in info.AuthenticatedSafe)
        {
            switch (safe.ConfidentialityMode)
            {
                case Pkcs12ConfidentialityMode.None:
                    break;

                // Decrypts the safe, not the key bag. A password-protected safe must be opened to
                // reach the certificate at all; the shrouded key bag inside it stays encrypted
                // because nothing here ever calls Decrypt on it.
                case Pkcs12ConfidentialityMode.Password:
                    safe.Decrypt(password);
                    break;

                default:
                    throw InvalidPfx(path,
                        $"uses the unsupported confidentiality mode '{safe.ConfidentialityMode}'. " +
                        "Only unencrypted and password-encrypted PKCS#12 safes are supported");
            }

            foreach (var bag in safe.GetBags())
            {
                switch (bag)
                {
                    case Pkcs12CertBag certBag:
                        certBags.Add(certBag);
                        break;

                    // Recorded for pairing only. Neither is decrypted or imported.
                    case Pkcs12KeyBag:
                    case Pkcs12ShroudedKeyBag:
                        if (LocalKeyIdOf(bag) is { } keyId)
                            keyLocalIds.Add(keyId);
                        break;
                }
            }
        }

        if (certBags.Count == 0)
        {
            throw InvalidPfx(path,
                "contains no certificate. Verify the file is a complete PKCS#12 bundle carrying both " +
                "a certificate and its private key");
        }

        // The normal case for any bundle carrying a chain: pair on localKeyId.
        if (keyLocalIds.Count > 0)
        {
            var paired = certBags
                .Where(certBag => LocalKeyIdOf(certBag) is { } certId
                    && keyLocalIds.Any(keyId => keyId.Span.SequenceEqual(certId.Span)))
                .ToList();

            if (paired.Count == 1)
                return paired[0].GetCertificate();

            if (paired.Count > 1)
            {
                throw InvalidPfx(path,
                    $"identifies {paired.Count} certificates as belonging to a private key, so which " +
                    "one signs is ambiguous. Export a bundle carrying a single signing certificate " +
                    "and its key");
            }

            // A private key whose certificate is not in the bundle. A lone certificate is still
            // unambiguous; anything else is a bundle that cannot say what it signs with.
            if (certBags.Count == 1)
                return certBags[0].GetCertificate();

            throw InvalidPfx(path,
                "names a private key whose certificate is not among the certificates it carries, so " +
                "which one signs cannot be determined. Re-export the bundle from the keypair it is " +
                "meant to hold");
        }

        if (certBags.Count == 1)
            return certBags[0].GetCertificate();

        // No key bag at all — a published-only bundle with its private key stripped, which is the
        // right shape for a Previous or Next slot. A chain comes with it, so fall back to the one
        // certificate the exporter marked as the subject of the keypair.
        var identified = certBags.Where(certBag => LocalKeyIdOf(certBag) is not null).ToList();

        if (identified.Count == 1)
            return identified[0].GetCertificate();

        throw InvalidPfx(path,
            $"contains {certBags.Count} certificates with nothing identifying which one signs. " +
            "PKCS#12 pairs a certificate with its key through a localKeyId attribute; re-export the " +
            "bundle with a tool that sets one, or supply a bundle holding a single certificate");
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

    private static ZeeKayDaConfigurationException InvalidPfx(string path, string problem) =>
        new(new ZeeKayDaConfigurationFailure(
            "signing.file_signing.invalid_pfx",
            $"The PFX/PKCS#12 file at '{path}' {problem}."));

    /// <summary>
    /// Loads the bundle at <paramref name="slot"/> with its private key. Used only by
    /// <see cref="CreateSignerAsync"/>, for the <c>Current</c> slot.
    /// </summary>
    /// <remarks>
    /// The returned certificate carries its private key, so the caller must dispose it as soon as the
    /// handle has been extracted — <see cref="FileSigningKeyExtractor.ExtractPrivateKey"/> returns a
    /// handle that outlives the certificate, and ownership transfers to the
    /// <see cref="LocalSigner"/> built over it.
    /// </remarks>
    /// <exception cref="ZeeKayDaConfigurationException">
    /// The file is not a valid PKCS#12 bundle, or the configured password is incorrect.
    /// </exception>
    private async ValueTask<X509Certificate2> LoadSigningCertificateAsync(
        PfxFile slot, CancellationToken cancellationToken)
    {
        var bytes = await _reader.ReadAllBytesAsync(slot.Path, cancellationToken).ConfigureAwait(false);
        var password = await slot.PasswordSource(cancellationToken).ConfigureAwait(false);

        try
        {
            return X509CertificateLoader.LoadPkcs12(bytes, password);
        }
        catch (CryptographicException ex)
        {
            throw InvalidPfx(slot.Path, $"could not be loaded: {ex.Message}. Verify the file is a " +
                "valid PKCS#12 bundle and that the configured password is correct");
        }
    }
}
