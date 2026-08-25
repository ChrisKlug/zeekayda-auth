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
/// <b>A published-only slot's private key is never decrypted.</b> PKCS#12 is a bundled format, so
/// keeping non-active private material out of memory cannot be enforced by the framework and is this
/// provider's own obligation. <see cref="ReadAsync"/> discharges it by walking the bundle with
/// <see cref="Pkcs12Info"/>: the password decrypts the authenticated safe, the certificate bag is
/// read, and the shrouded key bag is left untouched. Nothing materialises a private key —
/// <c>X509CertificateLoader.LoadPkcs12</c>, which would, is reached only from
/// <see cref="CreateSignerAsync"/>, only for <c>Current</c>. That holds on every platform, and is
/// what makes the transient key-container residue this provider used to risk unreachable for
/// <c>Previous</c> and <c>Next</c> rather than merely narrowed.
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

    // The one key set this source ever reports. Memoized so a second read cannot observe a bundle
    // replaced after startup — read-once is a property of this source, not only of the ring.
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
        PfxSigningFile? slot, SigningAlgorithm algorithm, CancellationToken cancellationToken)
    {
        if (slot is null)
            return null;

        using var certificate = await LoadPublicCertificateAsync(slot, cancellationToken).ConfigureAwait(false);

        return FileSigningKeyExtractor.ToSourceKey(certificate, slot.Path, algorithm);
    }

    /// <summary>
    /// Reads the certificate out of the PKCS#12 bundle at <paramref name="slot"/> without decrypting
    /// its key bag, so no private key is materialised for any slot — including <c>Current</c>, whose
    /// private key is loaded separately and only when its signer is opened.
    /// </summary>
    /// <exception cref="ZeeKayDaConfigurationException">
    /// The file is not a valid PKCS#12 bundle, the configured password is incorrect, or the bundle
    /// carries no certificate.
    /// </exception>
    private async ValueTask<X509Certificate2> LoadPublicCertificateAsync(
        PfxSigningFile slot, CancellationToken cancellationToken)
    {
        var bytes = await _reader.ReadAllBytesAsync(slot.Path, cancellationToken).ConfigureAwait(false);
        var password = await slot.PasswordSource(cancellationToken).ConfigureAwait(false);

        try
        {
            // skipCopy: the returned Pkcs12Info reads directly out of `bytes`, which is a freshly
            // allocated array owned by this method and alive for the whole of it. The certificate
            // returned below carries its own copy of the DER, so nothing outlives the buffer. Matches
            // KeyVaultCertificateReader's parsing of the same format.
            var info = Pkcs12Info.Decode(bytes, out _, skipCopy: true);

            foreach (var safe in info.AuthenticatedSafe)
            {
                // Decrypts the safe, not the key bag. A password-protected safe must be opened to
                // reach the certificate at all; the shrouded key bag inside it stays encrypted
                // because nothing below ever calls Decrypt on it.
                if (safe.ConfidentialityMode == Pkcs12ConfidentialityMode.Password)
                    safe.Decrypt(password);

                foreach (var bag in safe.GetBags())
                {
                    if (bag is Pkcs12CertBag certBag)
                        return certBag.GetCertificate();
                }
            }

            throw new ZeeKayDaConfigurationException(new ZeeKayDaConfigurationFailure(
                "signing.file_signing.invalid_pfx",
                $"The PFX/PKCS#12 file at '{slot.Path}' contains no certificate. Verify the file is a " +
                "complete PKCS#12 bundle carrying both a certificate and its private key."));
        }
        catch (Exception ex) when (ex is CryptographicException or AsnContentException)
        {
            // ex.Message comes from the BCL PKCS#12 parser and never echoes the supplied password.
            throw new ZeeKayDaConfigurationException(new ZeeKayDaConfigurationFailure(
                "signing.file_signing.invalid_pfx",
                $"The PFX/PKCS#12 file at '{slot.Path}' could not be loaded: {ex.Message}. Verify the " +
                "file is a valid PKCS#12 bundle and that the configured password is correct."));
        }
    }

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
        PfxSigningFile slot, CancellationToken cancellationToken)
    {
        var bytes = await _reader.ReadAllBytesAsync(slot.Path, cancellationToken).ConfigureAwait(false);
        var password = await slot.PasswordSource(cancellationToken).ConfigureAwait(false);

        try
        {
            return X509CertificateLoader.LoadPkcs12(bytes, password);
        }
        catch (CryptographicException ex)
        {
            throw new ZeeKayDaConfigurationException(new ZeeKayDaConfigurationFailure(
                "signing.file_signing.invalid_pfx",
                $"The PFX/PKCS#12 file at '{slot.Path}' could not be loaded: {ex.Message}. Verify the " +
                "file is a valid PKCS#12 bundle and that the configured password is correct."));
        }
    }
}
