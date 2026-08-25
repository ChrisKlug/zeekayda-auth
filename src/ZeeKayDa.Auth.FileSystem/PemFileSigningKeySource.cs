using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Microsoft.Extensions.Options;
using ZeeKayDa.Auth.Tokens;

namespace ZeeKayDa.Auth.FileSystem;

/// <summary>
/// An <see cref="ISigningKeySource"/> that reads the PEM certificates configured into
/// <see cref="PemFileSigningOptions"/>'s three slots and signs locally, in process, with
/// <see cref="PemFileSigningOptions.Current"/>'s private key.
/// </summary>
/// <remarks>
/// <para>
/// Read once, never re-read: the slots are fixed at configuration time and the ring reads this
/// source exactly once at startup. Picking up a replaced or rotated-in file requires a restart.
/// </para>
/// <para>
/// <see cref="ReadAsync"/> parses only each slot's certificate — no private key material is read
/// for any slot. Only <see cref="CreateSignerAsync"/> reads private material, and only for
/// <see cref="PemFileSigningOptions.Current"/>, so a <c>Previous</c> or <c>Next</c> private key is
/// never loaded into this process at all.
/// </para>
/// <para>
/// This source performs no algorithm/key-type check of its own.
/// <see cref="SigningKeySetBuilder"/> validates every reported key's algorithm against its key type
/// and EC curve, keyed on the source id — which here is the configured file path, so its failures
/// still name the offending file.
/// </para>
/// </remarks>
internal sealed class PemFileSigningKeySource : ISigningKeySource
{
    private readonly IOptions<PemFileSigningOptions> _options;
    private readonly FileSigningKeyReader _reader;

    // Serialises reads so the slots are parsed exactly once even if two callers read concurrently —
    // "only the ring calls this" is not something this type can enforce. Deliberately not disposed:
    // disposing it would make a read already in flight at shutdown throw from its own Release, and
    // would strand any reader queued behind it.
    private readonly SemaphoreSlim _readGate = new(1, 1);

    // The one key set this source ever reports. Memoized so a second read cannot observe a file
    // replaced after startup — read-once is a property of this source, not only of the ring.
    private SourceKeySet? _keySet;

    public PemFileSigningKeySource(IOptions<PemFileSigningOptions> options, FileSigningKeyReader reader)
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

            // Every slot is read by certificate path alone. Previous and Next have no private-key
            // path to pass even in principle, and Current's is deliberately not passed here.
            var previous = await ReadSlotAsync(options.Previous?.Path, options.Algorithm, cancellationToken).ConfigureAwait(false);
            var current = await ReadSlotAsync(options.Current?.Path, options.Algorithm, cancellationToken).ConfigureAwait(false);
            var next = await ReadSlotAsync(options.Next?.Path, options.Algorithm, cancellationToken).ConfigureAwait(false);

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
        // source should honour by reading a private key it otherwise never touches.
        if (current is null || !string.Equals(current.Path, id.Value, StringComparison.Ordinal))
        {
            throw new InvalidOperationException(
                $"{nameof(CreateSignerAsync)} was called for key '{id.Value}', which is not the " +
                $"configured {nameof(PemFileSigningOptions.Current)} PEM file. This source reads its " +
                "slots exactly once, so they must not change after startup, and only Current ever " +
                "signs.");
        }

        using var certificate = await LoadSigningCertificateAsync(current, cancellationToken).ConfigureAwait(false);
        var (privateKey, _) = FileSigningKeyExtractor.ExtractPrivateKey(certificate, current.Path);

        return new LocalSigner(options.Algorithm, privateKey);
    }

    private async ValueTask<SourceKey?> ReadSlotAsync(
        string? certificatePath, SigningAlgorithm algorithm, CancellationToken cancellationToken)
    {
        if (certificatePath is null)
            return null;

        using var certificate = await LoadPublicCertificateAsync(certificatePath, cancellationToken).ConfigureAwait(false);

        var (rawPublicKey, keyType) = FileSigningKeyExtractor.ExtractPublicKey(certificate, certificatePath);
        using var publicKey = rawPublicKey;

        // X509Certificate2 reports both ends of the validity window as local-kind DateTime, so the
        // conversion below applies the local offset rather than reinterpreting them as UTC.
        return new SourceKey(
            new SourceKeyId(certificatePath),
            algorithm,
            ToPublicKeyParameters(publicKey, keyType),
            ExpiresAt: new DateTimeOffset(certificate.NotAfter),
            NotBefore: new DateTimeOffset(certificate.NotBefore));
    }

    /// <summary>
    /// Exports <paramref name="publicKey"/>'s public parameters. The cast is safe:
    /// <see cref="FileSigningKeyExtractor.ExtractPublicKey"/> only ever returns an
    /// <see cref="RSA"/> paired with <see cref="SigningKeyType.Rsa"/> or an <see cref="ECDsa"/>
    /// paired with <see cref="SigningKeyType.Ec"/>.
    /// </summary>
    private static PublicKeyParameters ToPublicKeyParameters(AsymmetricAlgorithm publicKey, SigningKeyType keyType) =>
        keyType == SigningKeyType.Rsa
            ? PublicKeyParameters.FromRsa(((RSA)publicKey).ExportParameters(false))
            : PublicKeyParameters.FromEc(((ECDsa)publicKey).ExportParameters(false));

    /// <summary>
    /// Parses only the certificate at <paramref name="certificatePath"/> — no private key material is
    /// ever read or parsed, including for the <c>Current</c> slot.
    /// </summary>
    /// <exception cref="ZeeKayDaConfigurationException">
    /// The file does not contain a valid PEM-encoded certificate.
    /// </exception>
    private async ValueTask<X509Certificate2> LoadPublicCertificateAsync(
        string certificatePath, CancellationToken cancellationToken)
    {
        var certPem = await _reader.ReadPemTextAsync(certificatePath, cancellationToken).ConfigureAwait(false);

        try
        {
            return X509Certificate2.CreateFromPem(certPem);
        }
        catch (Exception ex) when (ex is CryptographicException or ArgumentException or FormatException)
        {
            throw new ZeeKayDaConfigurationException(new ZeeKayDaConfigurationFailure(
                "signing.file_signing.invalid_pem",
                $"The file at '{certificatePath}' does not contain a valid PEM-encoded certificate: {ex.Message}"));
        }
    }

    /// <summary>
    /// Parses the certificate and private key at <paramref name="slot"/>. Used only by
    /// <see cref="CreateSignerAsync"/>, for the <c>Current</c> slot.
    /// </summary>
    /// <exception cref="ZeeKayDaConfigurationException">
    /// The file(s) do not contain a valid PEM-encoded certificate and private key.
    /// </exception>
    private async ValueTask<X509Certificate2> LoadSigningCertificateAsync(
        PemSigningFile slot, CancellationToken cancellationToken)
    {
        // Reads through FileSigningKeyReader.ReadPemTextAsync and calls X509Certificate2.CreateFromPem
        // rather than X509Certificate2.CreateFromPemFile, which performs its own unvalidated file I/O
        // and would bypass FileSigningKeyReader's permission/symlink validation.
        var certPem = await _reader.ReadPemTextAsync(slot.Path, cancellationToken).ConfigureAwait(false);

        // With no separate key path, the combined file carries both PEM blocks, so the same text is
        // passed for both the certificate and the key source.
        var keyPem = slot.KeyPath is null
            ? certPem
            : await _reader.ReadPemTextAsync(slot.KeyPath, cancellationToken).ConfigureAwait(false);

        try
        {
            return X509Certificate2.CreateFromPem(certPem, keyPem);
        }
        catch (Exception ex) when (ex is CryptographicException or ArgumentException or FormatException)
        {
            var description = slot.KeyPath is null
                ? $"'{slot.Path}'"
                : $"certificate '{slot.Path}' / private key '{slot.KeyPath}'";

            throw new ZeeKayDaConfigurationException(new ZeeKayDaConfigurationFailure(
                "signing.file_signing.invalid_pem",
                $"The file(s) at {description} do not contain a valid PEM-encoded certificate and " +
                $"private key: {ex.Message}"));
        }
    }
}
