using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Microsoft.Extensions.Options;
using ZeeKayDa.Auth.Tokens;

namespace ZeeKayDa.Auth.Windows;

/// <summary>
/// An <see cref="ISigningKeySource"/> that reads the certificates configured into
/// <see cref="WindowsCertificateStoreSigningOptions"/>'s three slots from a Windows Certificate
/// Store and signs locally, in process, with <see cref="WindowsCertificateStoreSigningOptions.Current"/>'s
/// CNG/CAPI private-key handle.
/// </summary>
/// <remarks>
/// <para>
/// Read once, never re-read: the slots are fixed at configuration time and the ring reads this
/// source exactly once at startup. Picking up a rotated-in, removed, or replaced certificate
/// requires a restart.
/// </para>
/// <para>
/// <b>What this source guarantees about a published-only slot's private key is an access-path
/// property, not a materialisation one.</b> Opening a store entry hands back the certificate and its
/// private-key association together — there is no way to ask the store for the public half alone —
/// so a <c>Previous</c> or <c>Next</c> private key is briefly reachable through the certificate
/// object whether or not anything asks for it. That is a property of the platform, and this source
/// cannot change it. What it does guarantee is that no code path extracts a private-key handle for
/// any slot during <see cref="ReadAsync"/>: each slot's certificate is read transiently, only the
/// exported public parameters are retained, and the certificate is disposed immediately, releasing
/// the association. <see cref="CreateSignerAsync"/> is the only place private material is extracted,
/// and it rejects any id that is not <c>Current</c>.
/// </para>
/// <para>
/// The distinction matters when comparing this provider to the PEM one, whose published-only slots
/// take a certificate-only file: there, a published slot's private key is physically absent from the
/// process, which is a strictly stronger property than the one stated above. Do not read the two as
/// equivalent.
/// </para>
/// <para>
/// Uses only <see cref="WindowsCertificateKeyExtractor.ExtractPublicKey"/>/
/// <see cref="WindowsCertificateKeyExtractor.ExtractPrivateKey"/> — never <c>.PrivateKey</c> or
/// <c>ExportParameters(true)</c> — preferring CNG/CAPI-backed handles over exporting raw key bytes.
/// </para>
/// <para>
/// This source performs no algorithm/key-type check and no private/public pairing check of its own.
/// <see cref="SigningKeySetBuilder"/> validates every reported key's algorithm against its key type
/// and EC curve, keyed on the source id — which here is the certificate's thumbprint, so its
/// failures still name the offending certificate — and the ring's per-handoff self-test is the only
/// pairing check.
/// </para>
/// </remarks>
internal sealed class WindowsCertificateStoreSigningKeySource : ISigningKeySource
{
    private readonly IOptions<WindowsCertificateStoreSigningOptions> _options;
    private readonly ICertificateStoreReader _storeReader;
    private readonly ICertificateKeyExtractor _keyExtractor;

    // Guards the memoized read so the slots are read exactly once even if two callers read
    // concurrently — "only the ring calls this" is not something this type can enforce. A plain
    // lock rather than the sibling PEM source's SemaphoreSlim because every step of a store read is
    // synchronous, so there is nothing to await while holding it.
    private readonly Lock _readLock = new();

    // The one key set this source ever reports. Memoized so a second read cannot observe a
    // certificate removed or replaced after startup — read-once is a property of this source, not
    // only of the ring.
    private SourceKeySet? _keySet;

    public WindowsCertificateStoreSigningKeySource(
        IOptions<WindowsCertificateStoreSigningOptions> options,
        ICertificateStoreReader storeReader,
        ICertificateKeyExtractor keyExtractor)
    {
        ArgumentNullException.ThrowIfNull(options);
        ArgumentNullException.ThrowIfNull(storeReader);
        ArgumentNullException.ThrowIfNull(keyExtractor);

        _options = options;
        _storeReader = storeReader;
        _keyExtractor = keyExtractor;
    }

    /// <inheritdoc/>
    public ValueTask<SourceKeySet> ReadAsync(CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();

        var options = _options.Value;

        lock (_readLock)
        {
            if (_keySet is not null)
                return new ValueTask<SourceKeySet>(_keySet);

            var previous = ReadSlot(options.Previous, options);
            var current = ReadSlot(options.Current, options);
            var next = ReadSlot(options.Next, options);

            _keySet = SourceKeySet.Create(previous, current, next);
            return new ValueTask<SourceKeySet>(_keySet);
        }
    }

    /// <inheritdoc/>
    /// <remarks>
    /// Every step here is synchronous, so failures throw at the call site rather than through the
    /// returned task. The ring awaits this call immediately, so the two are indistinguishable to it.
    /// </remarks>
    public ValueTask<ISigner> CreateSignerAsync(SourceKeyId id, CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();

        var options = _options.Value;
        var current = options.Current;

        // Only Current is ever openable for signing. Previous and Next are published, never signed
        // with, so an id naming either of them is a defect in the caller rather than a request this
        // source should honour by opening a private key it otherwise never touches.
        if (current is null || !string.Equals(current.NormalizedThumbprint, id.Value, StringComparison.Ordinal))
        {
            throw new InvalidOperationException(
                $"{nameof(CreateSignerAsync)} was called for key '{id.Value}', which is not the " +
                $"configured {nameof(WindowsCertificateStoreSigningOptions.Current)} certificate. This " +
                "source reads its slots exactly once, so they must not change after startup, and only " +
                "Current ever signs.");
        }

        using var certificate = _storeReader.GetCertificate(current.NormalizedThumbprint, options.StoreLocation, options.StoreName);

        // Private/public key pairing is verified by the ring's per-handoff self-test, not here.
        var (privateKey, _) = _keyExtractor.ExtractPrivateKey(certificate, current.NormalizedThumbprint);

        return new ValueTask<ISigner>(new LocalSigner(options.Algorithm, privateKey));
    }

    /// <summary>
    /// Reads one slot's certificate for its public material alone. Private material is released the
    /// moment the certificate is disposed at the end of this method; only the exported public
    /// parameters survive into the returned <see cref="SourceKey"/>.
    /// </summary>
    private SourceKey? ReadSlot(CertificateLookup? lookup, WindowsCertificateStoreSigningOptions options)
    {
        if (lookup is null)
            return null;

        using var certificate = _storeReader.GetCertificate(lookup.NormalizedThumbprint, options.StoreLocation, options.StoreName);

        var (rawPublicKey, keyType) = _keyExtractor.ExtractPublicKey(certificate, lookup.NormalizedThumbprint);
        using var publicKey = rawPublicKey;

        // X509Certificate2 reports both ends of the validity window as local-kind DateTime, so the
        // conversion below applies the local offset rather than reinterpreting them as UTC.
        return new SourceKey(
            new SourceKeyId(lookup.NormalizedThumbprint),
            options.Algorithm,
            ToPublicKeyParameters(publicKey, keyType),
            ExpiresAt: new DateTimeOffset(certificate.NotAfter),
            NotBefore: new DateTimeOffset(certificate.NotBefore));
    }

    /// <summary>
    /// Exports <paramref name="publicKey"/>'s public parameters. The cast is safe:
    /// <see cref="ICertificateKeyExtractor.ExtractPublicKey"/> only ever returns an
    /// <see cref="RSA"/> paired with <see cref="SigningKeyType.Rsa"/> or an <see cref="ECDsa"/>
    /// paired with <see cref="SigningKeyType.Ec"/>.
    /// </summary>
    private static PublicKeyParameters ToPublicKeyParameters(AsymmetricAlgorithm publicKey, SigningKeyType keyType) =>
        keyType == SigningKeyType.Rsa
            ? PublicKeyParameters.FromRsa(((RSA)publicKey).ExportParameters(false))
            : PublicKeyParameters.FromEc(((ECDsa)publicKey).ExportParameters(false));
}
