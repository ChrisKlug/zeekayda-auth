using System.Security.Cryptography.X509Certificates;
using Microsoft.Extensions.Options;
using ZeeKayDa.Auth.Tokens;

namespace ZeeKayDa.Auth.Windows;

/// <summary>
/// An <see cref="ISigningKeySource"/> that lists the certificates in
/// <see cref="WindowsCertificateStoreSigningOptions.Certificates"/> from a Windows Certificate Store
/// and signs locally, in process, with whichever of them the framework chooses, through its CNG/CAPI
/// private-key handle.
/// </summary>
/// <remarks>
/// <para>
/// <b>Listing extracts no private-key handle, but cannot keep the private key out of reach.</b>
/// Opening a store entry hands back the certificate and its private-key association together — there
/// is no way to ask the store for the public half alone. <see cref="ReadAsync"/> reads each
/// certificate transiently, keeps only the exported public parameters, and disposes it at once.
/// <see cref="CreateSignerAsync"/> is the only place a private-key handle is extracted.
/// </para>
/// <para>
/// This source performs no algorithm/key-type check and no pairing check of its own.
/// <see cref="SigningKeySetBuilder"/> validates every reported key, keyed on the source id — which
/// here is the certificate's thumbprint — and the ring's self-test checks the pairing.
/// </para>
/// </remarks>
internal sealed class WindowsCertificateStoreSigningKeySource(
    IOptions<WindowsCertificateStoreSigningOptions> options,
    ICertificateStoreReader storeReader,
    ICertificateKeyExtractor keyExtractor) : ISigningKeySource
{
    private readonly IOptions<WindowsCertificateStoreSigningOptions> _options = options;

    /// <inheritdoc/>
    public SigningAlgorithm Algorithm => _options.Value.Algorithm;

    /// <inheritdoc/>
    public Task<SourceKeyListing> ReadAsync(CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();

        var options = _options.Value;
        var keys = new List<SourceKey>(options.Certificates.Count);
        var failures = new List<SourceKeyFailure>();
        foreach (var lookup in options.Certificates)
        {
            // Outside the per-entry catch: a store that cannot be opened fails the whole read.
            // A certificate removed from the store is no longer listed: removing it revokes the key.
            using var certificate = storeReader.FindCertificate(lookup.NormalizedThumbprint, options.StoreLocation, options.StoreName);
            if (certificate is null)
                continue;

            var id = new SourceKeyId(lookup.NormalizedThumbprint);
            try
            {
                keys.Add(ListedKey(certificate, id));
            }
            catch (ZeeKayDaConfigurationException ex)
            {
                failures.Add(new SourceKeyFailure(id, ex.AggregatedFailures[0]));
            }
        }

        return Task.FromResult(new SourceKeyListing(keys, failures));
    }

    /// <summary>
    /// Checks without extracting a handle that <paramref name="certificate"/> can sign: any listed
    /// certificate may be chosen to, so one that cannot fails now rather than at the restart that chooses it.
    /// </summary>
    private static SourceKey ListedKey(X509Certificate2 certificate, SourceKeyId id) =>
        certificate.HasPrivateKey
            ? SourceKey.FromCertificate(certificate, id)
            : throw WindowsCertificateKeyExtractor.NoPrivateKey(id.Value);

    /// <inheritdoc/>
    /// <remarks>
    /// Every step here is synchronous, so failures throw at the call site rather than through the
    /// returned task. The ring awaits this call immediately, so the two are indistinguishable to it.
    /// </remarks>
    public Task<ISigner> CreateSignerAsync(SourceKeyId id, CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();

        var options = _options.Value;
        var lookup = options.Certificates.FirstOrDefault(l => string.Equals(l.NormalizedThumbprint, id.Value, StringComparison.Ordinal))
            ?? throw new InvalidOperationException(
                $"{nameof(CreateSignerAsync)} was called for key '{id.Value}', which is not a listed certificate.");

        using var certificate = storeReader.FindCertificate(lookup.NormalizedThumbprint, options.StoreLocation, options.StoreName)
            ?? throw new ZeeKayDaConfigurationException(new ZeeKayDaConfigurationFailure(
                "signing.windows_certificate_store.certificate_not_found",
                $"No certificate with thumbprint '{lookup.NormalizedThumbprint}' was found in the '{options.StoreName}' " +
                $"store at '{options.StoreLocation}'. Verify the thumbprint and that the certificate has been " +
                "installed into this exact store/location combination."));

        // Not LocalSigner.FromCertificate: this extractor explains an inaccessible key in terms of the
        // process identity and the store's key ACL.
        var (privateKey, _) = keyExtractor.ExtractPrivateKey(certificate, lookup.NormalizedThumbprint);

        return Task.FromResult<ISigner>(new LocalSigner(options.Algorithm, privateKey));
    }
}
