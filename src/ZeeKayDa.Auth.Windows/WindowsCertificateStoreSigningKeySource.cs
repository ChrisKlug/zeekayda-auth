using System.Security.Cryptography.X509Certificates;
using Microsoft.Extensions.Options;
using ZeeKayDa.Auth.Tokens;

namespace ZeeKayDa.Auth.Windows;

/// <summary>
/// Lists the configured certificates from a Windows Certificate Store and signs in process with the
/// one the ring chooses. Only <see cref="CreateSignerAsync"/> extracts a private-key handle.
/// </summary>
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

    /// <summary>Any listed certificate may be chosen to sign, so one without a private key fails now.</summary>
    private static SourceKey ListedKey(X509Certificate2 certificate, SourceKeyId id) =>
        certificate.HasPrivateKey
            ? SourceKey.FromCertificate(certificate, id)
            : throw WindowsCertificateKeyExtractor.NoPrivateKey(id.Value);

    /// <inheritdoc/>
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
