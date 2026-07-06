using System.Security.Cryptography.X509Certificates;
using ZeeKayDa.Auth.Windows.Tests.Fixtures;

namespace ZeeKayDa.Auth.Windows.Tests.Fakes;

/// <summary>
/// Hand-rolled <see cref="ICertificateStoreReader"/> test double. Stores one certificate per
/// (normalized) thumbprint and hands back a fresh, independent copy on every call — matching what
/// the real <see cref="CertificateStoreReader"/> does — so the caller's disposal of a returned
/// instance never invalidates what the fake holds, and the same thumbprint can be loaded more than
/// once across a test without a shared-instance-disposed-twice hazard.
/// </summary>
internal sealed class FakeCertificateStoreReader : ICertificateStoreReader
{
    private readonly Dictionary<string, X509Certificate2> _certificates = new(StringComparer.Ordinal);

    /// <summary>Every thumbprint passed to <see cref="GetCertificate"/>, in call order.</summary>
    public List<string> Calls { get; } = [];

    /// <summary>When set, <see cref="GetCertificate"/> throws this instead of returning a certificate.</summary>
    public Exception? ExceptionToThrow { get; set; }

    public void AddCertificate(string thumbprint, X509Certificate2 certificate) =>
        _certificates[ThumbprintFormat.Normalize(thumbprint)] = certificate;

    public X509Certificate2 GetCertificate(string normalizedThumbprint, StoreLocation storeLocation, StoreName storeName)
    {
        Calls.Add(normalizedThumbprint);

        if (ExceptionToThrow is not null)
            throw ExceptionToThrow;

        if (!_certificates.TryGetValue(normalizedThumbprint, out var certificate))
        {
            throw new ZeeKayDaConfigurationException(new ZeeKayDaConfigurationFailure(
                "signing.windows_certificate_store.certificate_not_found",
                $"Simulated missing certificate '{normalizedThumbprint}' in '{storeName}'/'{storeLocation}'."));
        }

        return TestCertificateFactory.Copy(certificate);
    }
}
