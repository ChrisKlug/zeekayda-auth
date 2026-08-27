using Azure;
using Azure.Security.KeyVault.Certificates;

namespace ZeeKayDa.Auth.AzureKeyVault.Tests.Fakes;

/// <summary>
/// A <see cref="CertificateClient"/> built on the SDK's protected mocking constructor, so
/// <see cref="KeyVaultCertificateReader"/>'s SDK fault-mapping paths can be exercised without a
/// live vault. Configure either delegate to return SDK model objects (via
/// <see cref="CertificateModelFactory"/>) or to throw.
/// </summary>
internal sealed class FakeCertificateClient : CertificateClient
{
    public Func<AsyncPageable<CertificateProperties>>? OnGetVersions { get; init; }

    /// <summary>Receives the requested version; returns the certificate or throws.</summary>
    public Func<string, KeyVaultCertificate>? OnGetVersion { get; init; }

    public override AsyncPageable<CertificateProperties> GetPropertiesOfCertificateVersionsAsync(
        string certificateName, CancellationToken cancellationToken = default) =>
        OnGetVersions!();

    public override Task<Response<KeyVaultCertificate>> GetCertificateVersionAsync(
        string certificateName, string version, CancellationToken cancellationToken = default) =>
        Task.FromResult(Response.FromValue(OnGetVersion!(version), new FakeAzureResponse(200)));
}
