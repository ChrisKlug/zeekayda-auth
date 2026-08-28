using Azure;
using Azure.Security.KeyVault.Secrets;

namespace ZeeKayDa.Auth.AzureKeyVault.Tests.Fakes;

/// <summary>
/// A <see cref="SecretClient"/> built on the SDK's protected mocking constructor, so
/// <see cref="KeyVaultCertificateReader"/>'s secret-download fault mapping can be exercised
/// without a live vault.
/// </summary>
internal sealed class FakeSecretClient : SecretClient
{
    /// <summary>Receives the requested (name, version); returns the secret or throws.</summary>
    public Func<string, string?, KeyVaultSecret>? OnGetSecret { get; init; }

    public override Task<Response<KeyVaultSecret>> GetSecretAsync(
        string name, string? version = null, CancellationToken cancellationToken = default) =>
        Task.FromResult(Response.FromValue(OnGetSecret!(name, version), new FakeAzureResponse(200)));
}
