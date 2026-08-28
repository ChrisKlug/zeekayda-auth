using Azure;
using Azure.Security.KeyVault.Keys;

namespace ZeeKayDa.Auth.AzureKeyVault.Tests.Fakes;

/// <summary>
/// A <see cref="KeyClient"/> built on the SDK's protected mocking constructor, so
/// <see cref="KeyVaultKeyReader"/>'s SDK fault-mapping paths can be exercised without a live
/// vault. Configure either delegate to return SDK model objects (via
/// <see cref="KeyModelFactory"/>) or to throw.
/// </summary>
internal sealed class FakeKeyClient : KeyClient
{
    public Func<AsyncPageable<KeyProperties>>? OnGetVersions { get; init; }

    /// <summary>Receives the requested version; returns the key or throws.</summary>
    public Func<string?, KeyVaultKey>? OnGetKey { get; init; }

    /// <summary>Every key name the reader asked for, in call order, across both operations.</summary>
    public List<string> RequestedNames { get; } = [];

    public override AsyncPageable<KeyProperties> GetPropertiesOfKeyVersionsAsync(
        string name, CancellationToken cancellationToken = default)
    {
        RequestedNames.Add(name);
        return OnGetVersions!();
    }

    public override Task<Response<KeyVaultKey>> GetKeyAsync(
        string name, string? version = null, CancellationToken cancellationToken = default)
    {
        RequestedNames.Add(name);
        return Task.FromResult(Response.FromValue(OnGetKey!(version), new FakeAzureResponse(200)));
    }
}
