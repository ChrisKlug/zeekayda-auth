using Azure.Security.KeyVault.Keys;

namespace ZeeKayDa.Auth.AzureKeyVault.Tests;

/// <summary>
/// Tests for <see cref="KeyVaultKeyReader.MapVersion"/>, the one piece of the real reader that is a
/// pure function over SDK data and therefore testable without a live vault (via the SDK's
/// <see cref="KeyModelFactory"/>). The full network-facing reader remains covered only by the
/// known-gap note in <c>Integration/AzureKeyVaultRemoteSigningIntegrationTests.cs</c>.
/// </summary>
public sealed class KeyVaultKeyReaderTests
{
    private static readonly Uri VaultUri = new("https://fake-vault.vault.azure.net/");
    private static readonly Uri VersionUri = new("https://fake-vault.vault.azure.net/keys/fake-key/v1");
    private static readonly DateTimeOffset T0 = DateTimeOffset.Parse("2026-01-01T00:00:00Z");

    private static KeyProperties BuildProperties(DateTimeOffset? createdOn, bool? enabled)
    {
        var properties = KeyModelFactory.KeyProperties(
            id: VersionUri, vaultUri: VaultUri, name: "fake-key", version: "v1",
            managed: false, createdOn: createdOn, updatedOn: null, recoveryLevel: null);
        properties.Enabled = enabled;
        return properties;
    }

    [Fact]
    public void MapVersion_maps_a_complete_listing_entry()
    {
        var properties = BuildProperties(createdOn: T0, enabled: true);
        properties.NotBefore = T0 - TimeSpan.FromDays(1);
        properties.ExpiresOn = T0 + TimeSpan.FromDays(365);

        var info = KeyVaultKeyReader.MapVersion(properties, "fake-key", VaultUri);

        info.Id.Should().Be(VersionUri);
        info.Version.Should().Be("v1");
        info.Enabled.Should().BeTrue();
        info.CreatedOn.Should().Be(T0);
        info.NotBefore.Should().Be(T0 - TimeSpan.FromDays(1));
        info.ExpiresOn.Should().Be(T0 + TimeSpan.FromDays(365));
    }

    [Fact]
    public void MapVersion_fails_closed_when_CreatedOn_is_absent()
    {
        // An absent CreatedOn treated as ancient would satisfy the pre-activation age gate
        // immediately AND claim the first-ever exemption — the exact failure the gate exists to
        // prevent, reached through the one input the gate cannot see.
        var properties = BuildProperties(createdOn: null, enabled: true);

        var act = () => KeyVaultKeyReader.MapVersion(properties, "fake-key", VaultUri);

        act.Should().Throw<ZeeKayDaConfigurationException>()
            .WithMessage("*incomplete_version_metadata*");
    }

    [Fact]
    public void MapVersion_fails_closed_when_Enabled_is_absent()
    {
        // An absent Enabled treated as enabled would bypass the operator's revocation lever.
        var properties = BuildProperties(createdOn: T0, enabled: null);

        var act = () => KeyVaultKeyReader.MapVersion(properties, "fake-key", VaultUri);

        act.Should().Throw<ZeeKayDaConfigurationException>()
            .WithMessage("*incomplete_version_metadata*");
    }
}
