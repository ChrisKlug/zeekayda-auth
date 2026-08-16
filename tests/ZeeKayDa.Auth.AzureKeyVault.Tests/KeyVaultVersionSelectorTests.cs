using ZeeKayDa.Auth.AzureKeyVault;

namespace ZeeKayDa.Auth.AzureKeyVault.Tests;

public sealed class KeyVaultVersionSelectorTests
{
    private static readonly DateTimeOffset T0 = DateTimeOffset.Parse("2026-01-01T00:00:00Z");

    private static KeyVaultKeyVersionInfo Version(string version, DateTimeOffset createdOn, bool enabled = true) =>
        new(new Uri($"https://vault.example/keys/key/{version}"), version, enabled, createdOn, NotBefore: null, ExpiresOn: null);

    [Fact]
    public void DetermineFirstEverVersion_returns_the_only_version_when_a_single_version_exists()
    {
        var only = Version("v1", T0);

        var firstEver = KeyVaultVersionSelector.DetermineFirstEverVersion([only]);

        firstEver.Should().Be("v1");
    }

    [Fact]
    public void DetermineFirstEverVersion_returns_the_chronologically_earliest_version()
    {
        var earliest = Version("v1", T0);
        var later = Version("v2", T0 + TimeSpan.FromDays(1));

        var firstEver = KeyVaultVersionSelector.DetermineFirstEverVersion([later, earliest]);

        firstEver.Should().Be("v1", "the earliest CreatedOn wins regardless of list order");
    }

    [Fact]
    public void DetermineFirstEverVersion_includes_disabled_versions_in_the_comparison()
    {
        // A disabled version can still be the chronologically-first one ever recorded; this method
        // must not filter to enabled-only before comparing, or a later-created enabled version could
        // wrongly be treated as "first ever" and bypass PublicationLead.
        var disabledFirst = Version("v1", T0, enabled: false);
        var enabledSecond = Version("v2", T0 + TimeSpan.FromDays(1));

        var firstEver = KeyVaultVersionSelector.DetermineFirstEverVersion([disabledFirst, enabledSecond]);

        firstEver.Should().Be("v1");
    }

    [Fact]
    public void DetermineFirstEverVersion_breaks_ties_on_CreatedOn_by_ordinal_version_string()
    {
        var a = Version("bbb", T0);
        var b = Version("aaa", T0);

        var firstEver = KeyVaultVersionSelector.DetermineFirstEverVersion([a, b]);

        firstEver.Should().Be("aaa", "identical CreatedOn falls back to an ordinal comparison of the version string");
    }
}
