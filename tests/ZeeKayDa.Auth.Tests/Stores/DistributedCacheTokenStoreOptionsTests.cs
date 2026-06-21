using ZeeKayDa.Auth.Stores;

namespace ZeeKayDa.Auth.Tests.Stores;

/// <summary>
/// Tests for <see cref="DistributedCacheTokenStoreOptions"/> covering AC-3 (option defaults).
/// </summary>
public sealed class DistributedCacheTokenStoreOptionsTests
{
    // ── AC-3 — Default values ─────────────────────────────────────────────────────────────────────

    [Fact]
    public void FamilyRevocationMarkerTtl_default_is_null()
    {
        var options = new DistributedCacheTokenStoreOptions();

        options.FamilyRevocationMarkerTtl.Should().BeNull(
            because: "the default must be null so the store resolves it at runtime to " +
                     "RefreshTokenLifetime + 5 minutes, ensuring markers outlive all tokens " +
                     "in the family regardless of the configured RefreshTokenLifetime");
    }

    [Fact]
    public void FamilyRevocationMarkerTtl_can_be_set_to_explicit_value()
    {
        var options = new DistributedCacheTokenStoreOptions
        {
            FamilyRevocationMarkerTtl = TimeSpan.FromDays(30)
        };

        options.FamilyRevocationMarkerTtl.Should().Be(TimeSpan.FromDays(30),
            because: "operators must be able to override the family revocation marker TTL");
    }
}
