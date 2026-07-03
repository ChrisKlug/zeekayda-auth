using ZeeKayDa.Auth.Tokens;

namespace ZeeKayDa.Auth.Tests.Tokens;

public sealed class DevelopmentSigningKeyOptionsTests
{
    // ── Default property values ───────────────────────────────────────────────────────────────────

    [Fact]
    public void AllowedDevelopmentJwtSigningKeysEnvironments_defaults_to_Development_only()
    {
        var options = new DevelopmentSigningKeyOptions();

        options.AllowedDevelopmentJwtSigningKeysEnvironments.Should().ContainSingle()
            .Which.Should().Be("Development");
    }

    [Fact]
    public void AllowedDevelopmentJwtSigningKeysEnvironments_can_be_widened()
    {
        var options = new DevelopmentSigningKeyOptions
        {
            AllowedDevelopmentJwtSigningKeysEnvironments = ["Development", "IntegrationTesting"],
        };

        options.AllowedDevelopmentJwtSigningKeysEnvironments.Should().BeEquivalentTo(
            new[] { "Development", "IntegrationTesting" });
    }

    [Fact]
    public void EnvironmentName_defaults_to_null()
    {
        var options = new DevelopmentSigningKeyOptions();

        options.EnvironmentName.Should().BeNull();
    }

    [Fact]
    public void EnvironmentName_can_be_set()
    {
        var options = new DevelopmentSigningKeyOptions
        {
            EnvironmentName = "Development",
        };

        options.EnvironmentName.Should().Be("Development");
    }
}
