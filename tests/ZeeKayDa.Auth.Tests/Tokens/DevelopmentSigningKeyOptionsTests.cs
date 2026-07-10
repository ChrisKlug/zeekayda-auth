using ZeeKayDa.Auth.Tokens;

namespace ZeeKayDa.Auth.Tests.Tokens;

public sealed class DevelopmentSigningKeyOptionsTests
{
    // ── Default property values ───────────────────────────────────────────────────────────────────

    // AllowedDevelopmentJwtSigningKeysEnvironments moved to AuthorizationServerOptions (#332) — see
    // AuthorizationServerOptionsTests for its default-value and widening coverage.

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
