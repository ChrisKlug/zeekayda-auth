using ZeeKayDa.Auth.Tokens;

namespace ZeeKayDa.Auth.Tests.Tokens;

public sealed class DevelopmentSigningKeyOptionsTests
{
    // ── Default property values ───────────────────────────────────────────────────────────────────

    [Fact]
    public void EnvironmentName_defaults_to_null()
    {
        var options = new DevelopmentSigningKeyOptions();

        options.EnvironmentName.Should().BeNull();
    }

    [Fact]
    public void EnvironmentName_can_be_set()
    {
        // The setter is internal (not settable through the public configure callback) — this
        // assembly has InternalsVisibleTo access, matching how the AspNetCore registration layer
        // populates it from IHostEnvironment.EnvironmentName.
        var options = new DevelopmentSigningKeyOptions
        {
            EnvironmentName = "Development",
        };

        options.EnvironmentName.Should().Be("Development");
    }

    // ── AllowedDevelopmentJwtSigningKeysEnvironments (issue #338 — moved back from
    // AuthorizationServerOptions, reachable via AddPersistedDevelopmentJwtSigningKeys' public
    // configure callback. The in-memory variant uses the separate, smaller
    // InMemoryDevelopmentSigningKeyOptions type instead — see #338 follow-up.) ──────────────────────

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
        // This is the public, external entry point acceptance criterion (#337/#338) requires: a
        // consumer widens the list via the registration method's public configure callback with
        // no InternalsVisibleTo access and no reference to an internal type.
        var options = new DevelopmentSigningKeyOptions
        {
            AllowedDevelopmentJwtSigningKeysEnvironments = ["Development", "IntegrationTesting", "CI"],
        };

        options.AllowedDevelopmentJwtSigningKeysEnvironments.Should().BeEquivalentTo(
            new[] { "Development", "IntegrationTesting", "CI" });
    }
}
