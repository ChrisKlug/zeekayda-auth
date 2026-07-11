using System.Reflection;
using ZeeKayDa.Auth.Tokens;

namespace ZeeKayDa.Auth.Tests.Tokens;

public sealed class InMemoryDevelopmentSigningKeyOptionsTests
{
    // ── Shape guarantee (issue #338 follow-up — PersistToDirectory must not be reachable from
    // AddInMemoryDevelopmentJwtSigningKeys' public configure surface) ───────────────────────────────

    [Fact]
    public void Type_has_no_PersistToDirectory_member()
    {
        // This is a structural/shape assertion, not just a runtime-value check: the type
        // genuinely does not declare a PersistToDirectory property, so no caller code — and no
        // configure callback passed to AddInMemoryDevelopmentJwtSigningKeys — could ever reference
        // one; any attempt to write "o.PersistToDirectory = ..." against this type fails to
        // compile. This test documents and pins that shape so it cannot silently regress.
        var property = typeof(InMemoryDevelopmentSigningKeyOptions).GetProperty(
            "PersistToDirectory", BindingFlags.Public | BindingFlags.Instance);

        property.Should().BeNull(
            "PersistToDirectory must only exist on DevelopmentSigningKeyOptions (the persisted " +
            "variant's configure surface), never on the in-memory variant's");
    }

    [Fact]
    public void Type_exposes_only_AllowedDevelopmentJwtSigningKeysEnvironments()
    {
        var propertyNames = typeof(InMemoryDevelopmentSigningKeyOptions)
            .GetProperties(BindingFlags.Public | BindingFlags.Instance)
            .Select(p => p.Name);

        propertyNames.Should().BeEquivalentTo(
            [nameof(InMemoryDevelopmentSigningKeyOptions.AllowedDevelopmentJwtSigningKeysEnvironments)]);
    }

    // ── Default property values ───────────────────────────────────────────────────────────────────

    [Fact]
    public void AllowedDevelopmentJwtSigningKeysEnvironments_defaults_to_Development_only()
    {
        var options = new InMemoryDevelopmentSigningKeyOptions();

        options.AllowedDevelopmentJwtSigningKeysEnvironments.Should().ContainSingle()
            .Which.Should().Be("Development");
    }

    [Fact]
    public void AllowedDevelopmentJwtSigningKeysEnvironments_can_be_widened()
    {
        var options = new InMemoryDevelopmentSigningKeyOptions
        {
            AllowedDevelopmentJwtSigningKeysEnvironments = ["Development", "IntegrationTesting", "CI"],
        };

        options.AllowedDevelopmentJwtSigningKeysEnvironments.Should().BeEquivalentTo(
            new[] { "Development", "IntegrationTesting", "CI" });
    }
}
