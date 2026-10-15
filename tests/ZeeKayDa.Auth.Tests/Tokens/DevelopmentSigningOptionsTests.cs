using ZeeKayDa.Auth.Tokens;

namespace ZeeKayDa.Auth.Tests.Tokens;

public sealed class DevelopmentSigningOptionsTests
{
    // ── Default property values ───────────────────────────────────────────────────────────────────

    [Fact]
    public void EnvironmentName_defaults_to_null()
    {
        var options = new DevelopmentSigningOptions();

        options.EnvironmentName.Should().BeNull();
    }

    [Fact]
    public void EnvironmentName_can_be_set()
    {
        var options = new DevelopmentSigningOptions
        {
            EnvironmentName = "Development",
        };

        options.EnvironmentName.Should().Be("Development");
    }

    // ── AllowedEnvironments ───────────────────────────────────────────────────────────────────────

    [Fact]
    public void AllowedEnvironments_defaults_to_Development_only()
    {
        var options = new DevelopmentSigningOptions();

        options.AllowedEnvironments.Should().ContainSingle()
            .Which.Should().Be("Development");
    }

    [Fact]
    public void AllowedEnvironments_can_be_widened()
    {
        // This is the public, external entry point acceptance criterion (#337/#338) requires: a
        // consumer widens the list via the registration method's public configure callback with
        // no InternalsVisibleTo access and no reference to an internal type.
        var options = new DevelopmentSigningOptions
        {
            AllowedEnvironments = ["Development", "IntegrationTesting", "CI"],
        };

        options.AllowedEnvironments.Should().BeEquivalentTo(
            new[] { "Development", "IntegrationTesting", "CI" });
    }

    [Fact]
    public void AllowedEnvironments_is_a_copy_the_assigning_caller_cannot_change_afterwards()
    {
        var assigned = new List<string> { "Development" };
        var options = new DevelopmentSigningOptions { AllowedEnvironments = assigned };

        assigned.Add("Staging");

        options.AllowedEnvironments.Should().Equal("Development");
    }

    [Fact]
    public void AllowedEnvironments_rejects_null()
    {
        var options = new DevelopmentSigningOptions();

        var act = () => options.AllowedEnvironments = null!;

        act.Should().Throw<ArgumentNullException>();
    }

    [Fact]
    public void AllowedEnvironments_cannot_be_changed_through_a_cast_to_a_mutable_type()
    {
        var options = new DevelopmentSigningOptions { AllowedEnvironments = new List<string> { "Development" } };

        options.AllowedEnvironments.Should().NotBeAssignableTo<string[]>()
            .And.NotBeAssignableTo<List<string>>();
        var asList = (IList<string>)options.AllowedEnvironments;
        var act = () => asList[0] = "Production";

        act.Should().Throw<NotSupportedException>();
        options.AllowedEnvironments.Should().Equal("Development");
    }
}
