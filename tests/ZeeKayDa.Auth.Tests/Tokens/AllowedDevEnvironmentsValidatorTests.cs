using Microsoft.Extensions.Options;
using ZeeKayDa.Auth.Tokens;

namespace ZeeKayDa.Auth.Tests.Tokens;

public sealed class AllowedDevEnvironmentsValidatorTests
{
    private static readonly AllowedDevEnvironmentsValidator Sut = new();

    private static IReadOnlyList<ZeeKayDaConfigurationFailure> Validate(DevelopmentSigningOptions options, string? name = null)
    {
        try
        {
            ((IValidateOptions<DevelopmentSigningOptions>)Sut).Validate(name, options);
            return [];
        }
        catch (ZeeKayDaConfigurationException exception)
        {
            return exception.AggregatedFailures;
        }
    }

    // ── Valid configurations (no errors) ─────────────────────────────────────────────────────────

    [Fact]
    public void Validate_succeeds_for_default_allowed_environments()
    {
        var options = new DevelopmentSigningOptions(); // defaults to ["Development"]
        Validate(options).Should().BeEmpty();
    }

    [Fact]
    public void Validate_succeeds_for_custom_non_production_environments()
    {
        var options = new DevelopmentSigningOptions
        {
            AllowedEnvironments = ["Development", "Staging", "IntegrationTesting"],
        };
        Validate(options).Should().BeEmpty();
    }

    [Fact]
    public void Validate_fails_for_an_empty_allowed_list()
    {
        var options = new DevelopmentSigningOptions
        {
            AllowedEnvironments = [],
        };
        var failures = Validate(options);
        failures.Should().ContainSingle(f => f.Code == "configuration.development_signing.allowed_environments.empty")
            .Which.Message.Should().Contain("at least one environment");
    }

    // ── Production entries are rejected ──────────────────────────────────────────────────────────

    [Theory]
    [InlineData("Production")]
    [InlineData("production")]
    [InlineData("PRODUCTION")]
    public void Validate_fails_when_Production_is_in_allowed_list(string productionEntry)
    {
        var options = new DevelopmentSigningOptions
        {
            AllowedEnvironments = ["Development", productionEntry],
        };
        var failures = Validate(options);
        failures.Should().ContainSingle(f => f.Code == "configuration.development_signing.allowed_environments.contains_production")
            .Which.Message.Should().Contain("Production");
    }

    [Fact]
    public void Validate_fails_when_only_Production_in_list()
    {
        var options = new DevelopmentSigningOptions
        {
            AllowedEnvironments = ["Production"],
        };
        var failures = Validate(options);
        failures.Should().ContainSingle(f => f.Code == "configuration.development_signing.allowed_environments.contains_production");
    }

    // ── Null/empty entries are rejected ──────────────────────────────────────────────────────────

    [Fact]
    public void Validate_fails_when_list_contains_empty_string()
    {
        var options = new DevelopmentSigningOptions
        {
            AllowedEnvironments = ["Development", ""],
        };
        var failures = Validate(options);
        failures.Should().ContainSingle(f => f.Code == "configuration.development_signing.allowed_environments.blank_entry")
            .Which.Message.Should().Contain("null or empty");
    }

    [Fact]
    public void Validate_fails_when_list_contains_whitespace_only_string()
    {
        var options = new DevelopmentSigningOptions
        {
            AllowedEnvironments = ["Development", "   "],
        };
        var failures = Validate(options);
        failures.Should().ContainSingle(f => f.Code == "configuration.development_signing.allowed_environments.blank_entry")
            .Which.Message.Should().Contain("null or empty");
    }

    // ── Multiple errors are reported together ─────────────────────────────────────────────────────

    [Fact]
    public void Validate_reports_all_errors_when_multiple_invalid_entries_present()
    {
        var options = new DevelopmentSigningOptions
        {
            AllowedEnvironments = ["Production", ""],
        };
        var failures = Validate(options);

        failures.Select(f => f.Code).Should().Contain(
        [
            "configuration.development_signing.allowed_environments.contains_production",
            "configuration.development_signing.allowed_environments.blank_entry",
        ]);
    }

    // ── Name parameter is ignored (IValidateOptions contract) ─────────────────────────────────────

    [Fact]
    public void Validate_succeeds_regardless_of_name_parameter()
    {
        var options = new DevelopmentSigningOptions();
        Validate(options, "some-name").Should().BeEmpty();
        Validate(options, null).Should().BeEmpty();
        Validate(options, string.Empty).Should().BeEmpty();
    }
}
