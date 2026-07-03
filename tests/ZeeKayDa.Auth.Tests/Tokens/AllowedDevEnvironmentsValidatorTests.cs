using Microsoft.Extensions.Options;
using ZeeKayDa.Auth.Tokens;

namespace ZeeKayDa.Auth.Tests.Tokens;

public sealed class AllowedDevEnvironmentsValidatorTests
{
    private static readonly AllowedDevEnvironmentsValidator Sut = new();

    // ── Valid configurations (no errors) ─────────────────────────────────────────────────────────

    [Fact]
    public void Validate_succeeds_for_default_allowed_environments()
    {
        var options = new DevelopmentSigningKeyOptions(); // defaults to ["Development"]
        var result = Sut.Validate(null, options);
        result.Succeeded.Should().BeTrue();
    }

    [Fact]
    public void Validate_succeeds_for_custom_non_production_environments()
    {
        var options = new DevelopmentSigningKeyOptions
        {
            AllowedDevelopmentJwtSigningKeysEnvironments = ["Development", "Staging", "IntegrationTesting"],
        };
        var result = Sut.Validate(null, options);
        result.Succeeded.Should().BeTrue();
    }

    [Fact]
    public void Validate_succeeds_for_empty_allowed_list()
    {
        var options = new DevelopmentSigningKeyOptions
        {
            AllowedDevelopmentJwtSigningKeysEnvironments = [],
        };
        var result = Sut.Validate(null, options);
        result.Succeeded.Should().BeTrue();
    }

    // ── Production entries are rejected ──────────────────────────────────────────────────────────

    [Theory]
    [InlineData("Production")]
    [InlineData("production")]
    [InlineData("PRODUCTION")]
    public void Validate_fails_when_Production_is_in_allowed_list(string productionEntry)
    {
        var options = new DevelopmentSigningKeyOptions
        {
            AllowedDevelopmentJwtSigningKeysEnvironments = ["Development", productionEntry],
        };
        var result = Sut.Validate(null, options);
        result.Succeeded.Should().BeFalse();
        result.FailureMessage.Should().Contain("Production");
    }

    [Fact]
    public void Validate_fails_when_only_Production_in_list()
    {
        var options = new DevelopmentSigningKeyOptions
        {
            AllowedDevelopmentJwtSigningKeysEnvironments = ["Production"],
        };
        var result = Sut.Validate(null, options);
        result.Succeeded.Should().BeFalse();
    }

    // ── Null/empty entries are rejected ──────────────────────────────────────────────────────────

    [Fact]
    public void Validate_fails_when_list_contains_empty_string()
    {
        var options = new DevelopmentSigningKeyOptions
        {
            AllowedDevelopmentJwtSigningKeysEnvironments = ["Development", ""],
        };
        var result = Sut.Validate(null, options);
        result.Succeeded.Should().BeFalse();
        result.FailureMessage.Should().Contain("null or empty");
    }

    [Fact]
    public void Validate_fails_when_list_contains_whitespace_only_string()
    {
        var options = new DevelopmentSigningKeyOptions
        {
            AllowedDevelopmentJwtSigningKeysEnvironments = ["Development", "   "],
        };
        var result = Sut.Validate(null, options);
        result.Succeeded.Should().BeFalse();
        result.FailureMessage.Should().Contain("null or empty");
    }

    // ── Multiple errors are reported together ─────────────────────────────────────────────────────

    [Fact]
    public void Validate_reports_all_errors_when_multiple_invalid_entries_present()
    {
        var options = new DevelopmentSigningKeyOptions
        {
            AllowedDevelopmentJwtSigningKeysEnvironments = ["Production", ""],
        };
        var result = Sut.Validate(null, options);
        result.Succeeded.Should().BeFalse();
        // Both Production and empty-entry errors should be reported.
        result.FailureMessage.Should().Contain("Production");
        result.FailureMessage.Should().Contain("null or empty");
    }

    // ── Name parameter is ignored (IValidateOptions contract) ─────────────────────────────────────

    [Fact]
    public void Validate_succeeds_regardless_of_name_parameter()
    {
        var options = new DevelopmentSigningKeyOptions();
        Sut.Validate("some-name", options).Succeeded.Should().BeTrue();
        Sut.Validate(null, options).Succeeded.Should().BeTrue();
        Sut.Validate(string.Empty, options).Succeeded.Should().BeTrue();
    }
}
