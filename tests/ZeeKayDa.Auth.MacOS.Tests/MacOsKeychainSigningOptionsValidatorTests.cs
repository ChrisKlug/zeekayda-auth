using ZeeKayDa.Auth.Tokens;

namespace ZeeKayDa.Auth.MacOS.Tests;

public sealed class MacOsKeychainSigningOptionsValidatorTests
{
    private static MacOsKeychainSigningOptions ValidOptions() => new()
    {
        Label = "primary-label",
        RefreshInterval = TimeSpan.FromMinutes(5),
        Algorithm = SigningAlgorithm.RS256,
    };

    [Fact]
    public void Validate_succeeds_for_valid_options()
    {
        var result = new MacOsKeychainSigningOptionsValidator().Validate(null, ValidOptions());

        result.Succeeded.Should().BeTrue();
    }

    [Fact]
    public void Validate_fails_when_RefreshInterval_is_MaxValue()
    {
        var options = ValidOptions();
        options.RefreshInterval = TimeSpan.MaxValue;

        var result = new MacOsKeychainSigningOptionsValidator().Validate(null, options);

        result.Failed.Should().BeTrue();
        result.FailureMessage.Should().Contain("RefreshInterval");
    }

    [Fact]
    public void Validate_fails_when_RefreshInterval_is_below_the_one_minute_floor()
    {
        var options = ValidOptions();
        options.RefreshInterval = TimeSpan.FromSeconds(30);

        var result = new MacOsKeychainSigningOptionsValidator().Validate(null, options);

        result.Failed.Should().BeTrue();
        result.FailureMessage.Should().Contain("RefreshInterval");
    }

    [Fact]
    public void Validate_fails_when_Label_is_empty()
    {
        var options = ValidOptions();
        options.Label = string.Empty;

        var result = new MacOsKeychainSigningOptionsValidator().Validate(null, options);

        result.Failed.Should().BeTrue();
        result.FailureMessage.Should().Contain("Label");
    }

    [Fact]
    public void Validate_fails_when_Algorithm_is_not_a_defined_enum_member()
    {
        var options = ValidOptions();
        options.Algorithm = (SigningAlgorithm)999;

        var result = new MacOsKeychainSigningOptionsValidator().Validate(null, options);

        result.Failed.Should().BeTrue();
        result.FailureMessage.Should().Contain("Algorithm");
    }

    [Fact]
    public void Validate_fails_when_AddKey_duplicates_the_primary_label()
    {
        var options = ValidOptions();
        options.AddKey(options.Label);

        var result = new MacOsKeychainSigningOptionsValidator().Validate(null, options);

        result.Failed.Should().BeTrue();
        result.FailureMessage.Should().Contain("duplicates");
    }

    [Fact]
    public void Validate_fails_when_two_additional_keys_duplicate_each_other()
    {
        var options = ValidOptions();
        options.AddKey("secondary");
        options.AddKey("secondary", DateTimeOffset.UtcNow);

        var result = new MacOsKeychainSigningOptionsValidator().Validate(null, options);

        result.Failed.Should().BeTrue();
    }

    [Fact]
    public void Validate_succeeds_with_distinct_additional_keys_via_both_AddKey_overloads()
    {
        var options = ValidOptions();
        options.AddKey("secondary");
        options.AddKey("tertiary", DateTimeOffset.UtcNow, DateTimeOffset.UtcNow.AddYears(1));

        var result = new MacOsKeychainSigningOptionsValidator().Validate(null, options);

        result.Succeeded.Should().BeTrue();
    }

    [Fact]
    public void AddKey_single_argument_overload_throws_ArgumentException_for_null_or_whitespace_label()
    {
        var options = ValidOptions();

        var act = () => options.AddKey("  ");

        act.Should().Throw<ArgumentException>();
    }

    [Fact]
    public void AddKey_explicit_activation_overload_throws_ArgumentException_for_null_or_whitespace_label()
    {
        var options = ValidOptions();

        var act = () => options.AddKey("  ", DateTimeOffset.UtcNow);

        act.Should().Throw<ArgumentException>();
    }

    [Fact]
    public void AddKey_returns_options_instance_for_chaining()
    {
        var options = ValidOptions();

        var returned = options.AddKey("secondary");

        returned.Should().BeSameAs(options);
    }
}
