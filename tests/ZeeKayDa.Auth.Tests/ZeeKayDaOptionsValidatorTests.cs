using Microsoft.Extensions.Options;

namespace ZeeKayDa.Auth.Tests;

public sealed class ZeeKayDaOptionsValidatorTests
{
    [Fact]
    public void Validate_throws_every_added_failure_in_one_ZeeKayDaConfigurationException()
    {
        var validator = new FixedValidator(
            new ZeeKayDaConfigurationFailure("test.first", "First."),
            new ZeeKayDaConfigurationFailure("test.second", "Second."));

        var act = () => ((IValidateOptions<TestOptions>)validator).Validate(Options.DefaultName, new TestOptions());

        act.Should().Throw<ZeeKayDaConfigurationException>()
            .Which.AggregatedFailures.Select(f => f.Code).Should().Equal("test.first", "test.second");
    }

    [Fact]
    public void Validate_returns_success_when_no_failure_was_added()
    {
        var result = ((IValidateOptions<TestOptions>)new FixedValidator()).Validate(Options.DefaultName, new TestOptions());

        result.Succeeded.Should().BeTrue();
    }

    [Fact]
    public void Validate_passes_the_options_name_to_the_derived_validator()
    {
        var validator = new FixedValidator();

        ((IValidateOptions<TestOptions>)validator).Validate("tenant", new TestOptions());

        validator.SeenName.Should().Be("tenant");
    }

    [Fact]
    public void Validate_throws_ArgumentNullException_for_null_options()
    {
        var act = () => ((IValidateOptions<TestOptions>)new FixedValidator()).Validate(Options.DefaultName, null!);

        act.Should().Throw<ArgumentNullException>().WithParameterName("options");
    }

    [Fact]
    public void A_subclass_returning_null_is_reported_as_a_coded_failure()
    {
        var act = () => ((IValidateOptions<TestOptions>)new NullReturningValidator()).Validate(Options.DefaultName, new TestOptions());

        act.Should().Throw<ZeeKayDaConfigurationException>()
            .Which.AggregatedFailures.Should().ContainSingle()
            .Which.Code.Should().Be("configuration.options_validator.malformed_result");
    }

    [Fact]
    public void A_subclass_returning_a_null_failure_is_reported_as_a_coded_failure()
    {
        var act = () => ((IValidateOptions<TestOptions>)new FixedValidator(new ZeeKayDaConfigurationFailure[] { null! })).Validate(Options.DefaultName, new TestOptions());

        act.Should().Throw<ZeeKayDaConfigurationException>()
            .Which.AggregatedFailures.Should().ContainSingle()
            .Which.Code.Should().Be("configuration.options_validator.malformed_result");
    }

    private sealed class NullReturningValidator : ZeeKayDaOptionsValidator<TestOptions>
    {
        protected override IEnumerable<ZeeKayDaConfigurationFailure> Validate(string? name, TestOptions options) => null!;
    }

    private sealed class TestOptions;

    private sealed class FixedValidator(params ZeeKayDaConfigurationFailure[] toAdd)
        : ZeeKayDaOptionsValidator<TestOptions>
    {
        public string? SeenName { get; private set; }

        protected override IEnumerable<ZeeKayDaConfigurationFailure> Validate(string? name, TestOptions options)
        {
            SeenName = name;
            return toAdd;
        }
    }
}
