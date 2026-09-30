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

        var act = () => validator.Validate(Options.DefaultName, new TestOptions());

        act.Should().Throw<ZeeKayDaConfigurationException>()
            .Which.AggregatedFailures.Select(f => f.Code).Should().Equal("test.first", "test.second");
    }

    [Fact]
    public void Validate_returns_success_when_no_failure_was_added()
    {
        var result = new FixedValidator().Validate(Options.DefaultName, new TestOptions());

        result.Succeeded.Should().BeTrue();
    }

    [Fact]
    public void Validate_passes_the_options_name_to_the_derived_validator()
    {
        var validator = new FixedValidator();

        validator.Validate("tenant", new TestOptions());

        validator.SeenName.Should().Be("tenant");
    }

    [Fact]
    public void Validate_throws_ArgumentNullException_for_null_options()
    {
        var act = () => new FixedValidator().Validate(Options.DefaultName, null!);

        act.Should().Throw<ArgumentNullException>().WithParameterName("options");
    }

    private sealed class TestOptions;

    private sealed class FixedValidator(params ZeeKayDaConfigurationFailure[] toAdd)
        : ZeeKayDaOptionsValidator<TestOptions>
    {
        public string? SeenName { get; private set; }

        protected override void Validate(
            string? name,
            TestOptions options,
            ICollection<ZeeKayDaConfigurationFailure> failures)
        {
            SeenName = name;
            foreach (var failure in toAdd)
                failures.Add(failure);
        }
    }
}
