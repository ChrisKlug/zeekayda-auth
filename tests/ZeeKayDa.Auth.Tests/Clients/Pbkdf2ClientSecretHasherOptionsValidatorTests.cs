using Microsoft.Extensions.Options;
using ZeeKayDa.Auth.Clients;

namespace ZeeKayDa.Auth.Tests.Clients;

public sealed class Pbkdf2ClientSecretHasherOptionsValidatorTests
{
    private static IReadOnlyList<ZeeKayDaConfigurationFailure> Validate(int iterations)
    {
        try
        {
            ((IValidateOptions<Pbkdf2ClientSecretHasherOptions>)new Pbkdf2ClientSecretHasherOptionsValidator()).Validate(
                null, new Pbkdf2ClientSecretHasherOptions { Iterations = iterations });
            return [];
        }
        catch (ZeeKayDaConfigurationException exception)
        {
            return exception.AggregatedFailures;
        }
    }

    [Theory]
    [InlineData(Pbkdf2ClientSecretHasher.MinIterations)]
    [InlineData(1_200_000)]
    [InlineData(Pbkdf2ClientSecretHasher.MaxIterations)]
    public void Validate_accepts_an_iteration_count_within_the_allowed_range(int iterations)
    {
        Validate(iterations).Should().BeEmpty();
    }

    [Fact]
    public void Validate_refuses_an_iteration_count_below_the_minimum()
    {
        var failures = Validate(Pbkdf2ClientSecretHasher.MinIterations - 1);

        failures.Should().ContainSingle(f => f.Code == "configuration.pbkdf2.iterations_out_of_range")
            .Which.Message.Should().Contain("below the minimum");
    }

    [Fact]
    public void Validate_refuses_an_iteration_count_above_the_maximum_rather_than_clamping_it()
    {
        var failures = Validate(Pbkdf2ClientSecretHasher.MaxIterations + 1);

        failures.Should().ContainSingle(f => f.Code == "configuration.pbkdf2.iterations_out_of_range")
            .Which.Message.Should().Contain("above the maximum");
    }
}
