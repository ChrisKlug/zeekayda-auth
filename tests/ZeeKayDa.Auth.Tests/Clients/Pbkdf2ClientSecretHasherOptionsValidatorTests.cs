using ZeeKayDa.Auth.Clients;

namespace ZeeKayDa.Auth.Tests.Clients;

public sealed class Pbkdf2ClientSecretHasherOptionsValidatorTests
{
    private static Microsoft.Extensions.Options.ValidateOptionsResult Validate(int iterations)
        => new Pbkdf2ClientSecretHasherOptionsValidator().Validate(
            null, new Pbkdf2ClientSecretHasherOptions { Iterations = iterations });

    [Theory]
    [InlineData(Pbkdf2ClientSecretHasher.MinIterations)]
    [InlineData(1_200_000)]
    [InlineData(Pbkdf2ClientSecretHasher.MaxIterations)]
    public void Validate_accepts_an_iteration_count_within_the_allowed_range(int iterations)
    {
        Validate(iterations).Succeeded.Should().BeTrue();
    }

    [Fact]
    public void Validate_refuses_an_iteration_count_below_the_minimum()
    {
        var result = Validate(Pbkdf2ClientSecretHasher.MinIterations - 1);

        result.Failed.Should().BeTrue();
        result.FailureMessage.Should().Contain("below the minimum");
    }

    [Fact]
    public void Validate_refuses_an_iteration_count_above_the_maximum_rather_than_clamping_it()
    {
        var result = Validate(Pbkdf2ClientSecretHasher.MaxIterations + 1);

        result.Failed.Should().BeTrue();
        result.FailureMessage.Should().Contain("above the maximum");
    }
}
