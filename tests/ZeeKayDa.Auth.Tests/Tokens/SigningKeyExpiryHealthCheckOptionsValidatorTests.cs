using ZeeKayDa.Auth.Tokens;

namespace ZeeKayDa.Auth.Tests.Tokens;

/// <summary>
/// Exercises <see cref="SigningKeyExpiryHealthCheckOptionsValidator"/>: <c>DegradedThreshold</c> must
/// be a positive value, since zero or negative silently disables the only expiry watch a static
/// signing key ring has.
/// </summary>
public sealed class SigningKeyExpiryHealthCheckOptionsValidatorTests
{
    private readonly SigningKeyExpiryHealthCheckOptionsValidator _sut = new();

    private IReadOnlyList<ZeeKayDaConfigurationFailure> Validate(SigningKeyExpiryHealthCheckOptions options)
    {
        try
        {
            _sut.Validate(name: null, options);
            return [];
        }
        catch (ZeeKayDaConfigurationException exception)
        {
            return exception.AggregatedFailures;
        }
    }

    [Theory]
    [InlineData(0)]
    [InlineData(-1)]
    public void Validate_fails_when_DegradedThreshold_is_not_positive(int seconds)
    {
        var options = new SigningKeyExpiryHealthCheckOptions { DegradedThreshold = TimeSpan.FromSeconds(seconds) };

        var failures = Validate(options);

        failures.Should().ContainSingle(f => f.Code == "configuration.signing_key_expiry_health_check.degraded_threshold.not_positive")
            .Which.Message.Should().Contain("greater than zero");
    }

    [Fact]
    public void Validate_succeeds_for_a_positive_DegradedThreshold()
    {
        var options = new SigningKeyExpiryHealthCheckOptions { DegradedThreshold = TimeSpan.FromDays(14) };

        var failures = Validate(options);

        failures.Should().BeEmpty();
    }
}
