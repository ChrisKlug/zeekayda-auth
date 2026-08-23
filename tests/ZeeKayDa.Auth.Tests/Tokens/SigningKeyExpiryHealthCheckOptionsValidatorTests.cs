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

    [Theory]
    [InlineData(0)]
    [InlineData(-1)]
    public void Validate_fails_when_DegradedThreshold_is_not_positive(int seconds)
    {
        var options = new SigningKeyExpiryHealthCheckOptions { DegradedThreshold = TimeSpan.FromSeconds(seconds) };

        var result = _sut.Validate(name: null, options);

        result.Failed.Should().BeTrue();
    }

    [Fact]
    public void Validate_succeeds_for_a_positive_DegradedThreshold()
    {
        var options = new SigningKeyExpiryHealthCheckOptions { DegradedThreshold = TimeSpan.FromDays(14) };

        var result = _sut.Validate(name: null, options);

        result.Succeeded.Should().BeTrue();
    }
}
