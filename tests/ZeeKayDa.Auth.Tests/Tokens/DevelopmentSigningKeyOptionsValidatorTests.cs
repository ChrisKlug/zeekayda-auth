using Microsoft.Extensions.Options;
using ZeeKayDa.Auth.Tokens;

namespace ZeeKayDa.Auth.Tests.Tokens;

public sealed class DevelopmentSigningKeyOptionsValidatorTests
{
    private static ValidateOptionsResult Validate(DevelopmentSigningKeyOptions options)
        => new DevelopmentSigningKeyOptionsValidator().Validate(null, options);

    // ── Non-MaxValue interval ─────────────────────────────────────────────────────────────────────

    [Fact]
    public void Validate_fails_when_RefreshInterval_is_zero()
    {
        var options = new DevelopmentSigningKeyOptions { RefreshInterval = TimeSpan.Zero };

        var result = Validate(options);

        result.Failed.Should().BeTrue();
        result.FailureMessage.Should().Contain("RefreshInterval");
    }

    [Fact]
    public void Validate_fails_when_RefreshInterval_is_negative()
    {
        var options = new DevelopmentSigningKeyOptions { RefreshInterval = TimeSpan.FromSeconds(-1) };

        var result = Validate(options);

        result.Failed.Should().BeTrue();
        result.FailureMessage.Should().Contain("RefreshInterval");
    }

    [Fact]
    public void Validate_fails_when_RefreshInterval_is_finite_positive()
    {
        var options = new DevelopmentSigningKeyOptions { RefreshInterval = TimeSpan.FromSeconds(1) };

        var result = Validate(options);

        result.Failed.Should().BeTrue();
        result.FailureMessage.Should().Contain("RefreshInterval");
    }

    // ── MaxValue ──────────────────────────────────────────────────────────────────────────────────

    [Fact]
    public void Validate_succeeds_for_default_options()
    {
        var options = new DevelopmentSigningKeyOptions();

        var result = Validate(options);

        result.Succeeded.Should().BeTrue();
    }

    [Fact]
    public void Validate_succeeds_when_RefreshInterval_is_MaxValue()
    {
        var options = new DevelopmentSigningKeyOptions { RefreshInterval = TimeSpan.MaxValue };

        var result = Validate(options);

        result.Succeeded.Should().BeTrue();
    }
}
