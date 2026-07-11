using Microsoft.Extensions.Options;
using ZeeKayDa.Auth.Tokens;

namespace ZeeKayDa.Auth.Tests.Tokens;

public sealed class DevelopmentSigningKeyOptionsValidatorTests
{
    private static ValidateOptionsResult Validate(DevelopmentSigningKeyOptions options)
        => new DevelopmentSigningKeyOptionsValidator().Validate(null, options);

    // ── Non-null (finite) interval ────────────────────────────────────────────────────────────────

    [Fact]
    public void Validate_fails_when_KeySourceRefreshInterval_is_zero()
    {
        var options = new DevelopmentSigningKeyOptions { KeySourceRefreshInterval = TimeSpan.Zero };

        var result = Validate(options);

        result.Failed.Should().BeTrue();
        result.FailureMessage.Should().Contain("KeySourceRefreshInterval");
    }

    [Fact]
    public void Validate_fails_when_KeySourceRefreshInterval_is_negative()
    {
        var options = new DevelopmentSigningKeyOptions { KeySourceRefreshInterval = TimeSpan.FromSeconds(-1) };

        var result = Validate(options);

        result.Failed.Should().BeTrue();
        result.FailureMessage.Should().Contain("KeySourceRefreshInterval");
    }

    [Fact]
    public void Validate_fails_when_KeySourceRefreshInterval_is_finite_positive()
    {
        var options = new DevelopmentSigningKeyOptions { KeySourceRefreshInterval = TimeSpan.FromSeconds(1) };

        var result = Validate(options);

        result.Failed.Should().BeTrue();
        result.FailureMessage.Should().Contain("KeySourceRefreshInterval");
    }

    // ── null (static-source mode) ─────────────────────────────────────────────────────────────────

    [Fact]
    public void Validate_succeeds_for_default_options()
    {
        var options = new DevelopmentSigningKeyOptions();

        var result = Validate(options);

        result.Succeeded.Should().BeTrue();
    }

    [Fact]
    public void Validate_succeeds_when_KeySourceRefreshInterval_is_null()
    {
        var options = new DevelopmentSigningKeyOptions { KeySourceRefreshInterval = null };

        var result = Validate(options);

        result.Succeeded.Should().BeTrue();
    }
}
