using Microsoft.Extensions.Logging;
using ZeeKayDa.Auth.Tokens;

namespace ZeeKayDa.Auth.FileSystem.Tests;

public sealed class PfxFileSigningOptionsValidatorTests
{
    private static PfxFileSigningOptions ValidOptions() => new()
    {
        Path = "/etc/zeekayda/signing.pfx",
        PasswordSource = _ => ValueTask.FromResult("password"),
        KeyRotationCheckInterval = TimeSpan.FromMinutes(5),
        Algorithm = SigningAlgorithm.RS256,
    };

    [Fact]
    public void Validate_succeeds_for_valid_options()
    {
        var result = new PfxFileSigningOptionsValidator(NullSanitizingLogger<PfxFileSigningOptionsValidator>.Instance).Validate(null, ValidOptions());

        result.Succeeded.Should().BeTrue();
    }

    // The former "KeyRotationCheckInterval is null" test no longer applies: the property is now
    // non-nullable on RotatingKeySourceOptions (ADR 0011 §3.4, issue #409), so this options type
    // can no longer even represent that state.

    [Fact]
    public void Validate_fails_when_KeyRotationCheckInterval_is_below_the_one_minute_floor()
    {
        var options = ValidOptions();
        options.KeyRotationCheckInterval = TimeSpan.FromSeconds(30);

        var result = new PfxFileSigningOptionsValidator(NullSanitizingLogger<PfxFileSigningOptionsValidator>.Instance).Validate(null, options);

        result.Failed.Should().BeTrue();
        result.FailureMessage.Should().Contain("KeyRotationCheckInterval");
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("   ")]
    public void Validate_fails_when_Path_is_null_or_whitespace(string? path)
    {
        var options = ValidOptions();
        options.Path = path!;

        var result = new PfxFileSigningOptionsValidator(NullSanitizingLogger<PfxFileSigningOptionsValidator>.Instance).Validate(null, options);

        result.Failed.Should().BeTrue();
        result.FailureMessage.Should().Contain("Path");
    }

    [Fact]
    public void Validate_fails_when_PasswordSource_is_null()
    {
        var options = ValidOptions();
        options.PasswordSource = null;

        var result = new PfxFileSigningOptionsValidator(NullSanitizingLogger<PfxFileSigningOptionsValidator>.Instance).Validate(null, options);

        result.Failed.Should().BeTrue();
        result.FailureMessage.Should().Contain("PasswordSource");
    }

    [Fact]
    public void Validate_fails_when_Algorithm_is_not_a_defined_enum_member()
    {
        var options = ValidOptions();
        options.Algorithm = (SigningAlgorithm)999;

        var result = new PfxFileSigningOptionsValidator(NullSanitizingLogger<PfxFileSigningOptionsValidator>.Instance).Validate(null, options);

        result.Failed.Should().BeTrue();
        result.FailureMessage.Should().Contain("Algorithm");
    }

    [Fact]
    public void Validate_fails_when_AddFile_duplicates_the_primary_Path()
    {
        var options = ValidOptions();
        options.AddFile(options.Path, _ => ValueTask.FromResult("password"));

        var result = new PfxFileSigningOptionsValidator(NullSanitizingLogger<PfxFileSigningOptionsValidator>.Instance).Validate(null, options);

        result.Failed.Should().BeTrue();
        result.FailureMessage.Should().Contain("duplicates");
    }

    [Fact]
    public void Validate_fails_when_two_additional_files_duplicate_each_other()
    {
        var options = ValidOptions();
        options.AddFile("/etc/zeekayda/rotated-in.pfx", _ => ValueTask.FromResult("password-1"));
        options.AddFile("/etc/zeekayda/rotated-in.pfx", _ => ValueTask.FromResult("password-2"));

        var result = new PfxFileSigningOptionsValidator(NullSanitizingLogger<PfxFileSigningOptionsValidator>.Instance).Validate(null, options);

        result.Failed.Should().BeTrue();
        result.FailureMessage.Should().Contain("duplicates");
    }

    [Fact]
    public void Validate_succeeds_with_distinct_additional_files_each_with_their_own_password_source()
    {
        var options = ValidOptions();
        options.AddFile("/etc/zeekayda/rotated-in-1.pfx", _ => ValueTask.FromResult("password-1"));
        options.AddFile("/etc/zeekayda/rotated-in-2.pfx", _ => ValueTask.FromResult("password-2"));

        var result = new PfxFileSigningOptionsValidator(NullSanitizingLogger<PfxFileSigningOptionsValidator>.Instance).Validate(null, options);

        result.Succeeded.Should().BeTrue();
    }

    // ── AssumedJwksPropagationDelay validation (security review of PR #414, ADR 0011 §3.5) ───────

    [Theory]
    [InlineData(0)]
    [InlineData(-1)]
    public void Validate_fails_when_AssumedJwksPropagationDelay_is_zero_or_negative(int seconds)
    {
        var options = ValidOptions();
        options.AssumedJwksPropagationDelay = TimeSpan.FromSeconds(seconds);

        var result = new PfxFileSigningOptionsValidator(NullSanitizingLogger<PfxFileSigningOptionsValidator>.Instance).Validate(null, options);

        result.Failed.Should().BeTrue();
        result.FailureMessage.Should().Contain("AssumedJwksPropagationDelay");
    }

    [Fact]
    public void Validate_warns_but_succeeds_when_AssumedJwksPropagationDelay_is_shorter_than_KeyRotationCheckInterval()
    {
        var options = ValidOptions();
        options.KeyRotationCheckInterval = TimeSpan.FromMinutes(5);
        options.AssumedJwksPropagationDelay = TimeSpan.FromMinutes(1);
        var logger = new CapturingSanitizingLogger<PfxFileSigningOptionsValidator>();

        var result = new PfxFileSigningOptionsValidator(logger).Validate(null, options);

        result.Succeeded.Should().BeTrue();
        logger.Entries.Should().ContainSingle(e =>
            e.Level == LogLevel.Warning && e.Message.Contains("AssumedJwksPropagationDelay"));
    }

    [Fact]
    public void Validate_does_not_warn_when_AssumedJwksPropagationDelay_is_unset()
    {
        var options = ValidOptions();
        var logger = new CapturingSanitizingLogger<PfxFileSigningOptionsValidator>();

        var result = new PfxFileSigningOptionsValidator(logger).Validate(null, options);

        result.Succeeded.Should().BeTrue();
        logger.Entries.Should().BeEmpty();
    }
}
