using ZeeKayDa.Auth.Tokens;

namespace ZeeKayDa.Auth.FileSystem.Tests;

public sealed class PfxFileSigningOptionsValidatorTests
{
    private static PfxFileSigningOptions ValidOptions() => new()
    {
        Path = "/etc/zeekayda/signing.pfx",
        PasswordSource = _ => ValueTask.FromResult("password"),
        KeySourceRefreshInterval = TimeSpan.FromMinutes(5),
        Algorithm = SigningAlgorithm.RS256,
    };

    [Fact]
    public void Validate_succeeds_for_valid_options()
    {
        var result = new PfxFileSigningOptionsValidator().Validate(null, ValidOptions());

        result.Succeeded.Should().BeTrue();
    }

    [Fact]
    public void Validate_fails_when_KeySourceRefreshInterval_is_null()
    {
        var options = ValidOptions();
        options.KeySourceRefreshInterval = null;

        var result = new PfxFileSigningOptionsValidator().Validate(null, options);

        result.Failed.Should().BeTrue();
        result.FailureMessage.Should().Contain("KeySourceRefreshInterval");
    }

    [Fact]
    public void Validate_fails_when_KeySourceRefreshInterval_is_below_the_one_minute_floor()
    {
        var options = ValidOptions();
        options.KeySourceRefreshInterval = TimeSpan.FromSeconds(30);

        var result = new PfxFileSigningOptionsValidator().Validate(null, options);

        result.Failed.Should().BeTrue();
        result.FailureMessage.Should().Contain("KeySourceRefreshInterval");
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("   ")]
    public void Validate_fails_when_Path_is_null_or_whitespace(string? path)
    {
        var options = ValidOptions();
        options.Path = path!;

        var result = new PfxFileSigningOptionsValidator().Validate(null, options);

        result.Failed.Should().BeTrue();
        result.FailureMessage.Should().Contain("Path");
    }

    [Fact]
    public void Validate_fails_when_PasswordSource_is_null()
    {
        var options = ValidOptions();
        options.PasswordSource = null;

        var result = new PfxFileSigningOptionsValidator().Validate(null, options);

        result.Failed.Should().BeTrue();
        result.FailureMessage.Should().Contain("PasswordSource");
    }

    [Fact]
    public void Validate_fails_when_Algorithm_is_not_a_defined_enum_member()
    {
        var options = ValidOptions();
        options.Algorithm = (SigningAlgorithm)999;

        var result = new PfxFileSigningOptionsValidator().Validate(null, options);

        result.Failed.Should().BeTrue();
        result.FailureMessage.Should().Contain("Algorithm");
    }

    [Fact]
    public void Validate_fails_when_AddFile_duplicates_the_primary_Path()
    {
        var options = ValidOptions();
        options.AddFile(options.Path, _ => ValueTask.FromResult("password"));

        var result = new PfxFileSigningOptionsValidator().Validate(null, options);

        result.Failed.Should().BeTrue();
        result.FailureMessage.Should().Contain("duplicates");
    }

    [Fact]
    public void Validate_fails_when_two_additional_files_duplicate_each_other()
    {
        var options = ValidOptions();
        options.AddFile("/etc/zeekayda/rotated-in.pfx", _ => ValueTask.FromResult("password-1"));
        options.AddFile("/etc/zeekayda/rotated-in.pfx", _ => ValueTask.FromResult("password-2"));

        var result = new PfxFileSigningOptionsValidator().Validate(null, options);

        result.Failed.Should().BeTrue();
        result.FailureMessage.Should().Contain("duplicates");
    }

    [Fact]
    public void Validate_succeeds_with_distinct_additional_files_each_with_their_own_password_source()
    {
        var options = ValidOptions();
        options.AddFile("/etc/zeekayda/rotated-in-1.pfx", _ => ValueTask.FromResult("password-1"));
        options.AddFile("/etc/zeekayda/rotated-in-2.pfx", _ => ValueTask.FromResult("password-2"));

        var result = new PfxFileSigningOptionsValidator().Validate(null, options);

        result.Succeeded.Should().BeTrue();
    }
}
