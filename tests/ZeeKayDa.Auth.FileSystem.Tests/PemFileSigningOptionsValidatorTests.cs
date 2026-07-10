using ZeeKayDa.Auth.Tokens;

namespace ZeeKayDa.Auth.FileSystem.Tests;

public sealed class PemFileSigningOptionsValidatorTests
{
    private static PemFileSigningOptions ValidOptions() => new()
    {
        Path = "/etc/zeekayda/signing.pem",
        RefreshInterval = TimeSpan.FromMinutes(5),
        Algorithm = SigningAlgorithm.RS256,
    };

    [Fact]
    public void Validate_succeeds_for_valid_options()
    {
        var result = new PemFileSigningOptionsValidator().Validate(null, ValidOptions());

        result.Succeeded.Should().BeTrue();
    }

    [Fact]
    public void Validate_fails_when_RefreshInterval_is_MaxValue()
    {
        var options = ValidOptions();
        options.RefreshInterval = TimeSpan.MaxValue;

        var result = new PemFileSigningOptionsValidator().Validate(null, options);

        result.Failed.Should().BeTrue();
        result.FailureMessage.Should().Contain("RefreshInterval");
    }

    [Fact]
    public void Validate_fails_when_RefreshInterval_is_below_the_one_minute_floor()
    {
        var options = ValidOptions();
        options.RefreshInterval = TimeSpan.FromSeconds(30);

        var result = new PemFileSigningOptionsValidator().Validate(null, options);

        result.Failed.Should().BeTrue();
        result.FailureMessage.Should().Contain("RefreshInterval");
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("   ")]
    public void Validate_fails_when_Path_is_null_or_whitespace(string? path)
    {
        var options = ValidOptions();
        options.Path = path!;

        var result = new PemFileSigningOptionsValidator().Validate(null, options);

        result.Failed.Should().BeTrue();
        result.FailureMessage.Should().Contain("Path");
    }

    [Fact]
    public void Validate_fails_when_Algorithm_is_not_a_defined_enum_member()
    {
        var options = ValidOptions();
        options.Algorithm = (SigningAlgorithm)999;

        var result = new PemFileSigningOptionsValidator().Validate(null, options);

        result.Failed.Should().BeTrue();
        result.FailureMessage.Should().Contain("Algorithm");
    }

    [Fact]
    public void Validate_fails_when_AddFile_duplicates_the_primary_Path()
    {
        var options = ValidOptions();
        options.AddFile(options.Path);

        var result = new PemFileSigningOptionsValidator().Validate(null, options);

        result.Failed.Should().BeTrue();
        result.FailureMessage.Should().Contain("duplicates");
    }

    [Fact]
    public void Validate_fails_when_two_additional_files_duplicate_each_other()
    {
        var options = ValidOptions();
        options.AddFile("/etc/zeekayda/rotated-in.pem");
        options.AddFile("/etc/zeekayda/rotated-in.pem");

        var result = new PemFileSigningOptionsValidator().Validate(null, options);

        result.Failed.Should().BeTrue();
        result.FailureMessage.Should().Contain("duplicates");
    }

    [Fact]
    public void Validate_succeeds_with_distinct_additional_files()
    {
        var options = ValidOptions();
        options.AddFile("/etc/zeekayda/rotated-in-1.pem");
        options.AddFile("/etc/zeekayda/rotated-in-2.pem");

        var result = new PemFileSigningOptionsValidator().Validate(null, options);

        result.Succeeded.Should().BeTrue();
    }
}
