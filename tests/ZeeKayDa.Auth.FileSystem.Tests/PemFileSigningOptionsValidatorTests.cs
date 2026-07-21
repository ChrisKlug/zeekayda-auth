using ZeeKayDa.Auth.Tokens;

namespace ZeeKayDa.Auth.FileSystem.Tests;

public sealed class PemFileSigningOptionsValidatorTests
{
    private static PemFileSigningOptions ValidOptions() => new()
    {
        Path = "/etc/zeekayda/signing.pem",
        Algorithm = SigningAlgorithm.RS256,
    };

    [Fact]
    public void Validate_succeeds_for_valid_options()
    {
        var result = new PemFileSigningOptionsValidator().Validate(null, ValidOptions());

        result.Succeeded.Should().BeTrue();
    }

    // ── PublicationLead (ADR 0015 §1) ─────────────────────────────────────────────────────────────

    [Theory]
    [InlineData(0)]
    [InlineData(-1)]
    public void Validate_fails_when_PublicationLead_is_zero_or_negative(int seconds)
    {
        var options = ValidOptions();
        options.PublicationLead = TimeSpan.FromSeconds(seconds);

        var result = new PemFileSigningOptionsValidator().Validate(null, options);

        result.Failed.Should().BeTrue();
        result.FailureMessage.Should().Contain("PublicationLead");
    }

    [Fact]
    public void Validate_succeeds_with_a_positive_PublicationLead()
    {
        var options = ValidOptions();
        options.PublicationLead = TimeSpan.FromMinutes(30);

        var result = new PemFileSigningOptionsValidator().Validate(null, options);

        result.Succeeded.Should().BeTrue();
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

    // ── Split cert/key files (issue #405) ────────────────────────────────────────────────────────

    [Fact]
    public void Validate_succeeds_when_KeyPath_is_a_distinct_non_empty_path()
    {
        var options = ValidOptions();
        options.KeyPath = "/etc/zeekayda/signing.key";

        var result = new PemFileSigningOptionsValidator().Validate(null, options);

        result.Succeeded.Should().BeTrue();
    }

    [Theory]
    [InlineData("")]
    [InlineData("   ")]
    public void Validate_fails_when_KeyPath_is_whitespace_only(string keyPath)
    {
        var options = ValidOptions();
        options.KeyPath = keyPath;

        var result = new PemFileSigningOptionsValidator().Validate(null, options);

        result.Failed.Should().BeTrue();
        result.FailureMessage.Should().Contain("KeyPath");
    }

    [Fact]
    public void Validate_fails_when_KeyPath_duplicates_the_primary_Path()
    {
        var options = ValidOptions();
        options.KeyPath = options.Path;

        var result = new PemFileSigningOptionsValidator().Validate(null, options);

        result.Failed.Should().BeTrue();
        result.FailureMessage.Should().Contain("duplicates");
    }

    [Fact]
    public void Validate_fails_when_an_additional_files_KeyPath_duplicates_the_primary_KeyPath()
    {
        var options = ValidOptions();
        options.KeyPath = "/etc/zeekayda/signing.key";
        options.AddFile("/etc/zeekayda/rotated-in.pem", options.KeyPath);

        var result = new PemFileSigningOptionsValidator().Validate(null, options);

        result.Failed.Should().BeTrue();
        result.FailureMessage.Should().Contain("duplicates");
    }

    [Fact]
    public void Validate_succeeds_with_a_distinct_split_additional_file()
    {
        var options = ValidOptions();
        options.AddFile("/etc/zeekayda/rotated-in.pem", "/etc/zeekayda/rotated-in.key");

        var result = new PemFileSigningOptionsValidator().Validate(null, options);

        result.Succeeded.Should().BeTrue();
    }

    // ── Path normalization for duplicate detection (issue #405 follow-up) ───────────────────────────

    [Fact]
    public void Validate_fails_when_AddFile_duplicates_the_primary_Path_via_redundant_separators()
    {
        var options = ValidOptions();
        options.Path = "/etc/zeekayda//signing.pem";
        options.AddFile("/etc/zeekayda/signing.pem");

        var result = new PemFileSigningOptionsValidator().Validate(null, options);

        result.Failed.Should().BeTrue();
        result.FailureMessage.Should().Contain("duplicates");
    }

    [Fact]
    public void Validate_fails_when_AddFile_duplicates_the_primary_Path_via_a_relative_segment()
    {
        var options = ValidOptions();
        options.Path = "/etc/zeekayda/signing.pem";
        options.AddFile("/etc/zeekayda/other/../signing.pem");

        var result = new PemFileSigningOptionsValidator().Validate(null, options);

        result.Failed.Should().BeTrue();
        result.FailureMessage.Should().Contain("duplicates");
    }
}
