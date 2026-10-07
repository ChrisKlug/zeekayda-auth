using Microsoft.Extensions.Options;
using ZeeKayDa.Auth.Tokens;

namespace ZeeKayDa.Auth.FileSystem.Tests;

/// <summary>
/// Tests for <see cref="PemFileSigningOptionsValidator"/>, the startup gate on the listed signing files.
/// </summary>
public sealed class PemFileSigningOptionsValidatorTests
{
    private static PemFileSigningOptions ValidOptions() => Options(new PemSigningFile("/etc/zeekayda/current.pem"));

    private static PemFileSigningOptions Options(params PemSigningFile?[] files)
    {
        var options = new PemFileSigningOptions { Algorithm = SigningAlgorithm.RS256 };
        foreach (var file in files)
            options.Files.Add(file!);

        return options;
    }

    private static IReadOnlyList<ZeeKayDaConfigurationFailure> Validate(PemFileSigningOptions options)
    {
        try
        {
            ((IValidateOptions<PemFileSigningOptions>)new PemFileSigningOptionsValidator()).Validate(null, options);
            return [];
        }
        catch (ZeeKayDaConfigurationException exception)
        {
            return exception.AggregatedFailures;
        }
    }

    // ── Files ────────────────────────────────────────────────────────────────────────────────────

    [Fact]
    public void Succeeds_for_a_single_file()
    {
        Validate(ValidOptions()).Should().BeEmpty();
    }

    [Fact]
    public void Returns_Success_rather_than_merely_not_throwing_for_a_valid_configuration()
    {
        // Pins the Success result itself, so a validator that never returns Success cannot pass
        // startup on the strength of never having thrown.
        var result = ((IValidateOptions<PemFileSigningOptions>)new PemFileSigningOptionsValidator()).Validate(null, ValidOptions());

        result.Succeeded.Should().BeTrue();
    }

    [Fact]
    public void Succeeds_for_several_distinct_files()
    {
        var options = Options(
            new PemSigningFile("/etc/zeekayda/a.pem"),
            new PemSigningFile("/etc/zeekayda/b.crt", "/etc/zeekayda/b.key"),
            new PemSigningFile("/etc/zeekayda/c.pem"));

        Validate(options).Should().BeEmpty();
    }

    [Fact]
    public void Fails_when_no_file_is_listed()
    {
        Validate(Options()).Should().ContainSingle(f => f.Code == "configuration.pem_file_signing.files.empty")
            .Which.Message.Should().Contain("at least one PEM file");
    }

    [Fact]
    public void Fails_when_a_listed_entry_is_null()
    {
        var options = ValidOptions();
        options.Files.Add(null!);

        Validate(options).Should().ContainSingle(f => f.Code == "configuration.pem_file_signing.files.null_entry")
            .Which.Message.Should().Contain("Files[1]");
    }

    [Theory]
    [InlineData("")]
    [InlineData("   ")]
    public void Fails_when_a_files_Path_is_empty_or_whitespace(string path)
    {
        var options = Options(new PemSigningFile(path));

        Validate(options).Should().Contain(f => f.Code == "configuration.pem_file_signing.files.path.missing"
            && f.Message.Contains("Files[0].Path must be set"));
    }

    [Fact]
    public void Names_the_index_of_the_file_whose_Path_is_missing()
    {
        var options = Options(new PemSigningFile("/etc/zeekayda/ok.pem"), new PemSigningFile(""));

        Validate(options).Should().Contain(f => f.Code == "configuration.pem_file_signing.files.path.missing"
            && f.Message.Contains("Files[1].Path"));
    }

    [Fact]
    public void Succeeds_when_a_files_KeyPath_is_null()
    {
        var options = Options(new PemSigningFile("/etc/zeekayda/current.pem", null));

        Validate(options).Should().BeEmpty("a null KeyPath means Path is a combined cert+key file");
    }

    [Theory]
    [InlineData("")]
    [InlineData("   ")]
    public void Fails_when_a_files_KeyPath_is_empty_or_whitespace(string keyPath)
    {
        var options = Options(new PemSigningFile("/etc/zeekayda/current.pem", keyPath));

        Validate(options).Should().Contain(f => f.Code == "configuration.pem_file_signing.files.key_path.blank"
            && f.Message.Contains("Files[0].KeyPath must be null"));
    }

    // ── Algorithm ────────────────────────────────────────────────────────────────────────────────

    [Fact]
    public void Fails_when_Algorithm_is_not_a_defined_member()
    {
        var options = ValidOptions();
        options.Algorithm = (SigningAlgorithm)9999;

        Validate(options).Should().Contain(f => f.Code == "configuration.pem_file_signing.algorithm.undefined_value"
            && f.Message.Contains("Algorithm value"));
    }

    // ── Pairwise distinct paths ──────────────────────────────────────────────────────────────────

    [Fact]
    public void Fails_when_two_files_name_the_same_Path()
    {
        var options = Options(
            new PemSigningFile("/etc/zeekayda/current.pem"),
            new PemSigningFile("/etc/zeekayda/current.pem"));

        Validate(options).Should().Contain(f => f.Code == "configuration.pem_file_signing.paths.duplicate"
            && f.Message.Contains("reference the same file"));
    }

    [Fact]
    public void Fails_when_two_files_name_the_same_file_via_different_but_equivalent_paths()
    {
        var options = Options(
            new PemSigningFile(Path.Join(Path.GetTempPath(), "tls.pem")),
            new PemSigningFile(Path.Join(Path.GetTempPath(), ".", "tls.pem")));

        Validate(options).Should().Contain(f => f.Code == "configuration.pem_file_signing.paths.duplicate");
    }

    [Fact]
    public void Fails_when_one_files_KeyPath_duplicates_another_files_Path()
    {
        var options = Options(
            new PemSigningFile("/etc/zeekayda/a.crt", "/etc/zeekayda/shared.key"),
            new PemSigningFile("/etc/zeekayda/shared.key"));

        Validate(options).Should().Contain(f => f.Code == "configuration.pem_file_signing.paths.duplicate");
    }

    [Fact]
    public void Fails_when_two_files_share_a_KeyPath()
    {
        var options = Options(
            new PemSigningFile("/etc/zeekayda/a.crt", "/etc/zeekayda/shared.key"),
            new PemSigningFile("/etc/zeekayda/b.crt", "/etc/zeekayda/shared.key"));

        Validate(options).Should().Contain(f => f.Code == "configuration.pem_file_signing.paths.duplicate");
    }

    [Fact]
    public void Fails_when_a_single_files_Path_and_KeyPath_are_the_same_file()
    {
        var options = Options(new PemSigningFile("/etc/zeekayda/tls.pem", "/etc/zeekayda/tls.pem"));

        Validate(options).Should().Contain(f => f.Code == "configuration.pem_file_signing.paths.duplicate");
    }

    [Fact]
    public void Does_not_treat_two_independently_empty_paths_as_duplicates()
    {
        var options = Options(new PemSigningFile(""), new PemSigningFile(""));

        Validate(options).Should().NotContain(f => f.Code == "configuration.pem_file_signing.paths.duplicate");
    }

    // ── Paths the OS cannot resolve ──────────────────────────────────────────────────────────────

    [Fact]
    public void Fails_with_a_coded_configuration_exception_rather_than_an_unhandled_exception_for_a_path_with_an_embedded_NUL()
    {
        var options = Options(new PemSigningFile("/etc/zeekayda/tls\0.pem"));

        var act = () => ((IValidateOptions<PemFileSigningOptions>)new PemFileSigningOptionsValidator()).Validate(null, options);

        act.Should().Throw<ZeeKayDaConfigurationException>("an unresolvable path is a configuration error like any other");
        Validate(options).Should().Contain(f => f.Code == "configuration.pem_file_signing.paths.unresolvable"
            && f.Message.Contains("cannot resolve"));
    }

    [Fact]
    public void Fails_with_a_coded_configuration_exception_for_a_KeyPath_with_an_embedded_NUL()
    {
        var options = Options(new PemSigningFile("/etc/zeekayda/ok.crt", "/etc/zeekayda/key\0.pem"));

        Validate(options).Should().Contain(f => f.Code == "configuration.pem_file_signing.paths.unresolvable");
    }

    // ── Aggregation ──────────────────────────────────────────────────────────────────────────────

    [Fact]
    public void Reports_every_problem_at_once_rather_than_stopping_at_the_first()
    {
        var options = Options(new PemSigningFile(""));
        options.Algorithm = (SigningAlgorithm)9999;

        Validate(options).Should().HaveCount(2);
    }
}
