using Microsoft.Extensions.Options;
using ZeeKayDa.Auth.Tokens;

namespace ZeeKayDa.Auth.FileSystem.Tests;

/// <summary>
/// Tests for <see cref="PfxFileSigningOptionsValidator"/>, the startup gate on the listed signing files.
/// </summary>
public sealed class PfxFileSigningOptionsValidatorTests
{
    private static Func<CancellationToken, Task<string>> Password() =>
        _ => Task.FromResult("a password");

    private static PfxFileSigningOptions ValidOptions() =>
        Options(new PfxFile("/etc/zeekayda/current.pfx", Password()));

    private static PfxFileSigningOptions Options(params PfxFile?[] files)
    {
        var options = new PfxFileSigningOptions();
        foreach (var file in files)
            options.Files.Add(file!);

        return options;
    }

    private static IReadOnlyList<ZeeKayDaConfigurationFailure> Validate(PfxFileSigningOptions options)
    {
        try
        {
            ((IValidateOptions<PfxFileSigningOptions>)new PfxFileSigningOptionsValidator()).Validate(null, options);
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
        var result = ((IValidateOptions<PfxFileSigningOptions>)new PfxFileSigningOptionsValidator()).Validate(null, ValidOptions());

        result.Succeeded.Should().BeTrue();
    }

    [Fact]
    public void Succeeds_for_several_files_with_their_own_password_sources()
    {
        var options = Options(
            new PfxFile("/etc/zeekayda/a.pfx", _ => Task.FromResult("a")),
            new PfxFile("/etc/zeekayda/b.pfx", _ => Task.FromResult("b")));

        Validate(options).Should().BeEmpty();
    }

    [Fact]
    public void Fails_when_no_file_is_listed()
    {
        Validate(Options()).Should().ContainSingle(f => f.Code == "configuration.pfx_file_signing.files.empty")
            .Which.Message.Should().Contain("at least one PFX file");
    }

    [Fact]
    public void Fails_when_a_listed_entry_is_null()
    {
        var options = ValidOptions();
        options.Files.Add(null!);

        Validate(options).Should().ContainSingle(f => f.Code == "configuration.pfx_file_signing.files.null_entry")
            .Which.Message.Should().Contain("Files[1]");
    }

    [Theory]
    [InlineData("")]
    [InlineData("   ")]
    public void Fails_when_a_files_Path_is_empty_or_whitespace(string path)
    {
        var options = Options(new PfxFile(path, Password()));

        Validate(options).Should().Contain(f => f.Code == "configuration.pfx_file_signing.files.path.missing"
            && f.Message.Contains("Files[0].Path must be set"));
    }

    [Fact]
    public void Names_the_index_of_the_file_whose_PasswordSource_is_null()
    {
        var options = Options(
            new PfxFile("/etc/zeekayda/ok.pfx", Password()),
            new PfxFile("/etc/zeekayda/bad.pfx", null!));

        Validate(options).Should().Contain(f => f.Code == "configuration.pfx_file_signing.files.password_source.missing"
            && f.Message.Contains("Files[1].PasswordSource must be set"));
    }

    // ── Algorithm ────────────────────────────────────────────────────────────────────────────────

    [Fact]
    public void Fails_when_Algorithm_is_not_a_defined_member()
    {
        var options = ValidOptions();
        options.Algorithm = (SigningAlgorithm)9999;

        Validate(options).Should().Contain(f => f.Code == "configuration.pfx_file_signing.algorithm.undefined_value"
            && f.Message.Contains("Algorithm value"));
    }

    // ── Pairwise distinct paths ──────────────────────────────────────────────────────────────────

    [Fact]
    public void Fails_when_two_files_name_the_same_Path()
    {
        var options = Options(
            new PfxFile("/etc/zeekayda/current.pfx", Password()),
            new PfxFile("/etc/zeekayda/current.pfx", Password()));

        Validate(options).Should().Contain(f => f.Code == "configuration.pfx_file_signing.paths.duplicate"
            && f.Message.Contains("reference the same file"));
    }

    [Fact]
    public void Fails_when_two_files_name_the_same_file_via_different_but_equivalent_paths()
    {
        var options = Options(
            new PfxFile(Path.Join(Path.GetTempPath(), "tls.pfx"), Password()),
            new PfxFile(Path.Join(Path.GetTempPath(), ".", "tls.pfx"), Password()));

        Validate(options).Should().Contain(f => f.Code == "configuration.pfx_file_signing.paths.duplicate");
    }

    [Fact]
    public void Does_not_treat_two_independently_empty_paths_as_duplicates()
    {
        var options = Options(new PfxFile("", Password()), new PfxFile("", Password()));

        Validate(options).Should().NotContain(f => f.Code == "configuration.pfx_file_signing.paths.duplicate");
    }

    [Fact]
    public void Fails_with_a_coded_configuration_exception_rather_than_an_unhandled_exception_for_a_path_with_an_embedded_NUL()
    {
        var options = Options(new PfxFile("/etc/zeekayda/tls\0.pfx", Password()));

        var act = () => ((IValidateOptions<PfxFileSigningOptions>)new PfxFileSigningOptionsValidator()).Validate(null, options);

        act.Should().Throw<ZeeKayDaConfigurationException>("an unresolvable path is a configuration error like any other");
        Validate(options).Should().Contain(f => f.Code == "configuration.pfx_file_signing.paths.unresolvable"
            && f.Message.Contains("cannot resolve"));
    }

    // ── Aggregation ──────────────────────────────────────────────────────────────────────────────

    [Fact]
    public void Reports_every_problem_at_once_rather_than_stopping_at_the_first()
    {
        var options = Options(new PfxFile("", null!));
        options.Algorithm = (SigningAlgorithm)9999;

        Validate(options).Should().HaveCount(3);
    }
}
