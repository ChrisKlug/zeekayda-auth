using ZeeKayDa.Auth.Tokens;

namespace ZeeKayDa.Auth.FileSystem.Tests;

/// <summary>
/// Tests for <see cref="PfxFileSigningOptionsValidator"/>, the startup gate on the three configured
/// signing key slots.
/// </summary>
public sealed class PfxFileSigningOptionsValidatorTests
{
    private static Func<CancellationToken, Task<string>> Password() =>
        _ => Task.FromResult("a password");

    private static PfxFileSigningOptions ValidOptions() => new()
    {
        Current = new PfxFile("/etc/zeekayda/current.pfx", Password()),
    };

    private static IReadOnlyList<ZeeKayDaConfigurationFailure> Validate(PfxFileSigningOptions options)
    {
        try
        {
            new PfxFileSigningOptionsValidator().Validate(null, options);
            return [];
        }
        catch (ZeeKayDaConfigurationException exception)
        {
            return exception.AggregatedFailures;
        }
    }

    // ── Current is required ──────────────────────────────────────────────────────────────────────

    [Fact]
    public void Succeeds_for_a_Current_only_configuration()
    {
        Validate(ValidOptions()).Should().BeEmpty("Previous and Next are independently optional");
    }

    [Fact]
    public void Returns_Success_rather_than_merely_not_throwing_for_a_valid_configuration()
    {
        // Pins the Success result itself, so a validator that never returns Success cannot pass
        // startup on the strength of never having thrown.
        var result = new PfxFileSigningOptionsValidator().Validate(null, ValidOptions());

        result.Succeeded.Should().BeTrue();
    }

    [Fact]
    public void Fails_when_Current_is_not_configured()
    {
        var options = new PfxFileSigningOptions { Current = null };

        Validate(options).Should().ContainSingle(f => f.Code == "configuration.pfx_file_signing.current.missing")
            .Which.Message.Should().Contain("Current must be set");
    }

    [Fact]
    public void Succeeds_when_all_three_slots_are_configured_with_their_own_password_sources()
    {
        var options = ValidOptions();
        options.Previous = new PfxFile("/etc/zeekayda/previous.pfx", _ => Task.FromResult("previous"));
        options.Next = new PfxFile("/etc/zeekayda/next.pfx", _ => Task.FromResult("next"));

        Validate(options).Should().BeEmpty();
    }

    // ── Slot paths ───────────────────────────────────────────────────────────────────────────────

    [Theory]
    [InlineData("")]
    [InlineData("   ")]
    public void Fails_when_Currents_Path_is_empty_or_whitespace(string path)
    {
        var options = new PfxFileSigningOptions { Current = new PfxFile(path, Password()) };

        Validate(options).Should().Contain(f => f.Code == "configuration.pfx_file_signing.current.path.missing"
            && f.Message.Contains("Current.Path must be set"));
    }

    [Theory]
    [InlineData("")]
    [InlineData("   ")]
    public void Fails_when_a_published_only_slots_Path_is_empty_or_whitespace(string path)
    {
        var options = ValidOptions();
        options.Next = new PfxFile(path, Password());

        Validate(options).Should().Contain(f => f.Code == "configuration.pfx_file_signing.next.path.missing"
            && f.Message.Contains("Next.Path must be set"));
    }

    // ── Password sources ─────────────────────────────────────────────────────────────────────────

    [Fact]
    public void Fails_when_Currents_PasswordSource_is_null()
    {
        var options = new PfxFileSigningOptions { Current = new PfxFile("/etc/zeekayda/current.pfx", null!) };

        Validate(options).Should().Contain(f => f.Code == "configuration.pfx_file_signing.current.password_source.missing"
            && f.Message.Contains("Current.PasswordSource must be set"));
    }

    [Fact]
    public void Fails_when_a_published_only_slots_PasswordSource_is_null()
    {
        // A published-only bundle still needs its password: the certificate sits inside a
        // password-protected safe, even though the key bag is never decrypted.
        var options = ValidOptions();
        options.Previous = new PfxFile("/etc/zeekayda/previous.pfx", null!);

        Validate(options).Should().Contain(f => f.Code == "configuration.pfx_file_signing.previous.password_source.missing"
            && f.Message.Contains("Previous.PasswordSource must be set"));
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
    public void Fails_when_Previous_and_Current_name_the_same_file()
    {
        var options = ValidOptions();
        options.Previous = new PfxFile("/etc/zeekayda/current.pfx", Password());

        Validate(options).Should().Contain(f => f.Code == "configuration.pfx_file_signing.paths.duplicate"
            && f.Message.Contains("slots reference the same file"));
    }

    [Fact]
    public void Fails_when_Current_and_Next_name_the_same_file()
    {
        var options = ValidOptions();
        options.Next = new PfxFile("/etc/zeekayda/current.pfx", Password());

        Validate(options).Should().Contain(f => f.Code == "configuration.pfx_file_signing.paths.duplicate"
            && f.Message.Contains("slots reference the same file"));
    }

    [Fact]
    public void Fails_when_two_slots_name_the_same_file_via_different_but_equivalent_paths()
    {
        var options = new PfxFileSigningOptions
        {
            Current = new PfxFile(Path.Join(Path.GetTempPath(), "tls.pfx"), Password()),
            Next = new PfxFile(Path.Join(Path.GetTempPath(), ".", "tls.pfx"), Password()),
        };

        Validate(options).Should().Contain(f => f.Code == "configuration.pfx_file_signing.paths.duplicate"
            && f.Message.Contains("slots reference the same file"));
    }

    [Fact]
    public void Does_not_treat_two_independently_empty_paths_as_duplicates()
    {
        var options = new PfxFileSigningOptions
        {
            Current = new PfxFile("", Password()),
            Next = new PfxFile("", Password()),
        };

        Validate(options).Should().NotContain(f => f.Code == "configuration.pfx_file_signing.paths.duplicate");
    }

    [Fact]
    public void Fails_with_a_coded_configuration_exception_rather_than_an_unhandled_exception_for_a_slot_path_with_an_embedded_NUL()
    {
        var options = new PfxFileSigningOptions { Current = new PfxFile("/etc/zeekayda/tls\0.pfx", Password()) };

        var act = () => new PfxFileSigningOptionsValidator().Validate(null, options);

        act.Should().Throw<ZeeKayDaConfigurationException>("an unresolvable path is a configuration error like any other");
        Validate(options).Should().Contain(f => f.Code == "configuration.pfx_file_signing.paths.unresolvable"
            && f.Message.Contains("cannot resolve"));
    }

    // ── Aggregation ──────────────────────────────────────────────────────────────────────────────

    [Fact]
    public void Reports_every_problem_at_once_rather_than_stopping_at_the_first()
    {
        var options = new PfxFileSigningOptions
        {
            Current = new PfxFile("", null!),
        };
        options.Algorithm = (SigningAlgorithm)9999;

        Validate(options).Should().HaveCount(3);
    }
}
