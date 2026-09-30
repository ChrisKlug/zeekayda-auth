using ZeeKayDa.Auth.Tokens;

namespace ZeeKayDa.Auth.FileSystem.Tests;

/// <summary>
/// Tests for <see cref="PemFileSigningOptionsValidator"/>, the startup gate on the three configured
/// signing key slots.
/// </summary>
public sealed class PemFileSigningOptionsValidatorTests
{
    private static PemFileSigningOptions ValidOptions() => new()
    {
        Current = new PemSigningFile("/etc/zeekayda/current.pem"),
        Algorithm = SigningAlgorithm.RS256,
    };

    private static IReadOnlyList<ZeeKayDaConfigurationFailure> Validate(PemFileSigningOptions options)
    {
        try
        {
            new PemFileSigningOptionsValidator().Validate(null, options);
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
        var result = new PemFileSigningOptionsValidator().Validate(null, ValidOptions());

        result.Succeeded.Should().BeTrue();
    }

    [Fact]
    public void Fails_when_Current_is_not_configured()
    {
        var options = new PemFileSigningOptions { Current = null };

        Validate(options).Should().ContainSingle(f => f.Code == "configuration.pem_file_signing.current.missing")
            .Which.Message.Should().Contain("Current must be set");
    }

    [Fact]
    public void Fails_when_only_Previous_and_Next_are_configured()
    {
        var options = new PemFileSigningOptions
        {
            Previous = new PemCertificateFile("/etc/zeekayda/previous.pem"),
            Next = new PemCertificateFile("/etc/zeekayda/next.pem"),
        };

        Validate(options).Should().ContainSingle(f => f.Code == "configuration.pem_file_signing.current.missing")
            .Which.Message.Should().Contain("Current must be set");
    }

    [Fact]
    public void Succeeds_when_all_three_slots_are_configured()
    {
        var options = ValidOptions();
        options.Previous = new PemCertificateFile("/etc/zeekayda/previous.pem");
        options.Next = new PemCertificateFile("/etc/zeekayda/next.pem");

        Validate(options).Should().BeEmpty();
    }

    // ── Slot paths ───────────────────────────────────────────────────────────────────────────────

    [Theory]
    [InlineData("")]
    [InlineData("   ")]
    public void Fails_when_Currents_Path_is_empty_or_whitespace(string path)
    {
        var options = new PemFileSigningOptions { Current = new PemSigningFile(path) };

        Validate(options).Should().Contain(f => f.Code == "configuration.pem_file_signing.current.path.missing"
            && f.Message.Contains("Current.Path must be set"));
    }

    [Theory]
    [InlineData("")]
    [InlineData("   ")]
    public void Fails_when_Previouss_Path_is_empty_or_whitespace(string path)
    {
        var options = ValidOptions();
        options.Previous = new PemCertificateFile(path);

        Validate(options).Should().Contain(f => f.Code == "configuration.pem_file_signing.previous.path.missing"
            && f.Message.Contains("Previous.Path must be set"));
    }

    [Theory]
    [InlineData("")]
    [InlineData("   ")]
    public void Fails_when_Nexts_Path_is_empty_or_whitespace(string path)
    {
        var options = ValidOptions();
        options.Next = new PemCertificateFile(path);

        Validate(options).Should().Contain(f => f.Code == "configuration.pem_file_signing.next.path.missing"
            && f.Message.Contains("Next.Path must be set"));
    }

    [Fact]
    public void Succeeds_when_a_slots_KeyPath_is_null()
    {
        var options = new PemFileSigningOptions { Current = new PemSigningFile("/etc/zeekayda/current.pem", null) };

        Validate(options).Should().BeEmpty("a null KeyPath means Path is a combined cert+key file");
    }

    [Theory]
    [InlineData("")]
    [InlineData("   ")]
    public void Fails_when_Currents_KeyPath_is_empty_or_whitespace(string keyPath)
    {
        var options = new PemFileSigningOptions { Current = new PemSigningFile("/etc/zeekayda/current.pem", keyPath) };

        Validate(options).Should().Contain(f => f.Code == "configuration.pem_file_signing.current.key_path.blank"
            && f.Message.Contains("Current.KeyPath must be null"));
    }

    [Fact]
    public void A_published_only_slot_cannot_name_a_private_key_file_at_all()
    {
        // PemCertificateFile has no KeyPath member, so there is no validator rule to test here — the
        // rejection is the type. This test exists to fail if Previous or Next is ever widened back to
        // PemSigningFile, which would silently reopen a path the framework promises to
        // permission-check but never opens.
        typeof(PemFileSigningOptions).GetProperty(nameof(PemFileSigningOptions.Previous))!
            .PropertyType.Should().Be<PemCertificateFile>();
        typeof(PemFileSigningOptions).GetProperty(nameof(PemFileSigningOptions.Next))!
            .PropertyType.Should().Be<PemCertificateFile>();
        typeof(PemCertificateFile).GetProperty("KeyPath").Should().BeNull();
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
    public void Fails_when_Previous_and_Current_name_the_same_file()
    {
        var options = ValidOptions();
        options.Previous = new PemCertificateFile("/etc/zeekayda/current.pem");

        Validate(options).Should().Contain(f => f.Code == "configuration.pem_file_signing.paths.duplicate"
            && f.Message.Contains("slots reference the same file"));
    }

    [Fact]
    public void Fails_when_Current_and_Next_name_the_same_file()
    {
        var options = ValidOptions();
        options.Next = new PemCertificateFile("/etc/zeekayda/current.pem");

        Validate(options).Should().Contain(f => f.Code == "configuration.pem_file_signing.paths.duplicate"
            && f.Message.Contains("slots reference the same file"));
    }

    [Fact]
    public void Fails_when_Previous_and_Next_name_the_same_file()
    {
        var options = ValidOptions();
        options.Previous = new PemCertificateFile("/etc/zeekayda/staged.pem");
        options.Next = new PemCertificateFile("/etc/zeekayda/staged.pem");

        Validate(options).Should().Contain(f => f.Code == "configuration.pem_file_signing.paths.duplicate"
            && f.Message.Contains("slots reference the same file"));
    }

    [Fact]
    public void Fails_when_two_slots_name_the_same_file_via_different_but_equivalent_paths()
    {
        var options = new PemFileSigningOptions
        {
            Current = new PemSigningFile(Path.Join(Path.GetTempPath(), "tls.pem")),
            Next = new PemCertificateFile(Path.Join(Path.GetTempPath(), ".", "tls.pem")),
        };

        Validate(options).Should().Contain(f => f.Code == "configuration.pem_file_signing.paths.duplicate"
            && f.Message.Contains("slots reference the same file"));
    }

    [Fact]
    public void Fails_when_Currents_KeyPath_duplicates_another_slots_Path()
    {
        var options = new PemFileSigningOptions
        {
            Current = new PemSigningFile("/etc/zeekayda/current.crt", "/etc/zeekayda/shared.key"),
            Next = new PemCertificateFile("/etc/zeekayda/shared.key"),
        };

        Validate(options).Should().Contain(f => f.Code == "configuration.pem_file_signing.paths.duplicate"
            && f.Message.Contains("slots reference the same file"));
    }

    [Fact]
    public void Fails_when_a_single_slots_Path_and_KeyPath_are_the_same_file()
    {
        var options = new PemFileSigningOptions
        {
            Current = new PemSigningFile("/etc/zeekayda/tls.pem", "/etc/zeekayda/tls.pem"),
        };

        Validate(options).Should().Contain(f => f.Code == "configuration.pem_file_signing.paths.duplicate"
            && f.Message.Contains("slots reference the same file"));
    }

    [Fact]
    public void Does_not_treat_two_independently_empty_paths_as_duplicates()
    {
        var options = new PemFileSigningOptions
        {
            Current = new PemSigningFile(""),
            Next = new PemCertificateFile(""),
        };

        Validate(options).Should().NotContain(f => f.Code == "configuration.pem_file_signing.paths.duplicate");
    }

    // ── Paths the OS cannot resolve ──────────────────────────────────────────────────────────────

    [Fact]
    public void Fails_with_a_coded_configuration_exception_rather_than_an_unhandled_exception_for_a_slot_path_with_an_embedded_NUL()
    {
        var options = new PemFileSigningOptions { Current = new PemSigningFile("/etc/zeekayda/tls\0.pem") };

        var act = () => new PemFileSigningOptionsValidator().Validate(null, options);

        act.Should().Throw<ZeeKayDaConfigurationException>("an unresolvable path is a configuration error like any other");
        Validate(options).Should().Contain(f => f.Code == "configuration.pem_file_signing.paths.unresolvable"
            && f.Message.Contains("cannot resolve"));
    }

    [Fact]
    public void Fails_with_a_coded_configuration_exception_for_a_published_only_slot_path_with_an_embedded_NUL()
    {
        var options = ValidOptions();
        options.Next = new PemCertificateFile("/etc/zeekayda/next\0.pem");

        var act = () => new PemFileSigningOptionsValidator().Validate(null, options);

        act.Should().Throw<ZeeKayDaConfigurationException>();
        Validate(options).Should().Contain(f => f.Code == "configuration.pem_file_signing.paths.unresolvable"
            && f.Message.Contains("cannot resolve"));
    }

    // ── Aggregation ──────────────────────────────────────────────────────────────────────────────

    [Fact]
    public void Reports_every_problem_at_once_rather_than_stopping_at_the_first()
    {
        var options = new PemFileSigningOptions
        {
            Current = new PemSigningFile(""),
            Algorithm = (SigningAlgorithm)9999,
        };

        Validate(options).Should().HaveCount(2);
    }
}
