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

    private static IReadOnlyList<string> Validate(PemFileSigningOptions options) =>
        new PemFileSigningOptionsValidator().Validate(null, options).Failures?.ToList() ?? [];

    // ── Current is required ──────────────────────────────────────────────────────────────────────

    [Fact]
    public void Succeeds_for_a_Current_only_configuration()
    {
        Validate(ValidOptions()).Should().BeEmpty("Previous and Next are independently optional");
    }

    [Fact]
    public void Fails_when_Current_is_not_configured()
    {
        var options = new PemFileSigningOptions { Current = null };

        Validate(options).Should().ContainSingle(e => e.Contains("Current must be set"));
    }

    [Fact]
    public void Fails_when_only_Previous_and_Next_are_configured()
    {
        var options = new PemFileSigningOptions
        {
            Previous = new PemSigningFile("/etc/zeekayda/previous.pem"),
            Next = new PemSigningFile("/etc/zeekayda/next.pem"),
        };

        Validate(options).Should().ContainSingle(e => e.Contains("Current must be set"));
    }

    [Fact]
    public void Succeeds_when_all_three_slots_are_configured()
    {
        var options = ValidOptions();
        options.Previous = new PemSigningFile("/etc/zeekayda/previous.pem");
        options.Next = new PemSigningFile("/etc/zeekayda/next.pem");

        Validate(options).Should().BeEmpty();
    }

    // ── Slot paths ───────────────────────────────────────────────────────────────────────────────

    [Theory]
    [InlineData("")]
    [InlineData("   ")]
    public void Fails_when_Currents_Path_is_empty_or_whitespace(string path)
    {
        var options = new PemFileSigningOptions { Current = new PemSigningFile(path) };

        Validate(options).Should().Contain(e => e.Contains("Current.Path must be set"));
    }

    [Theory]
    [InlineData("")]
    [InlineData("   ")]
    public void Fails_when_Previouss_Path_is_empty_or_whitespace(string path)
    {
        var options = ValidOptions();
        options.Previous = new PemSigningFile(path);

        Validate(options).Should().Contain(e => e.Contains("Previous.Path must be set"));
    }

    [Theory]
    [InlineData("")]
    [InlineData("   ")]
    public void Fails_when_Nexts_Path_is_empty_or_whitespace(string path)
    {
        var options = ValidOptions();
        options.Next = new PemSigningFile(path);

        Validate(options).Should().Contain(e => e.Contains("Next.Path must be set"));
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
    public void Fails_when_a_slots_KeyPath_is_empty_or_whitespace(string keyPath)
    {
        var options = new PemFileSigningOptions { Current = new PemSigningFile("/etc/zeekayda/current.pem", keyPath) };

        Validate(options).Should().Contain(e => e.Contains("Current.KeyPath must be null"));
    }

    // ── Algorithm ────────────────────────────────────────────────────────────────────────────────

    [Fact]
    public void Fails_when_Algorithm_is_not_a_defined_member()
    {
        var options = ValidOptions();
        options.Algorithm = (SigningAlgorithm)9999;

        Validate(options).Should().Contain(e => e.Contains("Algorithm value"));
    }

    // ── Pairwise distinct paths ──────────────────────────────────────────────────────────────────

    [Fact]
    public void Fails_when_Previous_and_Current_name_the_same_file()
    {
        var options = ValidOptions();
        options.Previous = new PemSigningFile("/etc/zeekayda/current.pem");

        Validate(options).Should().Contain(e => e.Contains("slots reference the same file"));
    }

    [Fact]
    public void Fails_when_Current_and_Next_name_the_same_file()
    {
        var options = ValidOptions();
        options.Next = new PemSigningFile("/etc/zeekayda/current.pem");

        Validate(options).Should().Contain(e => e.Contains("slots reference the same file"));
    }

    [Fact]
    public void Fails_when_Previous_and_Next_name_the_same_file()
    {
        var options = ValidOptions();
        options.Previous = new PemSigningFile("/etc/zeekayda/staged.pem");
        options.Next = new PemSigningFile("/etc/zeekayda/staged.pem");

        Validate(options).Should().Contain(e => e.Contains("slots reference the same file"));
    }

    [Fact]
    public void Fails_when_two_slots_name_the_same_file_via_different_but_equivalent_paths()
    {
        var options = new PemFileSigningOptions
        {
            Current = new PemSigningFile(Path.Combine(Path.GetTempPath(), "tls.pem")),
            Next = new PemSigningFile(Path.Combine(Path.GetTempPath(), ".", "tls.pem")),
        };

        Validate(options).Should().Contain(e => e.Contains("slots reference the same file"));
    }

    [Fact]
    public void Fails_when_one_slots_KeyPath_duplicates_another_slots_Path()
    {
        var options = new PemFileSigningOptions
        {
            Current = new PemSigningFile("/etc/zeekayda/current.crt", "/etc/zeekayda/shared.key"),
            Next = new PemSigningFile("/etc/zeekayda/shared.key"),
        };

        Validate(options).Should().Contain(e => e.Contains("slots reference the same file"));
    }

    [Fact]
    public void Fails_when_a_single_slots_Path_and_KeyPath_are_the_same_file()
    {
        var options = new PemFileSigningOptions
        {
            Current = new PemSigningFile("/etc/zeekayda/tls.pem", "/etc/zeekayda/tls.pem"),
        };

        Validate(options).Should().Contain(e => e.Contains("slots reference the same file"));
    }

    [Fact]
    public void Does_not_treat_two_independently_empty_paths_as_duplicates()
    {
        var options = new PemFileSigningOptions
        {
            Current = new PemSigningFile(""),
            Next = new PemSigningFile(""),
        };

        Validate(options).Should().NotContain(e => e.Contains("slots reference the same file"));
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
