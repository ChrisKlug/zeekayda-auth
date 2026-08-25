using ZeeKayDa.Auth.Tokens;

namespace ZeeKayDa.Auth.FileSystem.Tests;

/// <summary>
/// Tests for <see cref="PfxFileSigningOptionsValidator"/>, the startup gate on the three configured
/// signing key slots.
/// </summary>
public sealed class PfxFileSigningOptionsValidatorTests
{
    private static Func<CancellationToken, ValueTask<string>> Password() =>
        _ => ValueTask.FromResult("a password");

    private static PfxFileSigningOptions ValidOptions() => new()
    {
        Current = new PfxSigningFile("/etc/zeekayda/current.pfx", Password()),
    };

    private static IReadOnlyList<string> Validate(PfxFileSigningOptions options) =>
        new PfxFileSigningOptionsValidator().Validate(null, options).Failures?.ToList() ?? [];

    // ── Current is required ──────────────────────────────────────────────────────────────────────

    [Fact]
    public void Succeeds_for_a_Current_only_configuration()
    {
        Validate(ValidOptions()).Should().BeEmpty("Previous and Next are independently optional");
    }

    [Fact]
    public void Fails_when_Current_is_not_configured()
    {
        var options = new PfxFileSigningOptions { Current = null };

        Validate(options).Should().ContainSingle(e => e.Contains("Current must be set"));
    }

    [Fact]
    public void Succeeds_when_all_three_slots_are_configured_with_their_own_password_sources()
    {
        var options = ValidOptions();
        options.Previous = new PfxSigningFile("/etc/zeekayda/previous.pfx", _ => ValueTask.FromResult("previous"));
        options.Next = new PfxSigningFile("/etc/zeekayda/next.pfx", _ => ValueTask.FromResult("next"));

        Validate(options).Should().BeEmpty();
    }

    // ── Slot paths ───────────────────────────────────────────────────────────────────────────────

    [Theory]
    [InlineData("")]
    [InlineData("   ")]
    public void Fails_when_Currents_Path_is_empty_or_whitespace(string path)
    {
        var options = new PfxFileSigningOptions { Current = new PfxSigningFile(path, Password()) };

        Validate(options).Should().Contain(e => e.Contains("Current.Path must be set"));
    }

    [Theory]
    [InlineData("")]
    [InlineData("   ")]
    public void Fails_when_a_published_only_slots_Path_is_empty_or_whitespace(string path)
    {
        var options = ValidOptions();
        options.Next = new PfxSigningFile(path, Password());

        Validate(options).Should().Contain(e => e.Contains("Next.Path must be set"));
    }

    // ── Password sources ─────────────────────────────────────────────────────────────────────────

    [Fact]
    public void Fails_when_Currents_PasswordSource_is_null()
    {
        var options = new PfxFileSigningOptions { Current = new PfxSigningFile("/etc/zeekayda/current.pfx", null!) };

        Validate(options).Should().Contain(e => e.Contains("Current.PasswordSource must be set"));
    }

    [Fact]
    public void Fails_when_a_published_only_slots_PasswordSource_is_null()
    {
        // A published-only bundle still needs its password: the certificate sits inside a
        // password-protected safe, even though the key bag is never decrypted.
        var options = ValidOptions();
        options.Previous = new PfxSigningFile("/etc/zeekayda/previous.pfx", null!);

        Validate(options).Should().Contain(e => e.Contains("Previous.PasswordSource must be set"));
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
        options.Previous = new PfxSigningFile("/etc/zeekayda/current.pfx", Password());

        Validate(options).Should().Contain(e => e.Contains("slots reference the same file"));
    }

    [Fact]
    public void Fails_when_Current_and_Next_name_the_same_file()
    {
        var options = ValidOptions();
        options.Next = new PfxSigningFile("/etc/zeekayda/current.pfx", Password());

        Validate(options).Should().Contain(e => e.Contains("slots reference the same file"));
    }

    [Fact]
    public void Fails_when_two_slots_name_the_same_file_via_different_but_equivalent_paths()
    {
        var options = new PfxFileSigningOptions
        {
            Current = new PfxSigningFile(Path.Join(Path.GetTempPath(), "tls.pfx"), Password()),
            Next = new PfxSigningFile(Path.Join(Path.GetTempPath(), ".", "tls.pfx"), Password()),
        };

        Validate(options).Should().Contain(e => e.Contains("slots reference the same file"));
    }

    [Fact]
    public void Does_not_treat_two_independently_empty_paths_as_duplicates()
    {
        var options = new PfxFileSigningOptions
        {
            Current = new PfxSigningFile("", Password()),
            Next = new PfxSigningFile("", Password()),
        };

        Validate(options).Should().NotContain(e => e.Contains("slots reference the same file"));
    }

    [Fact]
    public void Fails_rather_than_throwing_when_a_slot_path_contains_an_embedded_NUL()
    {
        var options = new PfxFileSigningOptions { Current = new PfxSigningFile("/etc/zeekayda/tls\0.pfx", Password()) };

        var act = () => Validate(options);

        act.Should().NotThrow("an unresolvable path is a configuration error like any other");
        Validate(options).Should().Contain(e => e.Contains("cannot resolve"));
    }

    // ── Aggregation ──────────────────────────────────────────────────────────────────────────────

    [Fact]
    public void Reports_every_problem_at_once_rather_than_stopping_at_the_first()
    {
        var options = new PfxFileSigningOptions
        {
            Current = new PfxSigningFile("", null!),
        };
        options.Algorithm = (SigningAlgorithm)9999;

        Validate(options).Should().HaveCount(3);
    }
}
