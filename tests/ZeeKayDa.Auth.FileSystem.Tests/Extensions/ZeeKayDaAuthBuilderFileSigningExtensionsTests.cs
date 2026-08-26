// These tests exercise the DI wiring for AddPemFileSigning/AddPfxFileSigning end to end — a real
// ServiceCollection / ZeeKayDaAuthBuilder / ServiceProvider. Neither extension method ever calls
// GetSigningKeysAsync during registration, so a real (but never-loaded) path is sufficient here;
// the real-filesystem load path itself is covered by PemFileSigningJwtSigningServiceTests /
// PfxFileSigningJwtSigningServiceTests and Integration/FileSigningIntegrationTests.

using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using ZeeKayDa.Auth;
using ZeeKayDa.Auth.FileSystem;
using ZeeKayDa.Auth.Tokens;

namespace ZeeKayDa.Auth.FileSystem.Tests.Extensions;

public sealed class ZeeKayDaAuthBuilderFileSigningExtensionsTests
{
    private const string PemPath = "/etc/zeekayda/signing.pem";
    private const string PfxPath = "/etc/zeekayda/signing.pfx";

    private static ZeeKayDaAuthBuilder NewBuilder()
    {
        var services = new ServiceCollection();
        services.AddSingleton(typeof(ILogger<>), typeof(NullLogger<>));
        return new ZeeKayDaAuthBuilder(services);
    }

    private static Func<CancellationToken, ValueTask<string>> AnyPassword() => _ => ValueTask.FromResult("password");

    // ── AddPemFileSigning: argument validation ───────────────────────────────────────────────────

    [Fact]
    public void AddPemFileSigning_throws_ArgumentNullException_when_builder_is_null()
    {
        var act = () => ((ZeeKayDaAuthBuilder)null!).AddPemFileSigning(PemPath, SigningAlgorithm.RS256);

        act.Should().Throw<ArgumentNullException>().WithParameterName("builder");
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("   ")]
    public void AddPemFileSigning_throws_ArgumentException_when_path_is_null_or_whitespace(string? path)
    {
        var builder = NewBuilder();

        var act = () => builder.AddPemFileSigning(path!, SigningAlgorithm.RS256);

        act.Should().Throw<ArgumentException>().WithParameterName("path");
    }

    // ── AddPemFileSigning(path, algorithm, keyPath: ...): the split-file case (issue #405) ──────────

    [Fact]
    public void AddPemFileSigning_with_keyPath_throws_ArgumentNullException_when_builder_is_null()
    {
        var act = () => ((ZeeKayDaAuthBuilder)null!).AddPemFileSigning(PemPath, SigningAlgorithm.RS256, "/etc/zeekayda/signing.key");

        act.Should().Throw<ArgumentNullException>().WithParameterName("builder");
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("   ")]
    public void AddPemFileSigning_with_keyPath_throws_ArgumentException_when_certPath_is_null_or_whitespace(string? certPath)
    {
        var builder = NewBuilder();

        var act = () => builder.AddPemFileSigning(certPath!, SigningAlgorithm.RS256, "/etc/zeekayda/signing.key");

        act.Should().Throw<ArgumentException>().WithParameterName("path");
    }

    [Theory]
    [InlineData("")]
    [InlineData("   ")]
    public void AddPemFileSigning_with_keyPath_throws_ArgumentException_when_keyPath_is_empty_or_whitespace(string keyPath)
    {
        var builder = NewBuilder();

        var act = () => builder.AddPemFileSigning(PemPath, SigningAlgorithm.RS256, keyPath);

        act.Should().Throw<ArgumentException>().WithParameterName("keyPath");
    }

    [Fact]
    public async Task AddPemFileSigning_with_keyPath_fills_the_Current_slot_with_both_paths()
    {
        var builder = NewBuilder();
        const string keyPath = "/etc/zeekayda/signing.key";

        builder.AddPemFileSigning(PemPath, SigningAlgorithm.RS256, keyPath);

        await using var provider = builder.Services.BuildServiceProvider();
        var options = provider.GetRequiredService<IOptions<PemFileSigningOptions>>().Value;
        options.Current.Should().Be(new PemSigningFile(PemPath, keyPath));
        options.Previous.Should().BeNull("the path overload stages no rotation");
        options.Next.Should().BeNull("the path overload stages no rotation");
    }

    // ── AddPfxFileSigning: argument validation ───────────────────────────────────────────────────

    [Fact]
    public void AddPfxFileSigning_throws_ArgumentNullException_when_builder_is_null()
    {
        var act = () => ((ZeeKayDaAuthBuilder)null!).AddPfxFileSigning(PfxPath, SigningAlgorithm.RS256, AnyPassword());

        act.Should().Throw<ArgumentNullException>().WithParameterName("builder");
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("   ")]
    public void AddPfxFileSigning_throws_ArgumentException_when_path_is_null_or_whitespace(string? path)
    {
        var builder = NewBuilder();

        var act = () => builder.AddPfxFileSigning(path!, SigningAlgorithm.RS256, AnyPassword());

        act.Should().Throw<ArgumentException>().WithParameterName("path");
    }

    [Fact]
    public void AddPfxFileSigning_throws_ArgumentNullException_when_passwordSource_is_null()
    {
        var builder = NewBuilder();

        var act = () => builder.AddPfxFileSigning(PfxPath, SigningAlgorithm.RS256, passwordSource: null!);

        act.Should().Throw<ArgumentNullException>().WithParameterName("passwordSource");
    }

    // ── Double-registration guard (AC #13): any combination ─────────────────────────────────────



    [Fact]
    public void AddPfxFileSigning_after_AddPemFileSigning_on_the_same_builder_throws()
    {
        var builder = NewBuilder();
        builder.AddPemFileSigning(PemPath, SigningAlgorithm.RS256);

        var act = () => builder.AddPfxFileSigning(PfxPath, SigningAlgorithm.RS256, AnyPassword());

        act.Should().Throw<InvalidOperationException>("AC #13: only one signing provider, of any kind, may be registered");
    }

    [Fact]
    public void AddPemFileSigning_after_AddPfxFileSigning_on_the_same_builder_throws()
    {
        var builder = NewBuilder();
        builder.AddPfxFileSigning(PfxPath, SigningAlgorithm.RS256, AnyPassword());

        var act = () => builder.AddPemFileSigning(PemPath, SigningAlgorithm.RS256);

        act.Should().Throw<InvalidOperationException>("AC #13: only one signing provider, of any kind, may be registered");
    }

    [Fact]
    public void AddPemFileSigning_after_AddPemFileSigning_on_the_same_builder_throws()
    {
        var builder = NewBuilder();
        builder.AddPemFileSigning(PemPath, SigningAlgorithm.RS256);

        var act = () => builder.AddPemFileSigning(PemPath, SigningAlgorithm.RS256);

        act.Should().Throw<InvalidOperationException>();
    }

    /// <summary>
    /// Issue #511: a second call with *different* options must fail loudly rather than silently
    /// composing two configurations onto one registration. The guard throws before this call's
    /// options callbacks are applied, so the surviving registration is the first one, unmodified.
    /// </summary>
    [Fact]
    public void AddPfxFileSigning_after_AddPfxFileSigning_with_different_options_throws()
    {
        var builder = NewBuilder();
        builder.AddPfxFileSigning(PfxPath, SigningAlgorithm.RS256, AnyPassword());

        var act = () => builder.AddPfxFileSigning(PfxPath, SigningAlgorithm.ES256, AnyPassword());

        act.Should().Throw<InvalidOperationException>();
    }

    // ── Successful registration ──────────────────────────────────────────────────────────────────

    [Fact]
    public async Task AddPemFileSigning_registers_a_static_signing_key_ring()
    {
        var builder = NewBuilder();

        builder.AddPemFileSigning(PemPath, SigningAlgorithm.RS256);

        await using var provider = builder.Services.BuildServiceProvider();
        provider.GetService<ISigningKeyRing>().Should().BeOfType<StaticSigningKeyRing>();
    }

    [Fact]
    public async Task AddPemFileSigning_does_not_register_the_source_in_the_container()
    {
        // The ring constructs and owns the one source it reads from, so no application code can
        // reach it.
        var builder = NewBuilder();

        builder.AddPemFileSigning(PemPath, SigningAlgorithm.RS256);

        await using var provider = builder.Services.BuildServiceProvider();
        provider.GetService<ISigningKeySource>().Should().BeNull();
    }

    [Fact]
    public void AddPemFileSigning_throws_when_a_signing_key_source_is_already_registered()
    {
        var builder = NewBuilder();
        builder.AddPemFileSigning(PemPath, SigningAlgorithm.RS256);

        var act = () => builder.AddPemFileSigning("/etc/zeekayda/other.pem", SigningAlgorithm.RS256);

        act.Should().Throw<InvalidOperationException>();
    }

    [Fact]
    public async Task AddPemFileSigning_does_not_apply_its_options_when_the_source_registration_is_rejected()
    {
        // The source is registered before any configuration callback runs, so a caller that catches
        // the rejection is not left with the rejected call's slots on the surviving registration.
        var builder = NewBuilder();
        builder.AddPemFileSigning(PemPath, SigningAlgorithm.RS256);

        var act = () => builder.AddPemFileSigning(SigningAlgorithm.ES256, options =>
            options.Current = new PemSigningFile("/etc/zeekayda/rejected.pem"));

        act.Should().Throw<InvalidOperationException>();
        await using var provider = builder.Services.BuildServiceProvider();
        var options = provider.GetRequiredService<IOptions<PemFileSigningOptions>>().Value;
        options.Current.Should().Be(new PemSigningFile(PemPath));
        options.Algorithm.Should().Be(SigningAlgorithm.RS256);
    }

    [Fact]
    public async Task AddPfxFileSigning_registers_a_static_signing_key_ring()
    {
        var builder = NewBuilder();

        builder.AddPfxFileSigning(PfxPath, SigningAlgorithm.RS256, AnyPassword());

        await using var provider = builder.Services.BuildServiceProvider();
        provider.GetService<ISigningKeyRing>().Should().BeOfType<StaticSigningKeyRing>();
    }

    [Fact]
    public async Task AddPfxFileSigning_fills_the_Current_slot_with_the_path_and_password_source()
    {
        var builder = NewBuilder();
        var passwordSource = AnyPassword();

        builder.AddPfxFileSigning(PfxPath, SigningAlgorithm.RS256, passwordSource);

        await using var provider = builder.Services.BuildServiceProvider();
        var options = provider.GetRequiredService<IOptions<PfxFileSigningOptions>>().Value;
        options.Current.Should().Be(new PfxFile(PfxPath, passwordSource));
        options.Previous.Should().BeNull("the path overload stages no rotation");
        options.Next.Should().BeNull("the path overload stages no rotation");
    }

    // ── AddPfxFileSigning: the three-slot overload ───────────────────────────────────────────────

    [Fact]
    public void AddPfxFileSigning_slots_overload_throws_ArgumentNullException_when_builder_is_null()
    {
        var act = () => ((ZeeKayDaAuthBuilder)null!).AddPfxFileSigning(SigningAlgorithm.RS256, _ => { });

        act.Should().Throw<ArgumentNullException>().WithParameterName("builder");
    }

    [Fact]
    public void AddPfxFileSigning_slots_overload_throws_ArgumentNullException_when_configure_is_null()
    {
        var builder = NewBuilder();

        var act = () => builder.AddPfxFileSigning(SigningAlgorithm.RS256, null!);

        act.Should().Throw<ArgumentNullException>().WithParameterName("configure");
    }

    [Fact]
    public async Task AddPfxFileSigning_slots_overload_fills_every_slot_the_callback_sets()
    {
        var builder = NewBuilder();
        var previousPassword = AnyPassword();
        var currentPassword = AnyPassword();
        var nextPassword = AnyPassword();

        builder.AddPfxFileSigning(SigningAlgorithm.ES256, options =>
        {
            options.Previous = new PfxFile("/etc/zeekayda/previous.pfx", previousPassword);
            options.Current = new PfxFile("/etc/zeekayda/current.pfx", currentPassword);
            options.Next = new PfxFile("/etc/zeekayda/next.pfx", nextPassword);
        });

        await using var provider = builder.Services.BuildServiceProvider();
        var options = provider.GetRequiredService<IOptions<PfxFileSigningOptions>>().Value;
        options.Previous.Should().Be(new PfxFile("/etc/zeekayda/previous.pfx", previousPassword));
        options.Current.Should().Be(new PfxFile("/etc/zeekayda/current.pfx", currentPassword));
        options.Next.Should().Be(new PfxFile("/etc/zeekayda/next.pfx", nextPassword));
        options.Algorithm.Should().Be(SigningAlgorithm.ES256);
    }

    [Fact]
    public async Task AddPfxFileSigning_algorithm_argument_is_the_only_thing_that_sets_the_algorithm()
    {
        // PfxFileSigningOptions.Algorithm has an internal setter, mirroring PEM: the algorithm is
        // said once, in the registration argument, and a configure callback cannot beat it.
        typeof(PfxFileSigningOptions).GetProperty(nameof(PfxFileSigningOptions.Algorithm))!
            .SetMethod!.IsAssembly.Should().BeTrue("a public setter would let a callback beat the argument");

        var builder = NewBuilder();

        builder.AddPfxFileSigning(SigningAlgorithm.ES256, options =>
            options.Current = new PfxFile("/etc/zeekayda/current.pfx", AnyPassword()));

        await using var provider = builder.Services.BuildServiceProvider();
        provider.GetRequiredService<IOptions<PfxFileSigningOptions>>().Value.Algorithm
            .Should().Be(SigningAlgorithm.ES256);
    }

    [Fact]
    public void AddPfxFileSigning_throws_when_a_signing_key_source_is_already_registered()
    {
        var builder = NewBuilder();
        builder.AddPfxFileSigning(PfxPath, SigningAlgorithm.RS256, AnyPassword());

        var act = () => builder.AddPfxFileSigning("/etc/zeekayda/other.pfx", SigningAlgorithm.RS256, AnyPassword());

        act.Should().Throw<InvalidOperationException>();
    }

    [Fact]
    public async Task AddPfxFileSigning_does_not_apply_its_options_when_the_source_registration_is_rejected()
    {
        // The source is registered before any configuration callback runs, so a caller that catches
        // the rejection is not left with the rejected call's slots on the surviving registration.
        var builder = NewBuilder();
        var originalPassword = AnyPassword();
        builder.AddPfxFileSigning(PfxPath, SigningAlgorithm.RS256, originalPassword);

        var act = () => builder.AddPfxFileSigning(SigningAlgorithm.ES256, options =>
            options.Current = new PfxFile("/etc/zeekayda/rejected.pfx", AnyPassword()));

        act.Should().Throw<InvalidOperationException>();
        await using var provider = builder.Services.BuildServiceProvider();
        var options = provider.GetRequiredService<IOptions<PfxFileSigningOptions>>().Value;
        options.Current.Should().Be(new PfxFile(PfxPath, originalPassword));
        options.Algorithm.Should().Be(SigningAlgorithm.RS256);
    }

    [Fact]
    public async Task AddPfxFileSigning_does_not_register_the_source_in_the_container()
    {
        var builder = NewBuilder();

        builder.AddPfxFileSigning(PfxPath, SigningAlgorithm.RS256, AnyPassword());

        await using var provider = builder.Services.BuildServiceProvider();
        provider.GetService<ISigningKeySource>().Should().BeNull();
    }

    // FileSigningStartupService was deleted in issue #437: it had no genuinely file-format-specific
    // behavior of its own (only the pre-warm every provider used to hand-roll), so it is fully
    // superseded by the framework-owned SigningStartupSelfTestVerifier registered once by
    // AddZeeKayDaAuthCore() for every signing provider. These tests now prove that verifier is
    // reachable through this package's registration path instead.

    // SigningStartupSelfTestVerifier is internal to ZeeKayDa.Auth (core), which does not grant
    // this test project [InternalsVisibleTo] access — only ZeeKayDa.Auth.FileSystem itself has that.
    // Its full type name is therefore matched by reflection rather than referenced directly, exactly
    // as the DI-registration proof this test replaces would look from any out-of-assembly test.



    [Fact]
    public void AddPemFileSigning_returns_builder_for_chaining()
    {
        var builder = NewBuilder();

        var returned = builder.AddPemFileSigning(PemPath, SigningAlgorithm.RS256);

        returned.Should().BeSameAs(builder);
    }

    [Fact]
    public void AddPfxFileSigning_returns_builder_for_chaining()
    {
        var builder = NewBuilder();

        var returned = builder.AddPfxFileSigning(PfxPath, SigningAlgorithm.RS256, AnyPassword());

        returned.Should().BeSameAs(builder);
    }

    // ── AddPemFileSigning: the three-slot overload ───────────────────────────────────────────────

    [Fact]
    public void AddPemFileSigning_slots_overload_throws_ArgumentNullException_when_builder_is_null()
    {
        var act = () => ((ZeeKayDaAuthBuilder)null!).AddPemFileSigning(SigningAlgorithm.RS256, _ => { });

        act.Should().Throw<ArgumentNullException>().WithParameterName("builder");
    }

    [Fact]
    public void AddPemFileSigning_slots_overload_throws_ArgumentNullException_when_configure_is_null()
    {
        var builder = NewBuilder();

        var act = () => builder.AddPemFileSigning(SigningAlgorithm.RS256, null!);

        act.Should().Throw<ArgumentNullException>().WithParameterName("configure");
    }

    [Fact]
    public async Task AddPemFileSigning_slots_overload_fills_every_slot_the_callback_sets()
    {
        var builder = NewBuilder();

        builder.AddPemFileSigning(SigningAlgorithm.ES256, options =>
        {
            options.Previous = new PemCertificateFile("/etc/zeekayda/previous.pem");
            options.Current = new PemSigningFile("/etc/zeekayda/current.pem");
            options.Next = new PemCertificateFile("/etc/zeekayda/next.pem");
        });

        await using var provider = builder.Services.BuildServiceProvider();
        var options = provider.GetRequiredService<IOptions<PemFileSigningOptions>>().Value;
        options.Previous.Should().Be(new PemCertificateFile("/etc/zeekayda/previous.pem"));
        options.Current.Should().Be(new PemSigningFile("/etc/zeekayda/current.pem"));
        options.Next.Should().Be(new PemCertificateFile("/etc/zeekayda/next.pem"));
        options.Algorithm.Should().Be(SigningAlgorithm.ES256);
    }

    [Fact]
    public async Task AddPemFileSigning_algorithm_argument_is_the_only_thing_that_sets_the_algorithm()
    {
        // Two halves, because this project holds InternalsVisibleTo to the FileSystem assembly and so
        // cannot express the negative case by failing to compile: the setter really is internal, so a
        // caller outside the assembly cannot beat the argument from a configure callback, and the
        // argument really is what lands. The API-approval analyzers gate the first half at build time;
        // the reflection assertion pins it here too, so the test name is true on its own terms.
        typeof(PemFileSigningOptions).GetProperty(nameof(PemFileSigningOptions.Algorithm))!
            .SetMethod!.IsAssembly.Should().BeTrue("a public setter would let a callback beat the argument");

        var builder = NewBuilder();

        builder.AddPemFileSigning(SigningAlgorithm.ES256, options =>
            options.Current = new PemSigningFile("/etc/zeekayda/current.pem"));

        await using var provider = builder.Services.BuildServiceProvider();
        provider.GetRequiredService<IOptions<PemFileSigningOptions>>().Value.Algorithm
            .Should().Be(SigningAlgorithm.ES256);
    }

    [Fact]
    public void AddPemFileSigning_slots_overload_returns_the_same_builder()
    {
        var builder = NewBuilder();

        var returned = builder.AddPemFileSigning(SigningAlgorithm.RS256, _ => { });

        returned.Should().BeSameAs(builder);
    }

    // ── Helpers ───────────────────────────────────────────────────────────────────────────────────

}
