using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;
using ZeeKayDa.Auth.MacOS.Tests.Fakes;
using ZeeKayDa.Auth.Tokens;

namespace ZeeKayDa.Auth.MacOS.Tests.Extensions;

public sealed class ZeeKayDaAuthBuilderMacOsKeychainSigningExtensionsTests
{
    private const string Label = "zeekayda-test-label";

    // ── Platform guard (AC #11) ──────────────────────────────────────────────────────────────────

    [Fact]
    public void AddMacOsKeychainSigning_throws_PlatformNotSupportedException_on_non_macOS()
    {
        // This is the opposite skip direction from every other test in this file: this assertion is
        // only meaningful when actually executed on a non-macOS agent, since the branch under test
        // can never be reached on macOS. Do not "fix" this to match the surrounding
        // SkipUnless(IsMacOS) pattern - it is intentionally inverted.
        Assert.SkipWhen(OperatingSystem.IsMacOS(),
            "This test verifies the non-macOS PlatformNotSupportedException guard and is only " +
            "meaningful when actually executed on a non-macOS CI agent/dev machine.");

        var services = new ServiceCollection();
        var builder = new ZeeKayDaAuthBuilder(services);

        var act = () => builder.AddMacOsKeychainSigning(Label);

        act.Should().Throw<PlatformNotSupportedException>().WithMessage("*macOS*");
    }

    // ── Argument validation ───────────────────────────────────────────────────────────────────────
    // The platform gate is checked first, before argument validation, so these tests must be
    // skipped off macOS or they would observe PlatformNotSupportedException instead.

    [Fact]
    public void AddMacOsKeychainSigning_throws_ArgumentNullException_when_builder_is_null()
    {
        Assert.SkipUnless(OperatingSystem.IsMacOS(), "the platform gate fires before argument validation off macOS");

        var act = () => ((ZeeKayDaAuthBuilder)null!).AddMacOsKeychainSigning(Label);

        act.Should().Throw<ArgumentNullException>().WithParameterName("builder");
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("   ")]
    public void AddMacOsKeychainSigning_throws_ArgumentException_when_label_is_null_or_whitespace(string? label)
    {
        Assert.SkipUnless(OperatingSystem.IsMacOS(), "the platform gate fires before argument validation off macOS");

        var services = new ServiceCollection();
        var builder = new ZeeKayDaAuthBuilder(services);

        var act = () => builder.AddMacOsKeychainSigning(label!);

        act.Should().Throw<ArgumentException>().WithParameterName("label");
    }

    // ── Double-registration guard ─────────────────────────────────────────────────────────────────

    [Fact]
    public void AddMacOsKeychainSigning_throws_InvalidOperationException_when_IJwtSigningService_already_registered()
    {
        Assert.SkipUnless(OperatingSystem.IsMacOS(), "requires the real registration path past the platform gate");

        var services = new ServiceCollection();
        services.AddSingleton<IJwtSigningService>(NoOpJwtSigningService.Instance);
        var builder = new ZeeKayDaAuthBuilder(services);

        var act = () => builder.AddMacOsKeychainSigning(Label);

        act.Should().Throw<InvalidOperationException>().WithMessage("*IJwtSigningService*already registered*");
    }

    // ── Successful registration ──────────────────────────────────────────────────────────────────

    [Fact]
    public async Task AddMacOsKeychainSigning_resolves_IJwtSigningService_as_the_macOS_implementation()
    {
        Assert.SkipUnless(OperatingSystem.IsMacOS(), "requires the real registration path past the platform gate");

        var services = new ServiceCollection();
        services.AddSingleton<IKeychainItemReader>(new FakeKeychainItemReader());
        // SecretSanitizingLogger<T> (registered by AddZeeKayDaAuthCore) needs a real ILogger<T> to
        // resolve; a plain ServiceCollection has no logging provider registered by default.
        services.AddSingleton(typeof(ILogger<>), typeof(NullLogger<>));
        var builder = new ZeeKayDaAuthBuilder(services);

        builder.AddMacOsKeychainSigning(Label);

        await using var provider = services.BuildServiceProvider();
        var service = provider.GetRequiredService<IJwtSigningService>();
        service.Should().BeOfType<MacOsKeychainSigningJwtSigningService>();
    }

    [Fact]
    public void AddMacOsKeychainSigning_returns_builder_for_chaining()
    {
        Assert.SkipUnless(OperatingSystem.IsMacOS(), "requires the real registration path past the platform gate");

        var services = new ServiceCollection();
        services.AddSingleton<IKeychainItemReader>(new FakeKeychainItemReader());
        var builder = new ZeeKayDaAuthBuilder(services);

        var returned = builder.AddMacOsKeychainSigning(Label);

        returned.Should().BeSameAs(builder);
    }

    // ── Helpers ───────────────────────────────────────────────────────────────────────────────────

    private sealed class NoOpJwtSigningService : IJwtSigningService
    {
        public static readonly NoOpJwtSigningService Instance = new();

        public ValueTask<IReadOnlyList<SigningKeyDescriptor>> GetSigningKeysAsync(CancellationToken cancellationToken) =>
            throw new NotSupportedException();

        public ValueTask<SigningResult> SignAsync(ReadOnlyMemory<byte> signingInput, CancellationToken cancellationToken) =>
            throw new NotSupportedException();
    }
}
