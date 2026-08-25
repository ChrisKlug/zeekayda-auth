using System.Security.Cryptography.X509Certificates;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using ZeeKayDa.Auth.Tokens;
using ZeeKayDa.Auth.Windows.Tests.Fakes;

namespace ZeeKayDa.Auth.Windows.Tests.Extensions;

/// <summary>
/// Registration tests for both <c>AddWindowsCertificateStoreSigning</c> overloads.
/// </summary>
/// <remarks>
/// Everything past the platform gate is skipped off Windows, because the gate is checked before
/// anything else and would otherwise be the only thing these tests ever observed. The one exception
/// is the gate's own test, which is inverted on purpose.
/// </remarks>
public sealed class ZeeKayDaAuthBuilderWindowsCertificateStoreSigningExtensionsTests
{
    private const string Thumbprint = "AABBCCDDEEFF00112233445566778899AABBCCD";
    private const string OtherThumbprint = "1111111111111111111111111111111111111A";

    private static CertificateLookup Certificate() => CertificateLookup.ByThumbprint(Thumbprint);

    private static ZeeKayDaAuthBuilder NewBuilder()
    {
        var services = new ServiceCollection();
        services.AddSingleton<ICertificateStoreReader>(new FakeCertificateStoreReader());
        // SecretSanitizingLogger<T> (registered by AddZeeKayDaAuthCore) needs a real ILogger<T> to
        // resolve; a plain ServiceCollection has no logging provider registered by default.
        services.AddSingleton(typeof(ILogger<>), typeof(NullLogger<>));
        return new ZeeKayDaAuthBuilder(services);
    }

    // ── Platform guard ───────────────────────────────────────────────────────────────────────────

    [Fact]
    public void AddWindowsCertificateStoreSigning_throws_PlatformNotSupportedException_on_non_Windows()
    {
        // This is the opposite skip direction from every other test in this file: this assertion is
        // only meaningful when actually executed on a non-Windows agent, since the branch under test
        // can never be reached on Windows. Do not "fix" this to match the surrounding
        // SkipUnless(IsWindows) pattern - it is intentionally inverted.
        Assert.SkipWhen(OperatingSystem.IsWindows(),
            "This test verifies the non-Windows PlatformNotSupportedException guard and is only " +
            "meaningful when actually executed on a non-Windows CI agent/dev machine.");

        var builder = new ZeeKayDaAuthBuilder(new ServiceCollection());

        var act = () => builder.AddWindowsCertificateStoreSigning(
            Certificate(), SigningAlgorithm.RS256, StoreLocation.CurrentUser, StoreName.My);

        act.Should().Throw<PlatformNotSupportedException>().WithMessage("*Windows*");
    }

    [Fact]
    public void AddWindowsCertificateStoreSigning_slots_overload_throws_PlatformNotSupportedException_on_non_Windows()
    {
        Assert.SkipWhen(OperatingSystem.IsWindows(),
            "This test verifies the non-Windows PlatformNotSupportedException guard and is only " +
            "meaningful when actually executed on a non-Windows CI agent/dev machine.");

        var builder = new ZeeKayDaAuthBuilder(new ServiceCollection());

        var act = () => builder.AddWindowsCertificateStoreSigning(
            SigningAlgorithm.RS256, StoreLocation.CurrentUser, StoreName.My, _ => { });

        act.Should().Throw<PlatformNotSupportedException>().WithMessage("*Windows*");
    }

    // ── Argument validation ──────────────────────────────────────────────────────────────────────
    // The platform gate is checked first, before argument validation, so these tests must be
    // skipped off Windows or they would observe PlatformNotSupportedException instead.

    [Fact]
    public void AddWindowsCertificateStoreSigning_throws_ArgumentNullException_when_builder_is_null()
    {
        Assert.SkipUnless(OperatingSystem.IsWindows(), "the platform gate fires before argument validation off Windows");

        var act = () => ((ZeeKayDaAuthBuilder)null!).AddWindowsCertificateStoreSigning(
            Certificate(), SigningAlgorithm.RS256, StoreLocation.CurrentUser, StoreName.My);

        act.Should().Throw<ArgumentNullException>().WithParameterName("builder");
    }

    [Fact]
    public void AddWindowsCertificateStoreSigning_throws_ArgumentNullException_when_certificate_is_null()
    {
        Assert.SkipUnless(OperatingSystem.IsWindows(), "the platform gate fires before argument validation off Windows");

        var builder = NewBuilder();

        var act = () => builder.AddWindowsCertificateStoreSigning(
            null!, SigningAlgorithm.RS256, StoreLocation.CurrentUser, StoreName.My);

        act.Should().Throw<ArgumentNullException>().WithParameterName("certificate");
    }

    [Fact]
    public void AddWindowsCertificateStoreSigning_slots_overload_throws_ArgumentNullException_when_builder_is_null()
    {
        Assert.SkipUnless(OperatingSystem.IsWindows(), "the platform gate fires before argument validation off Windows");

        var act = () => ((ZeeKayDaAuthBuilder)null!).AddWindowsCertificateStoreSigning(
            SigningAlgorithm.RS256, StoreLocation.CurrentUser, StoreName.My, _ => { });

        act.Should().Throw<ArgumentNullException>().WithParameterName("builder");
    }

    [Fact]
    public void AddWindowsCertificateStoreSigning_slots_overload_throws_ArgumentNullException_when_configure_is_null()
    {
        Assert.SkipUnless(OperatingSystem.IsWindows(), "the platform gate fires before argument validation off Windows");

        var builder = NewBuilder();

        var act = () => builder.AddWindowsCertificateStoreSigning(
            SigningAlgorithm.RS256, StoreLocation.CurrentUser, StoreName.My, null!);

        act.Should().Throw<ArgumentNullException>().WithParameterName("configure");
    }

    // ── Double-registration guard ────────────────────────────────────────────────────────────────

    [Fact]
    public void AddWindowsCertificateStoreSigning_throws_InvalidOperationException_when_IJwtSigningService_already_registered()
    {
        Assert.SkipUnless(OperatingSystem.IsWindows(), "requires the real registration path past the platform gate");

        var builder = NewBuilder();
        builder.Services.AddSingleton<IJwtSigningService>(NoOpJwtSigningService.Instance);

        var act = () => builder.AddWindowsCertificateStoreSigning(
            Certificate(), SigningAlgorithm.RS256, StoreLocation.CurrentUser, StoreName.My);

        act.Should().Throw<InvalidOperationException>().WithMessage("*IJwtSigningService*already registered*");
    }

    [Fact]
    public void AddWindowsCertificateStoreSigning_throws_when_a_signing_key_source_is_already_registered()
    {
        Assert.SkipUnless(OperatingSystem.IsWindows(), "requires the real registration path past the platform gate");

        var builder = NewBuilder();
        builder.AddWindowsCertificateStoreSigning(Certificate(), SigningAlgorithm.RS256, StoreLocation.CurrentUser, StoreName.My);

        var act = () => builder.AddWindowsCertificateStoreSigning(
            CertificateLookup.ByThumbprint(OtherThumbprint), SigningAlgorithm.RS256, StoreLocation.CurrentUser, StoreName.My);

        act.Should().Throw<InvalidOperationException>();
    }

    [Fact]
    public async Task AddWindowsCertificateStoreSigning_does_not_apply_its_options_when_the_source_registration_is_rejected()
    {
        // The source is registered before any configuration callback runs, so a caller that catches
        // the rejection is not left with the rejected call's slots on the surviving registration.
        Assert.SkipUnless(OperatingSystem.IsWindows(), "requires the real registration path past the platform gate");

        var builder = NewBuilder();
        builder.AddWindowsCertificateStoreSigning(Certificate(), SigningAlgorithm.RS256, StoreLocation.CurrentUser, StoreName.My);

        var act = () => builder.AddWindowsCertificateStoreSigning(
            SigningAlgorithm.ES256, StoreLocation.LocalMachine, StoreName.Root,
            options => options.Current = CertificateLookup.ByThumbprint(OtherThumbprint));

        act.Should().Throw<InvalidOperationException>();
        await using var provider = builder.Services.BuildServiceProvider();
        var options = provider.GetRequiredService<IOptions<WindowsCertificateStoreSigningOptions>>().Value;
        options.Current.Should().Be(Certificate());
        options.Algorithm.Should().Be(SigningAlgorithm.RS256);
        options.StoreLocation.Should().Be(StoreLocation.CurrentUser);
        options.StoreName.Should().Be(StoreName.My);
    }

    // ── Successful registration ──────────────────────────────────────────────────────────────────

    [Fact]
    public async Task AddWindowsCertificateStoreSigning_registers_a_static_signing_key_ring()
    {
        Assert.SkipUnless(OperatingSystem.IsWindows(), "requires the real registration path past the platform gate");

        var builder = NewBuilder();

        builder.AddWindowsCertificateStoreSigning(Certificate(), SigningAlgorithm.RS256, StoreLocation.CurrentUser, StoreName.My);

        await using var provider = builder.Services.BuildServiceProvider();
        provider.GetService<ISigningKeyRing>().Should().BeOfType<StaticSigningKeyRing>();
    }

    [Fact]
    public async Task AddWindowsCertificateStoreSigning_does_not_register_the_source_in_the_container()
    {
        // The ring constructs and owns the one source it reads from, so no application code can
        // reach it.
        Assert.SkipUnless(OperatingSystem.IsWindows(), "requires the real registration path past the platform gate");

        var builder = NewBuilder();

        builder.AddWindowsCertificateStoreSigning(Certificate(), SigningAlgorithm.RS256, StoreLocation.CurrentUser, StoreName.My);

        await using var provider = builder.Services.BuildServiceProvider();
        provider.GetService<ISigningKeySource>().Should().BeNull();
    }

    [Fact]
    public async Task AddWindowsCertificateStoreSigning_registers_the_framework_owned_signing_startup_self_test_as_an_IStartupVerifier()
    {
        Assert.SkipUnless(OperatingSystem.IsWindows(), "requires the real registration path past the platform gate");

        var builder = NewBuilder();

        builder.AddWindowsCertificateStoreSigning(Certificate(), SigningAlgorithm.RS256, StoreLocation.CurrentUser, StoreName.My);

        var targetType = typeof(IJwtSigningService).Assembly.GetType(
            "ZeeKayDa.Auth.Tokens.SigningStartupSelfTestVerifier", throwOnError: true)!;

        await using var provider = builder.Services.BuildServiceProvider();
        provider.GetServices<IStartupVerifier>().Should().Contain(s => targetType.IsAssignableFrom(s.GetType()));
    }

    [Fact]
    public async Task AddWindowsCertificateStoreSigning_fills_the_Current_slot_and_leaves_the_others_empty()
    {
        Assert.SkipUnless(OperatingSystem.IsWindows(), "requires the real registration path past the platform gate");

        var builder = NewBuilder();

        builder.AddWindowsCertificateStoreSigning(Certificate(), SigningAlgorithm.RS256, StoreLocation.LocalMachine, StoreName.Root);

        await using var provider = builder.Services.BuildServiceProvider();
        var options = provider.GetRequiredService<IOptions<WindowsCertificateStoreSigningOptions>>().Value;
        options.Current.Should().Be(Certificate());
        options.Previous.Should().BeNull();
        options.Next.Should().BeNull();
        options.StoreLocation.Should().Be(StoreLocation.LocalMachine);
        options.StoreName.Should().Be(StoreName.Root);
    }

    [Fact]
    public async Task AddWindowsCertificateStoreSigning_slots_overload_fills_every_slot_the_callback_sets()
    {
        Assert.SkipUnless(OperatingSystem.IsWindows(), "requires the real registration path past the platform gate");

        var builder = NewBuilder();

        builder.AddWindowsCertificateStoreSigning(SigningAlgorithm.ES256, StoreLocation.CurrentUser, StoreName.My, options =>
        {
            options.Previous = CertificateLookup.ByThumbprint(OtherThumbprint);
            options.Current = Certificate();
            options.Next = CertificateLookup.ByThumbprint("2222222222222222222222222222222222222B");
        });

        await using var provider = builder.Services.BuildServiceProvider();
        var options = provider.GetRequiredService<IOptions<WindowsCertificateStoreSigningOptions>>().Value;
        options.Previous.Should().Be(CertificateLookup.ByThumbprint(OtherThumbprint));
        options.Current.Should().Be(Certificate());
        options.Next.Should().Be(CertificateLookup.ByThumbprint("2222222222222222222222222222222222222B"));
        options.Algorithm.Should().Be(SigningAlgorithm.ES256);
    }

    [Fact]
    public async Task AddWindowsCertificateStoreSigning_arguments_are_the_only_things_that_set_algorithm_and_store()
    {
        // Two halves, because this project holds InternalsVisibleTo to the Windows assembly and so
        // cannot express the negative case by failing to compile: the setters really are internal, so
        // a caller outside the assembly cannot beat the arguments from a configure callback, and the
        // arguments really are what land. The API-approval analyzers gate the first half at build
        // time; the reflection assertions pin it here too, so the test name is true on its own terms.
        //
        // The accessibility half is pure metadata and needs no Windows, so it runs before the skip:
        // the pin then executes wherever this assembly runs, not only on Windows. (That is local runs
        // on any OS — the CI legs for macOS and Linux do not build this project at all, since it is in
        // neither per-OS solution filter.)
        typeof(WindowsCertificateStoreSigningOptions).GetProperty(nameof(WindowsCertificateStoreSigningOptions.Algorithm))!
            .SetMethod!.IsAssembly.Should().BeTrue("a public setter would let a callback beat the argument");
        typeof(WindowsCertificateStoreSigningOptions).GetProperty(nameof(WindowsCertificateStoreSigningOptions.StoreLocation))!
            .SetMethod!.IsAssembly.Should().BeTrue("a public setter would let a callback silently search the wrong store");
        typeof(WindowsCertificateStoreSigningOptions).GetProperty(nameof(WindowsCertificateStoreSigningOptions.StoreName))!
            .SetMethod!.IsAssembly.Should().BeTrue("a public setter would let a callback silently search the wrong store");

        Assert.SkipUnless(OperatingSystem.IsWindows(), "requires the real registration path past the platform gate");

        var builder = NewBuilder();

        builder.AddWindowsCertificateStoreSigning(SigningAlgorithm.ES256, StoreLocation.LocalMachine, StoreName.Root,
            options => options.Current = Certificate());

        await using var provider = builder.Services.BuildServiceProvider();
        var options = provider.GetRequiredService<IOptions<WindowsCertificateStoreSigningOptions>>().Value;
        options.Algorithm.Should().Be(SigningAlgorithm.ES256);
        options.StoreLocation.Should().Be(StoreLocation.LocalMachine);
        options.StoreName.Should().Be(StoreName.Root);
    }

    [Fact]
    public void AddWindowsCertificateStoreSigning_returns_builder_for_chaining()
    {
        Assert.SkipUnless(OperatingSystem.IsWindows(), "requires the real registration path past the platform gate");

        var builder = NewBuilder();

        var returned = builder.AddWindowsCertificateStoreSigning(
            Certificate(), SigningAlgorithm.RS256, StoreLocation.CurrentUser, StoreName.My);

        returned.Should().BeSameAs(builder);
    }

    [Fact]
    public void AddWindowsCertificateStoreSigning_slots_overload_returns_the_same_builder()
    {
        Assert.SkipUnless(OperatingSystem.IsWindows(), "requires the real registration path past the platform gate");

        var builder = NewBuilder();

        var returned = builder.AddWindowsCertificateStoreSigning(
            SigningAlgorithm.RS256, StoreLocation.CurrentUser, StoreName.My, _ => { });

        returned.Should().BeSameAs(builder);
    }

    // ── Helpers ──────────────────────────────────────────────────────────────────────────────────

    private sealed class NoOpJwtSigningService : IJwtSigningService
    {
        public static readonly NoOpJwtSigningService Instance = new();

        public ValueTask<IReadOnlyList<SigningKeyDescriptor>> GetSigningKeysAsync(CancellationToken cancellationToken) =>
            throw new NotSupportedException();

        public ValueTask<SigningResult> SignAsync(ReadOnlyMemory<byte> signingInput, CancellationToken cancellationToken) =>
            throw new NotSupportedException();
    }
}
