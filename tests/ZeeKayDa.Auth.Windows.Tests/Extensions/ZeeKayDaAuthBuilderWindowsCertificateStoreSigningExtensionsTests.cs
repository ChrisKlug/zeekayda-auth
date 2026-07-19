using System.Security.Cryptography.X509Certificates;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;
using ZeeKayDa.Auth.Tokens;
using ZeeKayDa.Auth.Windows.Tests.Fakes;

namespace ZeeKayDa.Auth.Windows.Tests.Extensions;

public sealed class ZeeKayDaAuthBuilderWindowsCertificateStoreSigningExtensionsTests
{
    private const string Thumbprint = "AABBCCDDEEFF00112233445566778899AABBCCD";

    // ── Platform guard (AC #11) ──────────────────────────────────────────────────────────────────

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

        var services = new ServiceCollection();
        var builder = new ZeeKayDaAuthBuilder(services);

        var act = () => builder.AddWindowsCertificateStoreSigning(Thumbprint, SigningAlgorithm.RS256, StoreLocation.CurrentUser, StoreName.My);

        act.Should().Throw<PlatformNotSupportedException>().WithMessage("*Windows*");
    }

    // ── Argument validation ───────────────────────────────────────────────────────────────────────
    // The platform gate is checked first, before argument validation, so these tests must be
    // skipped off Windows or they would observe PlatformNotSupportedException instead.

    [Fact]
    public void AddWindowsCertificateStoreSigning_throws_ArgumentNullException_when_builder_is_null()
    {
        Assert.SkipUnless(OperatingSystem.IsWindows(), "the platform gate fires before argument validation off Windows");

        var act = () => ((ZeeKayDaAuthBuilder)null!).AddWindowsCertificateStoreSigning(Thumbprint, SigningAlgorithm.RS256, StoreLocation.CurrentUser, StoreName.My);

        act.Should().Throw<ArgumentNullException>().WithParameterName("builder");
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("   ")]
    public void AddWindowsCertificateStoreSigning_throws_ArgumentException_when_thumbprint_is_null_or_whitespace(string? thumbprint)
    {
        Assert.SkipUnless(OperatingSystem.IsWindows(), "the platform gate fires before argument validation off Windows");

        var services = new ServiceCollection();
        var builder = new ZeeKayDaAuthBuilder(services);

        var act = () => builder.AddWindowsCertificateStoreSigning(thumbprint!, SigningAlgorithm.RS256, StoreLocation.CurrentUser, StoreName.My);

        act.Should().Throw<ArgumentException>().WithParameterName("thumbprint");
    }

    // ── Double-registration guard ─────────────────────────────────────────────────────────────────

    [Fact]
    public void AddWindowsCertificateStoreSigning_throws_InvalidOperationException_when_IJwtSigningService_already_registered()
    {
        Assert.SkipUnless(OperatingSystem.IsWindows(), "requires the real registration path past the platform gate");

        var services = new ServiceCollection();
        services.AddSingleton<IJwtSigningService>(NoOpJwtSigningService.Instance);
        var builder = new ZeeKayDaAuthBuilder(services);

        var act = () => builder.AddWindowsCertificateStoreSigning(Thumbprint, SigningAlgorithm.RS256, StoreLocation.CurrentUser, StoreName.My);

        act.Should().Throw<InvalidOperationException>().WithMessage("*IJwtSigningService*already registered*");
    }

    // ── Successful registration ──────────────────────────────────────────────────────────────────

    [Fact]
    public async Task AddWindowsCertificateStoreSigning_resolves_IJwtSigningService_as_the_windows_implementation()
    {
        Assert.SkipUnless(OperatingSystem.IsWindows(), "requires the real registration path past the platform gate");

        var services = new ServiceCollection();
        services.AddSingleton<ICertificateStoreReader>(new FakeCertificateStoreReader());
        // SecretSanitizingLogger<T> (registered by AddZeeKayDaAuthCore) needs a real ILogger<T> to
        // resolve; a plain ServiceCollection has no logging provider registered by default.
        services.AddSingleton(typeof(ILogger<>), typeof(NullLogger<>));
        var builder = new ZeeKayDaAuthBuilder(services);

        builder.AddWindowsCertificateStoreSigning(Thumbprint, SigningAlgorithm.RS256, StoreLocation.CurrentUser, StoreName.My);

        await using var provider = services.BuildServiceProvider();
        var service = provider.GetRequiredService<IJwtSigningService>();
        service.Should().BeOfType<WindowsCertificateStoreSigningJwtSigningService>();
    }

    [Fact]
    public void AddWindowsCertificateStoreSigning_returns_builder_for_chaining()
    {
        Assert.SkipUnless(OperatingSystem.IsWindows(), "requires the real registration path past the platform gate");

        var services = new ServiceCollection();
        services.AddSingleton<ICertificateStoreReader>(new FakeCertificateStoreReader());
        var builder = new ZeeKayDaAuthBuilder(services);

        var returned = builder.AddWindowsCertificateStoreSigning(Thumbprint, SigningAlgorithm.RS256, StoreLocation.CurrentUser, StoreName.My);

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
