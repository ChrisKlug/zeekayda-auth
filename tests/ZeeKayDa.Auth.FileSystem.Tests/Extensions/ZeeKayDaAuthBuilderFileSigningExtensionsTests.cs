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
    public void AddPemFileSigning_throws_InvalidOperationException_when_IJwtSigningService_already_registered()
    {
        var builder = NewBuilder();
        builder.Services.AddSingleton<IJwtSigningService>(NoOpJwtSigningService.Instance);

        var act = () => builder.AddPemFileSigning(PemPath, SigningAlgorithm.RS256);

        act.Should().Throw<InvalidOperationException>().WithMessage("*IJwtSigningService*already registered*");
    }

    [Fact]
    public void AddPfxFileSigning_throws_InvalidOperationException_when_IJwtSigningService_already_registered()
    {
        var builder = NewBuilder();
        builder.Services.AddSingleton<IJwtSigningService>(NoOpJwtSigningService.Instance);

        var act = () => builder.AddPfxFileSigning(PfxPath, SigningAlgorithm.RS256, AnyPassword());

        act.Should().Throw<InvalidOperationException>().WithMessage("*IJwtSigningService*already registered*");
    }

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

    // ── Successful registration ──────────────────────────────────────────────────────────────────

    [Fact]
    public async Task AddPemFileSigning_resolves_IJwtSigningService_as_PemFileSigningJwtSigningService()
    {
        var builder = NewBuilder();

        builder.AddPemFileSigning(PemPath, SigningAlgorithm.RS256);

        await using var provider = builder.Services.BuildServiceProvider();
        var service = provider.GetRequiredService<IJwtSigningService>();
        service.Should().BeOfType<PemFileSigningJwtSigningService>();
    }

    [Fact]
    public async Task AddPfxFileSigning_resolves_IJwtSigningService_as_PfxFileSigningJwtSigningService()
    {
        var builder = NewBuilder();

        builder.AddPfxFileSigning(PfxPath, SigningAlgorithm.RS256, AnyPassword());

        await using var provider = builder.Services.BuildServiceProvider();
        var service = provider.GetRequiredService<IJwtSigningService>();
        service.Should().BeOfType<PfxFileSigningJwtSigningService>();
    }

    [Fact]
    public async Task AddPemFileSigning_registers_FileSigningStartupService_as_a_hosted_service()
    {
        var builder = NewBuilder();

        builder.AddPemFileSigning(PemPath, SigningAlgorithm.RS256);

        await using var provider = builder.Services.BuildServiceProvider();
        provider.GetServices<IHostedService>().OfType<FileSigningStartupService>().Should().ContainSingle();
    }

    [Fact]
    public async Task AddPfxFileSigning_registers_FileSigningStartupService_as_a_hosted_service()
    {
        var builder = NewBuilder();

        builder.AddPfxFileSigning(PfxPath, SigningAlgorithm.RS256, AnyPassword());

        await using var provider = builder.Services.BuildServiceProvider();
        provider.GetServices<IHostedService>().OfType<FileSigningStartupService>().Should().ContainSingle();
    }

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

    [Fact]
    public async Task AddPemFileSigning_configure_callback_sets_additional_options()
    {
        var builder = NewBuilder();

        builder.AddPemFileSigning(PemPath, SigningAlgorithm.RS256, configure: options =>
        {
            options.Algorithm = SigningAlgorithm.ES256;
            options.AddFile("/etc/zeekayda/rotated-in.pem");
        });

        await using var provider = builder.Services.BuildServiceProvider();
        var options = provider.GetRequiredService<IOptions<PemFileSigningOptions>>().Value;
        options.Path.Should().Be(PemPath);
        options.Algorithm.Should().Be(SigningAlgorithm.ES256);
        options.AdditionalPaths.Should().ContainSingle().Which.Should().Be("/etc/zeekayda/rotated-in.pem");
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
