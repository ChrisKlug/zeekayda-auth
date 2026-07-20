// These tests exercise the full DI wiring for AddPemFileSigning/AddPfxFileSigning end to end — a
// real ServiceCollection / ZeeKayDaAuthBuilder / ServiceProvider — reading real temporary PEM/PFX
// files from disk, exactly as a deployed host would. No fake is substituted for FileSigningKeyReader
// or the filesystem: this provider's whole job is real file I/O and permission validation.
//
// NOTE: ZeeKayDa.Auth.AspNetCore's /connect/jwks HTTP endpoint is still a pre-alpha stub that always
// returns 501 Not Implemented (see ZeeKayDa.Auth.AspNetCore.Tests.Endpoints.DiscoveryEndpointTests),
// so "hit the JWKS endpoint" is exercised here at the IJwtSigningService level instead — the exact
// same level WindowsCertificateStoreSigningIntegrationTests uses for its JWKS-shape assertions —
// rather than over real HTTP, which would only ever observe the 501 stub today.

using System.Security.Cryptography.X509Certificates;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Time.Testing;
using ZeeKayDa.Auth.FileSystem;
using ZeeKayDa.Auth.FileSystem.Tests.Fixtures;
using ZeeKayDa.Auth.Tokens;

namespace ZeeKayDa.Auth.FileSystem.Tests.Integration;

public sealed class FileSigningIntegrationTests
{
    private static readonly DateTimeOffset T0 = DateTimeOffset.Parse("2026-01-01T00:00:00Z");
    private const string CorrectPassword = "correct horse battery staple";

    private static (ServiceCollection Services, FakeTimeProvider TimeProvider) BuildServices(
        DateTimeOffset now, TimeSpan? retirementWindow = null)
    {
        var timeProvider = new FakeTimeProvider(now);
        var services = new ServiceCollection();
        services.AddSingleton(typeof(ILogger<>), typeof(NullLogger<>));
        services.AddSingleton<TimeProvider>(timeProvider);
        services.AddSingleton<ISigningKeyRetirementWindowProvider>(new SigningKeyRetirementWindowProviderStub(retirementWindow ?? TimeSpan.FromHours(1)));
        return (services, timeProvider);
    }

    // ── PEM: end-to-end resolve + JWKS shape (AC #1/#8) ─────────────────────────────────────────

    [Fact]
    public async Task Full_DI_wiring_resolves_and_returns_a_well_formed_signing_key_for_a_PEM_file()
    {
        var ct = TestContext.Current.CancellationToken;
        using var tempDir = new TempSigningKeyDirectory();
        using var certificate = TestCertificateFactory.CreateRsaSelfSigned("test", T0 - TimeSpan.FromDays(1), T0 + TimeSpan.FromDays(365));
        var path = tempDir.WritePemFile("key.pem", certificate);
        var (services, _) = BuildServices(T0);

        var builder = new ZeeKayDaAuthBuilder(services);
        builder.AddPemFileSigning(path, SigningAlgorithm.RS256);

        await using var provider = services.BuildServiceProvider();
        var signingService = provider.GetRequiredService<IJwtSigningService>();

        var keys = await signingService.GetSigningKeysAsync(ct);

        keys.Should().ContainSingle("AC #8: the single registered file's public key must be exposed");
        keys[0].Kid.Should().NotBeNullOrEmpty();
        keys[0].RsaPublicParameters.Should().NotBeNull("the JWKS entry must expose only the public key");
        keys[0].Algorithm.Should().Be(SigningAlgorithm.RS256);
    }

    [Fact]
    public async Task Full_DI_wiring_JWKS_output_includes_both_PEM_files_during_a_rotation_overlap()
    {
        var ct = TestContext.Current.CancellationToken;
        var refreshInterval = TimeSpan.FromMinutes(5);
        using var tempDir = new TempSigningKeyDirectory();
        using var predecessor = TestCertificateFactory.CreateRsaSelfSigned("predecessor", T0 - TimeSpan.FromDays(30), T0 + TimeSpan.FromDays(365));
        var successorNotBefore = T0 + TimeSpan.FromDays(1);
        using var successor = TestCertificateFactory.CreateRsaSelfSigned("successor", successorNotBefore, T0 + TimeSpan.FromDays(400));
        var predecessorPath = tempDir.WritePemFile("predecessor.pem", predecessor);
        var successorPath = tempDir.WritePemFile("successor.pem", successor);
        var (services, _) = BuildServices(T0);

        var builder = new ZeeKayDaAuthBuilder(services);
        builder.AddPemFileSigning(predecessorPath, SigningAlgorithm.RS256, configure: options =>
        {
            options.AddFile(successorPath);
            options.KeyRotationCheckInterval = refreshInterval;
        });

        await using var provider = services.BuildServiceProvider();
        var signingService = provider.GetRequiredService<IJwtSigningService>();

        var keys = await signingService.GetSigningKeysAsync(ct);

        keys.Should().HaveCount(2, "AC #9: both files must be exposed during the overlap window");
    }

    [Fact]
    public async Task Full_DI_wiring_active_signer_switches_when_the_successors_NotBefore_arrives()
    {
        var ct = TestContext.Current.CancellationToken;
        var refreshInterval = TimeSpan.FromMinutes(5);
        using var tempDir = new TempSigningKeyDirectory();
        using var predecessor = TestCertificateFactory.CreateRsaSelfSigned("predecessor", T0 - TimeSpan.FromDays(30), T0 + TimeSpan.FromDays(365));
        var successorNotBefore = T0 + TimeSpan.FromDays(1);
        using var successor = TestCertificateFactory.CreateRsaSelfSigned("successor", successorNotBefore, T0 + TimeSpan.FromDays(400));
        var predecessorPath = tempDir.WritePemFile("predecessor.pem", predecessor);
        var successorPath = tempDir.WritePemFile("successor.pem", successor);
        var (services, timeProvider) = BuildServices(T0);

        var builder = new ZeeKayDaAuthBuilder(services);
        builder.AddPemFileSigning(predecessorPath, SigningAlgorithm.RS256, configure: options =>
        {
            options.AddFile(successorPath);
            options.KeyRotationCheckInterval = refreshInterval;
        });

        await using var provider = services.BuildServiceProvider();
        var signingService = provider.GetRequiredService<IJwtSigningService>();

        var before = await signingService.GetSigningKeysAsync(ct);
        before[0].Kid.Should().Be(JwkThumbprint.Compute(predecessor.GetRSAPublicKey()!.ExportParameters(false)));

        timeProvider.SetUtcNow(successorNotBefore);
        var after = await signingService.GetSigningKeysAsync(ct);
        after[0].Kid.Should().Be(JwkThumbprint.Compute(successor.GetRSAPublicKey()!.ExportParameters(false)));
    }

    // ── PFX: end-to-end resolve (AC #4/#8) ──────────────────────────────────────────────────────

    [Fact]
    public async Task Full_DI_wiring_resolves_and_returns_a_well_formed_signing_key_for_a_PFX_file()
    {
        var ct = TestContext.Current.CancellationToken;
        using var tempDir = new TempSigningKeyDirectory();
        using var certificate = TestCertificateFactory.CreateRsaSelfSigned("test", T0 - TimeSpan.FromDays(1), T0 + TimeSpan.FromDays(365));
        var path = tempDir.WritePfxFile("key.pfx", certificate, CorrectPassword);
        var (services, _) = BuildServices(T0);

        var builder = new ZeeKayDaAuthBuilder(services);
        builder.AddPfxFileSigning(path, SigningAlgorithm.RS256, _ => ValueTask.FromResult(CorrectPassword));

        await using var provider = services.BuildServiceProvider();
        var signingService = provider.GetRequiredService<IJwtSigningService>();

        var keys = await signingService.GetSigningKeysAsync(ct);

        keys.Should().ContainSingle();
        keys[0].RsaPublicParameters.Should().NotBeNull();
    }

    // ── Startup failure propagation ──────────────────────────────────────────────────────────────

    [Fact]
    public async Task Full_DI_wiring_surfaces_missing_file_as_ZeeKayDaConfigurationException()
    {
        var ct = TestContext.Current.CancellationToken;
        using var tempDir = new TempSigningKeyDirectory();
        var missingPath = tempDir.GetPath("does-not-exist.pem");
        var (services, _) = BuildServices(T0);

        var builder = new ZeeKayDaAuthBuilder(services);
        builder.AddPemFileSigning(missingPath, SigningAlgorithm.RS256);

        await using var provider = services.BuildServiceProvider();
        var signingService = provider.GetRequiredService<IJwtSigningService>();

        var act = async () => await signingService.GetSigningKeysAsync(ct);

        (await act.Should().ThrowAsync<ZeeKayDaConfigurationException>()).WithMessage("*file_not_found*");
    }

    [Fact]
    public async Task Full_DI_wiring_surfaces_invalid_PEM_content_as_ZeeKayDaConfigurationException()
    {
        var ct = TestContext.Current.CancellationToken;
        using var tempDir = new TempSigningKeyDirectory();
        var path = tempDir.WriteTextFile("key.pem", "this is not a valid PEM file");
        var (services, _) = BuildServices(T0);

        var builder = new ZeeKayDaAuthBuilder(services);
        builder.AddPemFileSigning(path, SigningAlgorithm.RS256);

        await using var provider = services.BuildServiceProvider();
        var signingService = provider.GetRequiredService<IJwtSigningService>();

        var act = async () => await signingService.GetSigningKeysAsync(ct);

        (await act.Should().ThrowAsync<ZeeKayDaConfigurationException>()).WithMessage("*invalid_pem*");
    }

    [Fact]
    public async Task Full_DI_wiring_surfaces_a_wrong_PFX_password_as_ZeeKayDaConfigurationException_without_leaking_it()
    {
        var ct = TestContext.Current.CancellationToken;
        using var tempDir = new TempSigningKeyDirectory();
        using var certificate = TestCertificateFactory.CreateRsaSelfSigned("test", T0 - TimeSpan.FromDays(1), T0 + TimeSpan.FromDays(365));
        var path = tempDir.WritePfxFile("key.pfx", certificate, CorrectPassword);
        var (services, _) = BuildServices(T0);

        var builder = new ZeeKayDaAuthBuilder(services);
        builder.AddPfxFileSigning(path, SigningAlgorithm.RS256, _ => ValueTask.FromResult("wrong-password"));

        await using var provider = services.BuildServiceProvider();
        var signingService = provider.GetRequiredService<IJwtSigningService>();

        var act = async () => await signingService.GetSigningKeysAsync(ct);

        var exception = await act.Should().ThrowAsync<ZeeKayDaConfigurationException>();
        exception.Which.Message.Should().Contain("invalid_pfx");
        exception.Which.Message.Should().NotContain(CorrectPassword);
    }

    // ── End-to-end signature verification (AC #8/#9) ─────────────────────────────────────────────

    [Fact]
    public async Task Full_DI_wiring_signed_token_validates_against_the_published_public_key()
    {
        var ct = TestContext.Current.CancellationToken;
        using var tempDir = new TempSigningKeyDirectory();
        using var certificate = TestCertificateFactory.CreateRsaSelfSigned("test", T0 - TimeSpan.FromDays(1), T0 + TimeSpan.FromDays(365));
        var path = tempDir.WritePemFile("key.pem", certificate);
        var (services, _) = BuildServices(T0);

        var builder = new ZeeKayDaAuthBuilder(services);
        builder.AddPemFileSigning(path, SigningAlgorithm.RS256);

        await using var provider = services.BuildServiceProvider();
        var signingService = provider.GetRequiredService<IJwtSigningService>();
        var payloadSegment = SigningTestHelpers.Base64UrlEncode("{\"sub\":\"test-subject\"}"u8.ToArray());

        var result = await signingService.SignAsync(payloadSegment, ct);
        var keys = await signingService.GetSigningKeysAsync(ct);
        var descriptor = keys.Single(k => k.Kid == result.Kid);

        SigningTestHelpers.VerifyRsaSignature(descriptor, result, payloadSegment).Should().BeTrue(
            "a relying party fetching this key from the JWKS must be able to validate a token this service signs");
    }

    // ── Startup service ───────────────────────────────────────────────────────────────────────────

    [Fact]
    public async Task StartupService_StartAsync_forces_key_loading_and_propagates_configuration_failure()
    {
        var ct = TestContext.Current.CancellationToken;
        using var tempDir = new TempSigningKeyDirectory();
        var missingPath = tempDir.GetPath("does-not-exist.pem");
        var (services, _) = BuildServices(T0);

        var builder = new ZeeKayDaAuthBuilder(services);
        builder.AddPemFileSigning(missingPath, SigningAlgorithm.RS256);

        await using var provider = services.BuildServiceProvider();
        var startupService = provider.GetServices<IHostedService>().OfType<FileSigningStartupService>().Single();

        var act = async () => await startupService.StartAsync(ct);

        (await act.Should().ThrowAsync<ZeeKayDaConfigurationException>()).WithMessage("*file_not_found*");
    }

    [Fact]
    public async Task StartupService_StartAsync_succeeds_when_the_key_loads_without_error()
    {
        var ct = TestContext.Current.CancellationToken;
        using var tempDir = new TempSigningKeyDirectory();
        using var certificate = TestCertificateFactory.CreateRsaSelfSigned("test", T0 - TimeSpan.FromDays(1), T0 + TimeSpan.FromDays(365));
        var path = tempDir.WritePemFile("key.pem", certificate);
        var (services, _) = BuildServices(T0);

        var builder = new ZeeKayDaAuthBuilder(services);
        builder.AddPemFileSigning(path, SigningAlgorithm.RS256);

        await using var provider = services.BuildServiceProvider();
        var startupService = provider.GetServices<IHostedService>().OfType<FileSigningStartupService>().Single();

        var act = async () => await startupService.StartAsync(ct);

        await act.Should().NotThrowAsync();
    }

    // ── Helpers ───────────────────────────────────────────────────────────────────────────────────

    private sealed class SigningKeyRetirementWindowProviderStub(TimeSpan window) : ISigningKeyRetirementWindowProvider
    {
        public TimeSpan GetRetirementWindow() => window;
    }
}
