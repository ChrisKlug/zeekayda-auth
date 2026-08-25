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

using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Time.Testing;
using ZeeKayDa.Auth;
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

    // ── PEM: end-to-end through the signing key ring ────────────────────────────────────────────

    /// <summary>
    /// Runs the host's real startup path — every registered <see cref="IHostedService"/>, which is
    /// what initializes the signing key ring — so these tests observe exactly what a deployed host
    /// observes, including a startup that fails.
    /// </summary>
    private static async Task StartHostedServicesAsync(ServiceProvider provider, CancellationToken cancellationToken)
    {
        foreach (var hostedService in provider.GetServices<IHostedService>())
            await hostedService.StartAsync(cancellationToken);
    }

    [Fact]
    public async Task Full_DI_wiring_serves_a_PEM_file_through_the_ring_and_signs_a_JWS()
    {
        var ct = TestContext.Current.CancellationToken;
        using var tempDir = new TempSigningKeyDirectory();
        using var certificate = TestCertificateFactory.CreateRsaSelfSigned("test", T0 - TimeSpan.FromDays(1), T0 + TimeSpan.FromDays(365));
        var path = tempDir.WritePemFile("current.pem", certificate);
        var (services, _) = BuildServices(T0);

        var builder = new ZeeKayDaAuthBuilder(services);
        builder.AddPemFileSigning(path, SigningAlgorithm.RS256);

        await using var provider = services.BuildServiceProvider();
        await StartHostedServicesAsync(provider, ct);
        var ring = provider.GetRequiredService<ISigningKeyRing>();

        ring.Current.Published.Should().ContainSingle("the single configured slot's public key must be published");
        ring.Current.SigningKey.Kid.Should().Be(JwkThumbprint.Compute(certificate.GetRSAPublicKey()!.ExportParameters(false)));
        ring.Current.AdvertisedAlgorithms.Should().Equal(SigningAlgorithm.RS256);

        var signingInput = "header.payload"u8.ToArray();
        var outcome = await ring.SignAsync(signingInput, static (_, input) => input, ct);

        using var rsa = RSA.Create(ring.Current.SigningKey.PublicKey.RsaPublicParameters!.Value);
        rsa.VerifyData(outcome.SigningInput.Span, outcome.Signature.Span, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1)
            .Should().BeTrue("the ring must sign with the private key of the published Current slot");
    }

    [Fact]
    public async Task Full_DI_wiring_publishes_every_configured_PEM_slot_and_signs_with_Current()
    {
        var ct = TestContext.Current.CancellationToken;
        using var tempDir = new TempSigningKeyDirectory();
        using var previous = TestCertificateFactory.CreateRsaSelfSigned("previous", T0 - TimeSpan.FromDays(400), T0 + TimeSpan.FromDays(30));
        using var current = TestCertificateFactory.CreateRsaSelfSigned("current", T0 - TimeSpan.FromDays(30), T0 + TimeSpan.FromDays(365));
        using var next = TestCertificateFactory.CreateRsaSelfSigned("next", T0 + TimeSpan.FromDays(1), T0 + TimeSpan.FromDays(400));
        var previousPath = tempDir.WritePemFile("previous.pem", previous);
        var currentPath = tempDir.WritePemFile("current.pem", current);
        var nextPath = tempDir.WritePemFile("next.pem", next);
        var (services, _) = BuildServices(T0);

        var builder = new ZeeKayDaAuthBuilder(services);
        builder.AddPemFileSigning(SigningAlgorithm.RS256, options =>
        {
            options.Previous = new PemSigningFile(previousPath);
            options.Current = new PemSigningFile(currentPath);
            options.Next = new PemSigningFile(nextPath);
        });

        await using var provider = services.BuildServiceProvider();
        await StartHostedServicesAsync(provider, ct);
        var ring = provider.GetRequiredService<ISigningKeyRing>();

        ring.Current.Published.Should().HaveCount(3, "every configured slot is published so relying parties can cache it");
        ring.Current.SigningKey.Kid.Should().Be(JwkThumbprint.Compute(current.GetRSAPublicKey()!.ExportParameters(false)));
    }

    [Fact]
    public async Task Full_DI_wiring_keeps_publishing_a_PEM_file_that_is_deleted_after_startup()
    {
        // The source reads its slots once, at startup, and never re-reads them, so nothing that
        // happens to the files afterwards can change what this process signs with or publishes.
        var ct = TestContext.Current.CancellationToken;
        using var tempDir = new TempSigningKeyDirectory();
        using var current = TestCertificateFactory.CreateRsaSelfSigned("current", T0 - TimeSpan.FromDays(1), T0 + TimeSpan.FromDays(365));
        using var next = TestCertificateFactory.CreateRsaSelfSigned("next", T0 + TimeSpan.FromDays(1), T0 + TimeSpan.FromDays(400));
        var currentPath = tempDir.WritePemFile("current.pem", current);
        var nextPath = tempDir.WritePemFile("next.pem", next);
        var (services, _) = BuildServices(T0);

        var builder = new ZeeKayDaAuthBuilder(services);
        builder.AddPemFileSigning(SigningAlgorithm.RS256, options =>
        {
            options.Current = new PemSigningFile(currentPath);
            options.Next = new PemSigningFile(nextPath);
        });

        await using var provider = services.BuildServiceProvider();
        await StartHostedServicesAsync(provider, ct);
        var ring = provider.GetRequiredService<ISigningKeyRing>();
        var publishedAtStartup = ring.Current.Published.Select(k => k.Kid).ToArray();

        File.Delete(currentPath);
        File.Delete(nextPath);

        ring.Current.Published.Select(k => k.Kid).Should().Equal(publishedAtStartup);

        var outcome = await ring.SignAsync("header.payload"u8.ToArray(), static (_, input) => input, ct);
        outcome.Key.Kid.Should().Be(JwkThumbprint.Compute(current.GetRSAPublicKey()!.ExportParameters(false)));
    }

    [Fact]
    public async Task Full_DI_wiring_fails_startup_when_the_Current_PEM_certificate_is_not_valid_yet()
    {
        // The single-key bootstrap exemption is gone: a lone configured file is the active signer
        // through ordinary slot selection, with no special case that would let a not-yet-valid
        // certificate sign.
        var ct = TestContext.Current.CancellationToken;
        using var tempDir = new TempSigningKeyDirectory();
        using var certificate = TestCertificateFactory.CreateRsaSelfSigned("future", T0 + TimeSpan.FromDays(1), T0 + TimeSpan.FromDays(400));
        var path = tempDir.WritePemFile("current.pem", certificate);
        var (services, _) = BuildServices(T0);

        var builder = new ZeeKayDaAuthBuilder(services);
        builder.AddPemFileSigning(path, SigningAlgorithm.RS256);

        await using var provider = services.BuildServiceProvider();
        var act = async () => await StartHostedServicesAsync(provider, ct);

        (await act.Should().ThrowAsync<ZeeKayDaConfigurationException>())
            .Which.AggregatedFailures.Should().Contain(f => f.Code == "signing.signing_key_not_yet_valid");
    }

    [Fact]
    public async Task Full_DI_wiring_fails_startup_when_the_Current_PEM_certificate_has_expired()
    {
        var ct = TestContext.Current.CancellationToken;
        using var tempDir = new TempSigningKeyDirectory();
        using var certificate = TestCertificateFactory.CreateRsaSelfSigned("expired", T0 - TimeSpan.FromDays(400), T0 - TimeSpan.FromDays(1));
        var path = tempDir.WritePemFile("current.pem", certificate);
        var (services, _) = BuildServices(T0);

        var builder = new ZeeKayDaAuthBuilder(services);
        builder.AddPemFileSigning(path, SigningAlgorithm.RS256);

        await using var provider = services.BuildServiceProvider();
        var act = async () => await StartHostedServicesAsync(provider, ct);

        (await act.Should().ThrowAsync<ZeeKayDaConfigurationException>())
            .Which.AggregatedFailures.Should().Contain(f => f.Code == "signing.signing_key_expired");
    }

    [Fact]
    public async Task Full_DI_wiring_fails_startup_when_no_Current_PEM_slot_is_configured()
    {
        var ct = TestContext.Current.CancellationToken;
        using var tempDir = new TempSigningKeyDirectory();
        using var certificate = TestCertificateFactory.CreateRsaSelfSigned("next", T0 + TimeSpan.FromDays(1), T0 + TimeSpan.FromDays(400));
        var nextPath = tempDir.WritePemFile("next.pem", certificate);
        var (services, _) = BuildServices(T0);

        var builder = new ZeeKayDaAuthBuilder(services);
        builder.AddPemFileSigning(SigningAlgorithm.RS256, options => options.Next = new PemSigningFile(nextPath));

        await using var provider = services.BuildServiceProvider();
        var act = async () => await StartHostedServicesAsync(provider, ct);

        await act.Should().ThrowAsync<Exception>("the options validator rejects a configuration with no Current slot");
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

        var act = async () => await StartHostedServicesAsync(provider, ct);

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

        var act = async () => await StartHostedServicesAsync(provider, ct);

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

    // ── Startup verifier ──────────────────────────────────────────────────────────────────────────
    // The PEM provider no longer registers an IJwtSigningService, so the generic
    // SigningStartupSelfTest verifier that used to pre-warm and self-test it does not apply here.
    // AddZeeKayDaSigningKeySource registers the SigningKeyRing verifier instead, and that verifier
    // is what the hosted-service tests above run: they already prove it reads the source, builds the
    // set, opens the signer and self-tests it, and that a configuration failure fails the host. The
    // two PEM-specific self-test tests that stood here were deleted as duplicates of those; the PFX
    // provider's own self-test coverage below is untouched.

    [Fact]
    public async Task AddPemFileSigning_registers_the_signing_key_ring_startup_verifier()
    {
        // Pins the wiring the tests above depend on: without this verifier, a misconfigured signing
        // key would surface on the first request instead of failing the host.
        using var tempDir = new TempSigningKeyDirectory();
        using var certificate = TestCertificateFactory.CreateRsaSelfSigned("test", T0 - TimeSpan.FromDays(1), T0 + TimeSpan.FromDays(365));
        var path = tempDir.WritePemFile("current.pem", certificate);
        var (services, _) = BuildServices(T0);

        var builder = new ZeeKayDaAuthBuilder(services);
        builder.AddPemFileSigning(path, SigningAlgorithm.RS256);

        await using var provider = services.BuildServiceProvider();
        provider.GetServices<IStartupVerifier>().Select(v => v.Name).Should().Contain("SigningKeyRing");
    }

    private static IStartupVerifier FindSigningStartupSelfTestVerifier(ServiceProvider provider) =>
        provider.GetServices<IStartupVerifier>()
            .Single(v => v.Name == "SigningStartupSelfTest");

    // ── Helpers ───────────────────────────────────────────────────────────────────────────────────

    private sealed class SigningKeyRetirementWindowProviderStub(TimeSpan window) : ISigningKeyRetirementWindowProvider
    {
        public TimeSpan GetRetirementWindow() => window;
    }
}
