// These tests exercise the full DI wiring for AddPemFileSigning/AddPfxFileSigning end to end — a
// real ServiceCollection / ZeeKayDaAuthCoreBuilder / ServiceProvider — reading real temporary PEM/PFX
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
using ZeeKayDa.Auth.StartupVerification;
using ZeeKayDa.Auth.Tokens;

namespace ZeeKayDa.Auth.FileSystem.Tests.Integration;

public sealed class FileSigningIntegrationTests
{
    private static readonly DateTimeOffset T0 = DateTimeOffset.Parse("2026-01-01T00:00:00Z");
    private const string CorrectPassword = "correct horse battery staple";

    private static (ServiceCollection Services, FakeTimeProvider TimeProvider) BuildServices(DateTimeOffset now)
    {
        var timeProvider = new FakeTimeProvider(now);
        var services = new ServiceCollection();
        services.AddSingleton(typeof(ILogger<>), typeof(NullLogger<>));
        services.AddSingleton<TimeProvider>(timeProvider);
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

        var builder = services.AddZeeKayDaAuthCoreForTesting();
        builder.AddPemFileSigning(path, SigningAlgorithm.RS256);

        await using var provider = services.BuildServiceProvider();
        await StartHostedServicesAsync(provider, ct);
        var ring = provider.GetRequiredService<SigningKeyRing>();

        ring.Current.Published.Should().ContainSingle("the single listed file's public key must be published");
        ring.Current.SigningKey!.Kid.Should().Be(JwkThumbprint.Compute(certificate.GetRSAPublicKey()!.ExportParameters(false)));
        ring.Current.Algorithm.Should().Be(SigningAlgorithm.RS256);

        var signingInput = "header.payload"u8.ToArray();
        var outcome = await ring.SignAsync(signingInput, static (_, input) => input, ct);

        using var rsa = RSA.Create(ring.Current.SigningKey!.PublicKey.RsaPublicParameters!.Value);
        rsa.VerifyData(outcome.SigningInput.Span, outcome.Signature.Span, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1)
            .Should().BeTrue("the ring must sign with the private key of the published file");
    }

    [Fact]
    public async Task Full_DI_wiring_publishes_every_listed_PEM_file_and_signs_with_the_newer_one_past_the_lead_time()
    {
        var ct = TestContext.Current.CancellationToken;
        using var tempDir = new TempSigningKeyDirectory();
        using var older = TestCertificateFactory.CreateRsaSelfSigned("older", T0 - TimeSpan.FromDays(400), T0 + TimeSpan.FromDays(30));
        // Just past the one-day lead time, so the newer certificate signs and the older one stays
        // published, still inside its own validity window.
        using var newer = TestCertificateFactory.CreateRsaSelfSigned("newer", T0 - TimeSpan.FromDays(1) - TimeSpan.FromMinutes(1), T0 + TimeSpan.FromDays(365));
        var olderPath = tempDir.WritePemFile("older.pem", older);
        var newerPath = tempDir.WritePemFile("newer.pem", newer);
        var (services, _) = BuildServices(T0);

        var builder = services.AddZeeKayDaAuthCoreForTesting();
        builder.AddPemFileSigning(SigningAlgorithm.RS256, options =>
        {
            options.Files.Add(new PemSigningFile(olderPath));
            options.Files.Add(new PemSigningFile(newerPath));
        });

        await using var provider = services.BuildServiceProvider();
        await StartHostedServicesAsync(provider, ct);
        var ring = provider.GetRequiredService<SigningKeyRing>();

        ring.Current.Published.Should().HaveCount(2, "every listed file is published so relying parties can cache it");
        ring.Current.SigningKey!.Kid.Should().Be(JwkThumbprint.Compute(newer.GetRSAPublicKey()!.ExportParameters(false)));
    }

    [Fact]
    public async Task Full_DI_wiring_signs_with_the_older_PEM_file_while_the_newer_one_is_inside_the_lead_time()
    {
        var ct = TestContext.Current.CancellationToken;
        using var tempDir = new TempSigningKeyDirectory();
        using var older = TestCertificateFactory.CreateRsaSelfSigned("older", T0 - TimeSpan.FromDays(400), T0 + TimeSpan.FromDays(30));
        using var newer = TestCertificateFactory.CreateRsaSelfSigned("newer", T0 - TimeSpan.FromHours(1), T0 + TimeSpan.FromDays(365));
        var olderPath = tempDir.WritePemFile("older.pem", older);
        var newerPath = tempDir.WritePemFile("newer.pem", newer);
        var (services, _) = BuildServices(T0);

        var builder = services.AddZeeKayDaAuthCoreForTesting();
        builder.AddPemFileSigning(SigningAlgorithm.RS256, options =>
        {
            options.Files.Add(new PemSigningFile(newerPath));
            options.Files.Add(new PemSigningFile(olderPath));
        });

        await using var provider = services.BuildServiceProvider();
        await StartHostedServicesAsync(provider, ct);
        var ring = provider.GetRequiredService<SigningKeyRing>();

        ring.Current.SigningKey!.Kid.Should().Be(
            JwkThumbprint.Compute(older.GetRSAPublicKey()!.ExportParameters(false)),
            "a certificate newer than the lead time has not had time to reach relying parties' JWKS caches yet");
        ring.Current.Published.Should().HaveCount(2);
    }

    [Fact]
    public async Task Full_DI_wiring_keeps_publishing_a_PEM_file_that_is_deleted_after_startup()
    {
        // The ring reads the source once, at startup, so nothing that happens to the files afterwards
        // changes what this process signs with or publishes until it next reads them.
        var ct = TestContext.Current.CancellationToken;
        using var tempDir = new TempSigningKeyDirectory();
        using var current = TestCertificateFactory.CreateRsaSelfSigned("current", T0 - TimeSpan.FromDays(1), T0 + TimeSpan.FromDays(365));
        using var next = TestCertificateFactory.CreateRsaSelfSigned("next", T0 + TimeSpan.FromDays(1), T0 + TimeSpan.FromDays(400));
        var currentPath = tempDir.WritePemFile("current.pem", current);
        var nextPath = tempDir.WritePemFile("next.pem", next);
        var (services, _) = BuildServices(T0);

        var builder = services.AddZeeKayDaAuthCoreForTesting();
        builder.AddPemFileSigning(SigningAlgorithm.RS256, options =>
        {
            options.Files.Add(new PemSigningFile(currentPath));
            options.Files.Add(new PemSigningFile(nextPath));
        });

        await using var provider = services.BuildServiceProvider();
        await StartHostedServicesAsync(provider, ct);
        var ring = provider.GetRequiredService<SigningKeyRing>();
        var publishedAtStartup = ring.Current.Published.Select(k => k.Kid).ToArray();

        File.Delete(currentPath);
        File.Delete(nextPath);

        ring.Current.Published.Select(k => k.Kid).Should().Equal(publishedAtStartup);

        var outcome = await ring.SignAsync("header.payload"u8.ToArray(), static (_, input) => input, ct);
        outcome.Key.Kid.Should().Be(JwkThumbprint.Compute(current.GetRSAPublicKey()!.ExportParameters(false)));
    }

    [Fact]
    public async Task Full_DI_wiring_signs_with_the_only_PEM_certificate_even_before_its_NotBefore()
    {
        // NotBefore is no validity gate: no relying party can observe it, so a lone certificate dated
        // in the future signs at once rather than failing startup.
        var ct = TestContext.Current.CancellationToken;
        using var tempDir = new TempSigningKeyDirectory();
        using var certificate = TestCertificateFactory.CreateRsaSelfSigned("future", T0 + TimeSpan.FromDays(1), T0 + TimeSpan.FromDays(400));
        var path = tempDir.WritePemFile("current.pem", certificate);
        var (services, _) = BuildServices(T0);

        var builder = services.AddZeeKayDaAuthCoreForTesting();
        builder.AddPemFileSigning(path, SigningAlgorithm.RS256);

        await using var provider = services.BuildServiceProvider();
        await StartHostedServicesAsync(provider, ct);

        provider.GetRequiredService<SigningKeyRing>().Current.SigningKey!.Kid
            .Should().Be(JwkThumbprint.Compute(certificate.GetRSAPublicKey()!.ExportParameters(false)));
    }

    [Fact]
    public async Task Full_DI_wiring_starts_and_signs_on_when_the_only_PEM_certificate_has_expired()
    {
        var ct = TestContext.Current.CancellationToken;
        using var tempDir = new TempSigningKeyDirectory();
        using var certificate = TestCertificateFactory.CreateRsaSelfSigned("expired", T0 - TimeSpan.FromDays(400), T0 - TimeSpan.FromDays(1));
        var path = tempDir.WritePemFile("current.pem", certificate);
        var (services, _) = BuildServices(T0);

        var builder = services.AddZeeKayDaAuthCoreForTesting();
        builder.AddPemFileSigning(path, SigningAlgorithm.RS256);

        await using var provider = services.BuildServiceProvider();
        await StartHostedServicesAsync(provider, ct);

        var outcome = await provider.GetRequiredService<SigningKeyRing>()
            .SignAsync("header.payload"u8.ToArray(), static (_, input) => input, ct);
        outcome.Key.Kid.Should().Be(JwkThumbprint.Compute(certificate.GetRSAPublicKey()!.ExportParameters(false)));
        certificate.GetRSAPublicKey()!.VerifyData(
                "header.payload"u8.ToArray(), outcome.Signature.Span, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1)
            .Should().BeTrue();
    }

    [Fact]
    public async Task Full_DI_wiring_fails_startup_when_no_PEM_file_is_listed()
    {
        var ct = TestContext.Current.CancellationToken;
        var (services, _) = BuildServices(T0);

        var builder = services.AddZeeKayDaAuthCoreForTesting();
        builder.AddPemFileSigning(SigningAlgorithm.RS256, _ => { });

        await using var provider = services.BuildServiceProvider();
        var act = async () => await StartHostedServicesAsync(provider, ct);

        (await act.Should().ThrowAsync<ZeeKayDaConfigurationException>())
            .Which.AggregatedFailures.Should().Contain(f => f.Code == "configuration.pem_file_signing.files.empty");
    }

    [Fact]
    public async Task Full_DI_wiring_fails_startup_naming_a_PEM_file_whose_key_does_not_suit_the_algorithm()
    {
        var ct = TestContext.Current.CancellationToken;
        using var tempDir = new TempSigningKeyDirectory();
        using var certificate = TestCertificateFactory.CreateRsaSelfSigned("current", T0 - TimeSpan.FromDays(1), T0 + TimeSpan.FromDays(365));
        var path = tempDir.WritePemFile("current.pem", certificate);
        var (services, _) = BuildServices(T0);

        var builder = services.AddZeeKayDaAuthCoreForTesting();
        builder.AddPemFileSigning(path, SigningAlgorithm.ES256);

        await using var provider = services.BuildServiceProvider();
        var act = async () => await StartHostedServicesAsync(provider, ct);

        var exception = await act.Should().ThrowAsync<ZeeKayDaConfigurationException>();
        exception.Which.AggregatedFailures.Should().ContainSingle(f => f.Code == "signing.key_algorithm_mismatch")
            .Which.Message.Should().Contain(path);
    }

    [Fact]
    public async Task Full_DI_wiring_fails_startup_naming_a_PFX_bundle_whose_key_does_not_suit_the_algorithm()
    {
        var ct = TestContext.Current.CancellationToken;
        using var tempDir = new TempSigningKeyDirectory();
        using var certificate = TestCertificateFactory.CreateRsaSelfSigned("current", T0 - TimeSpan.FromDays(1), T0 + TimeSpan.FromDays(365));
        var path = tempDir.WritePfxFile("current.pfx", certificate, CorrectPassword);
        var (services, _) = BuildServices(T0);

        var builder = services.AddZeeKayDaAuthCoreForTesting();
        builder.AddPfxFileSigning(path, SigningAlgorithm.ES256, _ => Task.FromResult(CorrectPassword));

        await using var provider = services.BuildServiceProvider();
        var act = async () => await StartHostedServicesAsync(provider, ct);

        var exception = await act.Should().ThrowAsync<ZeeKayDaConfigurationException>();
        exception.Which.AggregatedFailures.Should().ContainSingle(f => f.Code == "signing.key_algorithm_mismatch")
            .Which.Message.Should().Contain(path);
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

        var builder = services.AddZeeKayDaAuthCoreForTesting();
        builder.AddPfxFileSigning(path, SigningAlgorithm.RS256, _ => Task.FromResult(CorrectPassword));

        await using var provider = services.BuildServiceProvider();
        await StartHostedServicesAsync(provider, ct);
        var ring = provider.GetRequiredService<SigningKeyRing>();

        ring.Current.Published.Should().ContainSingle();
        ring.Current.SigningKey!.Kid.Should().Be(JwkThumbprint.Compute(certificate.GetRSAPublicKey()!.ExportParameters(false)));

        var outcome = await ring.SignAsync("header.payload"u8.ToArray(), static (_, input) => input, ct);

        using var rsa = RSA.Create(ring.Current.SigningKey!.PublicKey.RsaPublicParameters!.Value);
        rsa.VerifyData(outcome.SigningInput.Span, outcome.Signature.Span, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1)
            .Should().BeTrue("the ring must sign with the private key of the published file");
    }

    [Fact]
    public async Task Full_DI_wiring_publishes_every_listed_PFX_file_and_signs_with_the_newer_one_past_the_lead_time()
    {
        var ct = TestContext.Current.CancellationToken;
        using var tempDir = new TempSigningKeyDirectory();
        using var older = TestCertificateFactory.CreateRsaSelfSigned("older", T0 - TimeSpan.FromDays(400), T0 + TimeSpan.FromDays(30));
        // Just past the one-day lead time, so the newer certificate signs and the older one stays
        // published, still inside its own validity window.
        using var newer = TestCertificateFactory.CreateRsaSelfSigned("newer", T0 - TimeSpan.FromDays(1) - TimeSpan.FromMinutes(1), T0 + TimeSpan.FromDays(365));
        var olderPath = tempDir.WritePfxFile("older.pfx", older, "older-password");
        var newerPath = tempDir.WritePfxFile("newer.pfx", newer, CorrectPassword);
        var (services, _) = BuildServices(T0);

        var builder = services.AddZeeKayDaAuthCoreForTesting();
        builder.AddPfxFileSigning(SigningAlgorithm.RS256, options =>
        {
            options.Files.Add(new PfxFile(olderPath, _ => Task.FromResult("older-password")));
            options.Files.Add(new PfxFile(newerPath, _ => Task.FromResult(CorrectPassword)));
        });

        await using var provider = services.BuildServiceProvider();
        await StartHostedServicesAsync(provider, ct);
        var ring = provider.GetRequiredService<SigningKeyRing>();

        ring.Current.Published.Should().HaveCount(2, "every listed file is published, each opened with its own password");
        ring.Current.SigningKey!.Kid.Should().Be(JwkThumbprint.Compute(newer.GetRSAPublicKey()!.ExportParameters(false)));
    }

    [Fact]
    public async Task Full_DI_wiring_keeps_publishing_a_PFX_bundle_that_is_deleted_after_startup()
    {
        var ct = TestContext.Current.CancellationToken;
        using var tempDir = new TempSigningKeyDirectory();
        using var current = TestCertificateFactory.CreateRsaSelfSigned("current", T0 - TimeSpan.FromDays(1), T0 + TimeSpan.FromDays(365));
        using var next = TestCertificateFactory.CreateRsaSelfSigned("next", T0 + TimeSpan.FromDays(1), T0 + TimeSpan.FromDays(400));
        var currentPath = tempDir.WritePfxFile("current.pfx", current, CorrectPassword);
        var nextPath = tempDir.WritePfxFile("next.pfx", next, CorrectPassword);
        var (services, _) = BuildServices(T0);

        var builder = services.AddZeeKayDaAuthCoreForTesting();
        builder.AddPfxFileSigning(SigningAlgorithm.RS256, options =>
        {
            options.Files.Add(new PfxFile(currentPath, _ => Task.FromResult(CorrectPassword)));
            options.Files.Add(new PfxFile(nextPath, _ => Task.FromResult(CorrectPassword)));
        });

        await using var provider = services.BuildServiceProvider();
        await StartHostedServicesAsync(provider, ct);
        var ring = provider.GetRequiredService<SigningKeyRing>();
        var publishedAtStartup = ring.Current.Published.Select(k => k.Kid).ToArray();

        File.Delete(currentPath);
        File.Delete(nextPath);

        ring.Current.Published.Select(k => k.Kid).Should().Equal(publishedAtStartup);

        var outcome = await ring.SignAsync("header.payload"u8.ToArray(), static (_, input) => input, ct);
        outcome.Key.Kid.Should().Be(JwkThumbprint.Compute(current.GetRSAPublicKey()!.ExportParameters(false)));
    }

    // ── Startup failure propagation ──────────────────────────────────────────────────────────────

    [Fact]
    public async Task Full_DI_wiring_fails_startup_naming_the_PEM_file_whose_key_does_not_match_the_configured_algorithm()
    {
        var ct = TestContext.Current.CancellationToken;
        using var tempDir = new TempSigningKeyDirectory();
        using var certificate = TestCertificateFactory.CreateRsaSelfSigned("rsa", T0 - TimeSpan.FromDays(1), T0 + TimeSpan.FromDays(365));
        var path = tempDir.WritePemFile("current.pem", certificate);
        var (services, _) = BuildServices(T0);

        var builder = services.AddZeeKayDaAuthCoreForTesting();
        builder.AddPemFileSigning(path, SigningAlgorithm.ES256);

        await using var provider = services.BuildServiceProvider();
        var act = async () => await StartHostedServicesAsync(provider, ct);

        var exception = await act.Should().ThrowAsync<ZeeKayDaConfigurationException>();
        exception.Which.AggregatedFailures.Should().ContainSingle(f => f.Code == "signing.key_algorithm_mismatch");
        exception.Which.Message.Should().Contain(path);
    }

    [Fact]
    public async Task Full_DI_wiring_fails_startup_naming_the_PFX_bundle_whose_key_does_not_match_the_configured_algorithm()
    {
        var ct = TestContext.Current.CancellationToken;
        using var tempDir = new TempSigningKeyDirectory();
        using var certificate = TestCertificateFactory.CreateRsaSelfSigned("rsa", T0 - TimeSpan.FromDays(1), T0 + TimeSpan.FromDays(365));
        var path = tempDir.WritePfxFile("current.pfx", certificate, CorrectPassword);
        var (services, _) = BuildServices(T0);

        var builder = services.AddZeeKayDaAuthCoreForTesting();
        builder.AddPfxFileSigning(path, SigningAlgorithm.ES256, _ => Task.FromResult(CorrectPassword));

        await using var provider = services.BuildServiceProvider();
        var act = async () => await StartHostedServicesAsync(provider, ct);

        var exception = await act.Should().ThrowAsync<ZeeKayDaConfigurationException>();
        exception.Which.AggregatedFailures.Should().ContainSingle(f => f.Code == "signing.key_algorithm_mismatch");
        exception.Which.Message.Should().Contain(path);
    }

    [Fact]
    public async Task Ring_stops_signing_at_the_next_read_after_the_only_listed_file_is_deleted()
    {
        var ct = TestContext.Current.CancellationToken;
        using var tempDir = new TempSigningKeyDirectory();
        using var certificate = TestCertificateFactory.CreateRsaSelfSigned("test", T0 - TimeSpan.FromDays(1), T0 + TimeSpan.FromDays(365));
        var path = tempDir.WritePemFile("current.pem", certificate);
        var (services, time) = BuildServices(T0);
        services.AddZeeKayDaAuthCoreForTesting().AddPemFileSigning(path, SigningAlgorithm.RS256);
        await using var provider = services.BuildServiceProvider();
        await StartHostedServicesAsync(provider, ct);
        var ring = provider.GetRequiredService<SigningKeyRing>();

        File.Delete(path);
        time.Advance(new SigningKeyOptions().RefreshInterval);
        await ring.LastTransition;

        ring.Current.SigningKey.Should().BeNull();
        ring.Current.Published.Should().BeEmpty();
    }

    [Fact]
    public async Task Full_DI_wiring_fails_startup_with_no_keys_when_the_only_listed_file_is_missing()
    {
        var ct = TestContext.Current.CancellationToken;
        using var tempDir = new TempSigningKeyDirectory();
        var missingPath = tempDir.GetPath("does-not-exist.pem");
        var (services, _) = BuildServices(T0);

        var builder = services.AddZeeKayDaAuthCoreForTesting();
        builder.AddPemFileSigning(missingPath, SigningAlgorithm.RS256);

        await using var provider = services.BuildServiceProvider();

        var act = async () => await StartHostedServicesAsync(provider, ct);

        (await act.Should().ThrowAsync<ZeeKayDaConfigurationException>()).WithMessage("*signing.no_keys*");
    }

    [Fact]
    public async Task Full_DI_wiring_surfaces_invalid_PEM_content_as_ZeeKayDaConfigurationException()
    {
        var ct = TestContext.Current.CancellationToken;
        using var tempDir = new TempSigningKeyDirectory();
        var path = tempDir.WriteTextFile("key.pem", "this is not a valid PEM file");
        var (services, _) = BuildServices(T0);

        var builder = services.AddZeeKayDaAuthCoreForTesting();
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

        var builder = services.AddZeeKayDaAuthCoreForTesting();
        builder.AddPfxFileSigning(path, SigningAlgorithm.RS256, _ => Task.FromResult("wrong-password"));

        await using var provider = services.BuildServiceProvider();

        var act = async () => await StartHostedServicesAsync(provider, ct);

        var exception = await act.Should().ThrowAsync<ZeeKayDaConfigurationException>();
        exception.Which.Message.Should().Contain("invalid_pfx");
        exception.Which.Message.Should().NotContain(CorrectPassword).And.NotContain("wrong-password");
    }

    // ── End-to-end signature verification (AC #8/#9) ─────────────────────────────────────────────

    // ── Startup verifier ──────────────────────────────────────────────────────────────────────────
    // The PEM provider no longer registers an IJwtSigningService, so the generic
    // SigningStartupSelfTest verifier that used to pre-warm and self-test it does not apply here.
    // AddSigningKeySource registers the SigningKeyRing verifier instead, and that verifier
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

        var builder = services.AddZeeKayDaAuthCoreForTesting();
        builder.AddPemFileSigning(path, SigningAlgorithm.RS256);

        await using var provider = services.BuildServiceProvider();
        provider.GetServices<IStartupActivator>().Select(v => v.Name).Should().Contain("SigningKeyRing");
    }

    // ── Helpers ───────────────────────────────────────────────────────────────────────────────────
}
