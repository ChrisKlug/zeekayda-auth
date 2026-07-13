// These tests exercise the full DI wiring for AddWindowsCertificateStoreSigning end to end — a real
// ServiceCollection / ZeeKayDaAuthBuilder / ServiceProvider — with a fake substituted for the
// ICertificateStoreReader seam. No real Windows Certificate Store access is made or required.
//
// AddWindowsCertificateStoreSigning's platform gate (AC #11) fires unconditionally before any DI
// wiring, so — unlike the rotation-timeline/descriptor-factory/key-extractor unit tests, which are
// pure functions and run on any OS — every test here that calls the real extension method can only
// run on Windows. Each test is individually skip-guarded rather than the whole class, matching the
// pattern already established in Extensions/ZeeKayDaAuthBuilderWindowsCertificateStoreSigningExtensionsTests.cs.
//
// KNOWN GAP: a real ACL-denied X509Store.Open() (the store_inaccessible failure) is not practically
// provokable in CI, so it is only simulated here via the fake's ExceptionToThrow. The genuinely
// Windows-only real-store round trip is covered separately by Integration/CertificateStoreReaderTests.cs.

using System.Security.Cryptography.X509Certificates;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Time.Testing;
using ZeeKayDa.Auth.Logging;
using ZeeKayDa.Auth.Tokens;
using ZeeKayDa.Auth.Windows.Tests.Fakes;
using ZeeKayDa.Auth.Windows.Tests.Fixtures;

namespace ZeeKayDa.Auth.Windows.Tests.Integration;

public sealed class WindowsCertificateStoreSigningIntegrationTests
{
    private static readonly DateTimeOffset T0 = DateTimeOffset.Parse("2026-01-01T00:00:00Z");
    private const string PrimaryThumbprint = "AABBCCDDEEFF00112233445566778899AABBCCD";
    private const string SecondaryThumbprint = "1111111111111111111111111111111111111A";
    private const string RequiresWindowsReason = "AddWindowsCertificateStoreSigning's platform gate fires unconditionally, before any DI wiring";

    private static (ServiceCollection Services, FakeCertificateStoreReader Reader, FakeTimeProvider TimeProvider) BuildServices(
        DateTimeOffset now, TimeSpan? retirementWindow = null)
    {
        var reader = new FakeCertificateStoreReader();
        var timeProvider = new FakeTimeProvider(now);
        var services = new ServiceCollection();
        services.AddSingleton(typeof(ILogger<>), typeof(NullLogger<>));
        services.AddSingleton<ICertificateStoreReader>(reader);
        services.AddSingleton<ISigningKeyRetirementWindowProvider>(new FakeRetirementWindowProvider(retirementWindow ?? TimeSpan.FromHours(1)));
        services.AddSingleton<TimeProvider>(timeProvider);
        return (services, reader, timeProvider);
    }

    // ── End-to-end: resolve, list keys (JWKS shape) ─────────────────────────────────────────────

    [Fact]
    public async Task Full_DI_wiring_resolves_and_returns_a_well_formed_signing_key_for_one_certificate()
    {
        Assert.SkipUnless(OperatingSystem.IsWindows(), RequiresWindowsReason);

        var ct = TestContext.Current.CancellationToken;
        var (services, reader, _) = BuildServices(T0);
        using var certificate = TestCertificateFactory.CreateRsaSelfSigned("test", T0 + TimeSpan.FromDays(1), T0 + TimeSpan.FromDays(365));
        reader.AddCertificate(PrimaryThumbprint, certificate);

        var builder = new ZeeKayDaAuthBuilder(services);
        builder.AddWindowsCertificateStoreSigning(PrimaryThumbprint, StoreLocation.CurrentUser, StoreName.My);

        await using var provider = services.BuildServiceProvider();
        var signingService = provider.GetRequiredService<IJwtSigningService>();

        var keys = await signingService.GetSigningKeysAsync(ct);

        keys.Should().ContainSingle("the single registered certificate activates immediately regardless of NotBefore (AC #6)");
        keys[0].Kid.Should().NotBeNullOrEmpty();
        keys[0].Kid.Should().NotContain(PrimaryThumbprint, "kid must be the RFC 7638 thumbprint, never the certificate's own thumbprint (AC #3)");
        keys[0].Algorithm.Should().Be(SigningAlgorithm.RS256, "the default WindowsCertificateStoreSigningOptions.Algorithm is RS256");
        keys[0].RsaPublicParameters.Should().NotBeNull("the JWKS entry must expose only the public key");
    }

    [Fact]
    public async Task Full_DI_wiring_JWKS_output_includes_both_certificates_during_a_rotation_overlap()
    {
        Assert.SkipUnless(OperatingSystem.IsWindows(), RequiresWindowsReason);

        var ct = TestContext.Current.CancellationToken;
        var (services, reader, _) = BuildServices(T0);
        using var primary = TestCertificateFactory.CreateRsaSelfSigned("primary", T0 - TimeSpan.FromDays(30), T0 + TimeSpan.FromDays(365));
        using var secondary = TestCertificateFactory.CreateRsaSelfSigned("secondary", T0 + TimeSpan.FromDays(1), T0 + TimeSpan.FromDays(400));
        reader.AddCertificate(PrimaryThumbprint, primary);
        reader.AddCertificate(SecondaryThumbprint, secondary);

        var builder = new ZeeKayDaAuthBuilder(services);
        builder.AddWindowsCertificateStoreSigning(PrimaryThumbprint, StoreLocation.CurrentUser, StoreName.My,
            configure: options => options.AddCertificate(SecondaryThumbprint));

        await using var provider = services.BuildServiceProvider();
        var signingService = provider.GetRequiredService<IJwtSigningService>();

        var keys = await signingService.GetSigningKeysAsync(ct);

        keys.Should().HaveCount(2, "AC #4: both certificates must be exposed during the overlap window");
    }

    [Fact]
    public async Task Full_DI_wiring_single_certificate_is_active_immediately_despite_future_NotBefore()
    {
        Assert.SkipUnless(OperatingSystem.IsWindows(), RequiresWindowsReason);

        var ct = TestContext.Current.CancellationToken;
        var (services, reader, _) = BuildServices(T0);
        using var certificate = TestCertificateFactory.CreateRsaSelfSigned("test", T0 + TimeSpan.FromDays(30), T0 + TimeSpan.FromDays(365));
        reader.AddCertificate(PrimaryThumbprint, certificate);

        var builder = new ZeeKayDaAuthBuilder(services);
        builder.AddWindowsCertificateStoreSigning(PrimaryThumbprint, StoreLocation.CurrentUser, StoreName.My);

        await using var provider = services.BuildServiceProvider();
        var signingService = provider.GetRequiredService<IJwtSigningService>();

        var act = async () => await signingService.GetSigningKeysAsync(ct);

        await act.Should().NotThrowAsync("AC #6: the bootstrap exemption activates the sole certificate immediately");
    }

    [Fact]
    public async Task Full_DI_wiring_active_signer_switches_when_successors_NotBefore_arrives()
    {
        Assert.SkipUnless(OperatingSystem.IsWindows(), RequiresWindowsReason);

        var ct = TestContext.Current.CancellationToken;
        var refreshInterval = TimeSpan.FromMinutes(5);
        var (services, reader, timeProvider) = BuildServices(T0);
        using var predecessor = TestCertificateFactory.CreateRsaSelfSigned("predecessor", T0 - TimeSpan.FromDays(30), T0 + TimeSpan.FromDays(365));
        var successorNotBefore = T0 + TimeSpan.FromDays(1);
        using var successor = TestCertificateFactory.CreateRsaSelfSigned("successor", successorNotBefore, T0 + TimeSpan.FromDays(400));
        reader.AddCertificate(PrimaryThumbprint, predecessor);
        reader.AddCertificate(SecondaryThumbprint, successor);

        var builder = new ZeeKayDaAuthBuilder(services);
        builder.AddWindowsCertificateStoreSigning(PrimaryThumbprint, StoreLocation.CurrentUser, StoreName.My,
            configure: options =>
            {
                options.AddCertificate(SecondaryThumbprint);
                options.KeySourceRefreshInterval = refreshInterval;
            });

        await using var provider = services.BuildServiceProvider();
        var signingService = provider.GetRequiredService<IJwtSigningService>();

        var before = await signingService.GetSigningKeysAsync(ct);
        before[0].Kid.Should().Be(JwkThumbprint.Compute(predecessor.GetRSAPublicKey()!.ExportParameters(false)), "predecessor is active before successor's NotBefore arrives");

        timeProvider.SetUtcNow(successorNotBefore);
        var after = await signingService.GetSigningKeysAsync(ct);
        after[0].Kid.Should().Be(JwkThumbprint.Compute(successor.GetRSAPublicKey()!.ExportParameters(false)), "successor becomes active once its NotBefore arrives");
    }

    // ── Startup failure propagation ──────────────────────────────────────────────────────────────

    [Fact]
    public async Task Full_DI_wiring_surfaces_certificate_not_found_as_ZeeKayDaConfigurationException()
    {
        Assert.SkipUnless(OperatingSystem.IsWindows(), RequiresWindowsReason);

        var ct = TestContext.Current.CancellationToken;
        var (services, _, _) = BuildServices(T0); // No certificate registered -> certificate_not_found.

        var builder = new ZeeKayDaAuthBuilder(services);
        builder.AddWindowsCertificateStoreSigning(PrimaryThumbprint, StoreLocation.CurrentUser, StoreName.My);

        await using var provider = services.BuildServiceProvider();
        var signingService = provider.GetRequiredService<IJwtSigningService>();

        var act = async () => await signingService.GetSigningKeysAsync(ct);

        (await act.Should().ThrowAsync<ZeeKayDaConfigurationException>()).WithMessage("*certificate_not_found*");
    }

    [Fact]
    public async Task Full_DI_wiring_surfaces_private_key_not_found_as_ZeeKayDaConfigurationException()
    {
        Assert.SkipUnless(OperatingSystem.IsWindows(), RequiresWindowsReason);

        var ct = TestContext.Current.CancellationToken;
        var (services, reader, _) = BuildServices(T0);
        using var certificate = TestCertificateFactory.CreateRsaSelfSigned(
            "test", T0 - TimeSpan.FromDays(1), T0 + TimeSpan.FromDays(365), withPrivateKey: false);
        reader.AddCertificate(PrimaryThumbprint, certificate);

        var builder = new ZeeKayDaAuthBuilder(services);
        builder.AddWindowsCertificateStoreSigning(PrimaryThumbprint, StoreLocation.CurrentUser, StoreName.My);

        await using var provider = services.BuildServiceProvider();
        var signingService = provider.GetRequiredService<IJwtSigningService>();

        var act = async () => await signingService.GetSigningKeysAsync(ct);

        (await act.Should().ThrowAsync<ZeeKayDaConfigurationException>()).WithMessage("*private_key_not_found*");
    }

    [Fact]
    public async Task Full_DI_wiring_surfaces_store_inaccessible_as_ZeeKayDaConfigurationException()
    {
        Assert.SkipUnless(OperatingSystem.IsWindows(), RequiresWindowsReason);

        var ct = TestContext.Current.CancellationToken;
        var (services, reader, _) = BuildServices(T0);
        reader.ExceptionToThrow = new ZeeKayDaConfigurationException(new ZeeKayDaConfigurationFailure(
            "signing.windows_certificate_store.store_inaccessible", "Simulated store-access failure."));

        var builder = new ZeeKayDaAuthBuilder(services);
        builder.AddWindowsCertificateStoreSigning(PrimaryThumbprint, StoreLocation.CurrentUser, StoreName.My);

        await using var provider = services.BuildServiceProvider();
        var signingService = provider.GetRequiredService<IJwtSigningService>();

        var act = async () => await signingService.GetSigningKeysAsync(ct);

        (await act.Should().ThrowAsync<ZeeKayDaConfigurationException>()).WithMessage("*store_inaccessible*");
    }

    // ── Logging (AC #2, #7, expiry warning) ─────────────────────────────────────────────────────

    [Fact]
    public async Task Full_DI_wiring_logs_one_informational_line_per_registered_certificate_on_first_load()
    {
        Assert.SkipUnless(OperatingSystem.IsWindows(), RequiresWindowsReason);

        var ct = TestContext.Current.CancellationToken;
        var (services, reader, _) = BuildServices(T0);
        using var certificate = TestCertificateFactory.CreateRsaSelfSigned("test", T0 - TimeSpan.FromDays(1), T0 + TimeSpan.FromDays(365));
        reader.AddCertificate(PrimaryThumbprint, certificate);
        var logger = new CapturingSanitizingLogger<WindowsCertificateStoreSigningJwtSigningService>();
        services.AddSingleton<ISanitizingLogger<WindowsCertificateStoreSigningJwtSigningService>>(logger);

        var builder = new ZeeKayDaAuthBuilder(services);
        builder.AddWindowsCertificateStoreSigning(PrimaryThumbprint, StoreLocation.CurrentUser, StoreName.My);

        await using var provider = services.BuildServiceProvider();
        var signingService = provider.GetRequiredService<IJwtSigningService>();

        await signingService.GetSigningKeysAsync(ct);

        logger.Entries.Count(e => e.Level == LogLevel.Information).Should().Be(1,
            "AC #2: one informational line for the one registered certificate");
    }

    [Fact]
    public async Task Full_DI_wiring_does_not_log_again_when_an_unchanged_cycle_skips_the_reload()
    {
        Assert.SkipUnless(OperatingSystem.IsWindows(), RequiresWindowsReason);

        // HasKeySetChangedAsync reports "no change" here (nothing has rotated), so LoadKeysAsync —
        // and the LogCertificateStatuses call inside it — must not run a second time (issue #348).
        var ct = TestContext.Current.CancellationToken;
        var refreshInterval = TimeSpan.FromMinutes(5);
        var (services, reader, timeProvider) = BuildServices(T0);
        using var certificate = TestCertificateFactory.CreateRsaSelfSigned("test", T0 - TimeSpan.FromDays(1), T0 + TimeSpan.FromDays(365));
        reader.AddCertificate(PrimaryThumbprint, certificate);
        var logger = new CapturingSanitizingLogger<WindowsCertificateStoreSigningJwtSigningService>();
        services.AddSingleton<ISanitizingLogger<WindowsCertificateStoreSigningJwtSigningService>>(logger);

        var builder = new ZeeKayDaAuthBuilder(services);
        builder.AddWindowsCertificateStoreSigning(PrimaryThumbprint, StoreLocation.CurrentUser, StoreName.My,
            configure: options => options.KeySourceRefreshInterval = refreshInterval);

        await using var provider = services.BuildServiceProvider();
        var signingService = provider.GetRequiredService<IJwtSigningService>();
        await signingService.GetSigningKeysAsync(ct); // Bootstrap load.

        timeProvider.SetUtcNow(T0 + refreshInterval); // Cache expires -> triggers the "ask" step.
        await signingService.GetSigningKeysAsync(ct);

        logger.Entries.Count(e => e.Level == LogLevel.Information).Should().Be(1,
            "with only one registered certificate and no elapsed-time boundary crossed, nothing has " +
            "changed, so the per-certificate status line must not repeat");
    }

    [Fact]
    public async Task Full_DI_wiring_per_certificate_log_reflects_active_included_and_excluded_status_as_rotation_progresses()
    {
        Assert.SkipUnless(OperatingSystem.IsWindows(), RequiresWindowsReason);

        var ct = TestContext.Current.CancellationToken;
        var refreshInterval = TimeSpan.FromMinutes(5);
        var retirementWindow = TimeSpan.FromHours(1);
        var (services, reader, timeProvider) = BuildServices(T0, retirementWindow);
        using var predecessor = TestCertificateFactory.CreateRsaSelfSigned("predecessor", T0 - TimeSpan.FromDays(30), T0 + TimeSpan.FromDays(365));
        var successorNotBefore = T0 + TimeSpan.FromDays(1);
        using var successor = TestCertificateFactory.CreateRsaSelfSigned("successor", successorNotBefore, T0 + TimeSpan.FromDays(400));
        reader.AddCertificate(PrimaryThumbprint, predecessor);
        reader.AddCertificate(SecondaryThumbprint, successor);
        var logger = new CapturingSanitizingLogger<WindowsCertificateStoreSigningJwtSigningService>();
        services.AddSingleton<ISanitizingLogger<WindowsCertificateStoreSigningJwtSigningService>>(logger);

        var builder = new ZeeKayDaAuthBuilder(services);
        builder.AddWindowsCertificateStoreSigning(PrimaryThumbprint, StoreLocation.CurrentUser, StoreName.My,
            configure: options =>
            {
                options.AddCertificate(SecondaryThumbprint);
                options.KeySourceRefreshInterval = refreshInterval;
            });

        await using var provider = services.BuildServiceProvider();
        var signingService = provider.GetRequiredService<IJwtSigningService>();

        // Before the successor's NotBefore: predecessor is active, successor is pending.
        await signingService.GetSigningKeysAsync(ct);
        logger.Entries.Should().Contain(e => e.Message.Contains(PrimaryThumbprint) && e.Message.Contains("the active signer"));
        logger.Entries.Should().Contain(e => e.Message.Contains(SecondaryThumbprint) && e.Message.Contains("not yet active"));
        logger.Entries.Clear();

        // After the successor activates but within the predecessor's retirement window.
        timeProvider.SetUtcNow(successorNotBefore);
        await signingService.GetSigningKeysAsync(ct);
        logger.Entries.Should().Contain(e => e.Message.Contains(SecondaryThumbprint) && e.Message.Contains("the active signer"));
        logger.Entries.Should().Contain(e => e.Message.Contains(PrimaryThumbprint) && e.Message.Contains("retirement window"));
        logger.Entries.Clear();

        // After the predecessor's retirement window has fully elapsed - no longer trusted at all.
        timeProvider.SetUtcNow(successorNotBefore + retirementWindow + TimeSpan.FromMinutes(1));
        await signingService.GetSigningKeysAsync(ct);
        logger.Entries.Should().Contain(e => e.Message.Contains(PrimaryThumbprint) && e.Message.Contains("NOT included"),
            "once a registered certificate's retirement window has fully elapsed, the log should say so plainly so an operator knows it can be removed from configuration");
    }

    [Fact]
    public async Task Full_DI_wiring_logs_startup_warning_when_soonest_pending_NotBefore_is_closer_than_KeySourceRefreshInterval()
    {
        Assert.SkipUnless(OperatingSystem.IsWindows(), RequiresWindowsReason);

        var ct = TestContext.Current.CancellationToken;
        var refreshInterval = TimeSpan.FromMinutes(5);
        var (services, reader, _) = BuildServices(T0);
        using var primary = TestCertificateFactory.CreateRsaSelfSigned("primary", T0 - TimeSpan.FromDays(30), T0 + TimeSpan.FromDays(365));
        using var secondary = TestCertificateFactory.CreateRsaSelfSigned("secondary", T0 + TimeSpan.FromMinutes(1), T0 + TimeSpan.FromDays(400));
        reader.AddCertificate(PrimaryThumbprint, primary);
        reader.AddCertificate(SecondaryThumbprint, secondary);
        var logger = new CapturingSanitizingLogger<WindowsCertificateStoreSigningJwtSigningService>();
        services.AddSingleton<ISanitizingLogger<WindowsCertificateStoreSigningJwtSigningService>>(logger);

        var builder = new ZeeKayDaAuthBuilder(services);
        builder.AddWindowsCertificateStoreSigning(PrimaryThumbprint, StoreLocation.CurrentUser, StoreName.My,
            configure: options =>
            {
                options.AddCertificate(SecondaryThumbprint);
                options.KeySourceRefreshInterval = refreshInterval;
            });

        await using var provider = services.BuildServiceProvider();
        var signingService = provider.GetRequiredService<IJwtSigningService>();
        await signingService.GetSigningKeysAsync(ct);

        logger.Entries.Should().Contain(e => e.Level == LogLevel.Warning, "AC #7: the too-soon-NotBefore misconfiguration must be surfaced");
    }

    [Fact]
    public async Task Full_DI_wiring_logs_warning_when_active_certificate_expires_within_30_days()
    {
        Assert.SkipUnless(OperatingSystem.IsWindows(), RequiresWindowsReason);

        var ct = TestContext.Current.CancellationToken;
        var (services, reader, _) = BuildServices(T0);
        using var certificate = TestCertificateFactory.CreateRsaSelfSigned("test", T0 - TimeSpan.FromDays(300), T0 + TimeSpan.FromDays(10));
        reader.AddCertificate(PrimaryThumbprint, certificate);
        var logger = new CapturingSanitizingLogger<WindowsCertificateStoreSigningJwtSigningService>();
        services.AddSingleton<ISanitizingLogger<WindowsCertificateStoreSigningJwtSigningService>>(logger);

        var builder = new ZeeKayDaAuthBuilder(services);
        builder.AddWindowsCertificateStoreSigning(PrimaryThumbprint, StoreLocation.CurrentUser, StoreName.My);

        await using var provider = services.BuildServiceProvider();
        var signingService = provider.GetRequiredService<IJwtSigningService>();
        await signingService.GetSigningKeysAsync(ct);

        logger.Entries.Should().Contain(e => e.Level == LogLevel.Warning && e.Message.Contains("expires"),
            "the active certificate expiring within 30 days must be surfaced");
    }

    // ── Startup service ───────────────────────────────────────────────────────────────────────────

    [Fact]
    public async Task StartupService_StartAsync_forces_key_loading_and_propagates_configuration_failure()
    {
        Assert.SkipUnless(OperatingSystem.IsWindows(), RequiresWindowsReason);

        var ct = TestContext.Current.CancellationToken;
        var (services, _, _) = BuildServices(T0); // No certificate registered.

        var builder = new ZeeKayDaAuthBuilder(services);
        builder.AddWindowsCertificateStoreSigning(PrimaryThumbprint, StoreLocation.CurrentUser, StoreName.My);

        await using var provider = services.BuildServiceProvider();
        var startupService = provider.GetServices<IHostedService>().OfType<WindowsCertificateStoreSigningStartupService>().Single();

        var act = async () => await startupService.StartAsync(ct);

        (await act.Should().ThrowAsync<ZeeKayDaConfigurationException>()).WithMessage("*certificate_not_found*");
    }

    [Fact]
    public async Task StartupService_StartAsync_succeeds_when_certificate_loads_without_error()
    {
        Assert.SkipUnless(OperatingSystem.IsWindows(), RequiresWindowsReason);

        var ct = TestContext.Current.CancellationToken;
        var (services, reader, _) = BuildServices(T0);
        using var certificate = TestCertificateFactory.CreateRsaSelfSigned("test", T0 - TimeSpan.FromDays(1), T0 + TimeSpan.FromDays(365));
        reader.AddCertificate(PrimaryThumbprint, certificate);

        var builder = new ZeeKayDaAuthBuilder(services);
        builder.AddWindowsCertificateStoreSigning(PrimaryThumbprint, StoreLocation.CurrentUser, StoreName.My);

        await using var provider = services.BuildServiceProvider();
        var startupService = provider.GetServices<IHostedService>().OfType<WindowsCertificateStoreSigningStartupService>().Single();

        var act = async () => await startupService.StartAsync(ct);

        await act.Should().NotThrowAsync();
    }
}
