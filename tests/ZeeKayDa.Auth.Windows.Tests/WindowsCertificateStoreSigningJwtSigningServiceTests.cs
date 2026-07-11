using System.Security.Cryptography.X509Certificates;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Microsoft.Extensions.Time.Testing;
using ZeeKayDa.Auth.Logging;
using ZeeKayDa.Auth.Windows.Tests.Fakes;
using ZeeKayDa.Auth.Windows.Tests.Fixtures;

namespace ZeeKayDa.Auth.Windows.Tests;

/// <summary>
/// Direct-construction tests for <see cref="WindowsCertificateStoreSigningJwtSigningService"/>,
/// bypassing DI and the platform-gated <c>AddWindowsCertificateStoreSigning</c> extension method
/// entirely. The service class itself has no Windows-specific code (it depends only on
/// <see cref="ICertificateStoreReader"/>), so — mirroring
/// <c>AzureKeyVaultCachedSigningJwtSigningServiceTests</c>'s pattern for its sibling provider —
/// these tests run on any OS, unlike <c>Integration/WindowsCertificateStoreSigningIntegrationTests</c>,
/// which goes through the real, Windows-only extension method.
/// </summary>
public sealed class WindowsCertificateStoreSigningJwtSigningServiceTests
{
    private static readonly DateTimeOffset T0 = DateTimeOffset.Parse("2026-01-01T00:00:00Z");
    private const string PrimaryThumbprint = "AABBCCDDEEFF00112233445566778899AABBCCD";
    private const string SecondaryThumbprint = "1111111111111111111111111111111111111A";

    private static WindowsCertificateStoreSigningJwtSigningService BuildService(
        FakeCertificateStoreReader reader,
        FakeTimeProvider timeProvider,
        string primaryThumbprint,
        IReadOnlyList<string>? additionalThumbprints = null,
        TimeSpan? refreshInterval = null,
        TimeSpan? retirementWindow = null,
        ISanitizingLogger<WindowsCertificateStoreSigningJwtSigningService>? logger = null)
    {
        var settingsOptions = new WindowsCertificateStoreSigningOptions
        {
            Thumbprint = primaryThumbprint,
            StoreLocation = StoreLocation.CurrentUser,
            StoreName = StoreName.My,
            KeySourceRefreshInterval = refreshInterval ?? TimeSpan.FromMinutes(5),
        };
        foreach (var additional in additionalThumbprints ?? [])
            settingsOptions.AddCertificate(additional);

        return new WindowsCertificateStoreSigningJwtSigningService(
            Options.Create(settingsOptions),
            timeProvider,
            reader,
            new FakeRetirementWindowProvider(retirementWindow ?? TimeSpan.FromHours(1)),
            logger ?? NullSanitizingLogger<WindowsCertificateStoreSigningJwtSigningService>.Instance);
    }

    [Fact]
    public async Task GetSigningKeysAsync_logs_one_informational_line_per_registered_certificate_on_every_load()
    {
        var ct = TestContext.Current.CancellationToken;
        var refreshInterval = TimeSpan.FromMinutes(5);
        var reader = new FakeCertificateStoreReader();
        using var certificate = TestCertificateFactory.CreateRsaSelfSigned("test", T0 - TimeSpan.FromDays(1), T0 + TimeSpan.FromDays(365));
        reader.AddCertificate(PrimaryThumbprint, certificate);
        var timeProvider = new FakeTimeProvider(T0);
        var logger = new CapturingSanitizingLogger<WindowsCertificateStoreSigningJwtSigningService>();

        await using var sut = BuildService(reader, timeProvider, PrimaryThumbprint, refreshInterval: refreshInterval, logger: logger);

        await sut.GetSigningKeysAsync(ct);
        logger.Entries.Count(e => e.Level == LogLevel.Information).Should().Be(1,
            "AC #2: one informational line for the one registered certificate");

        timeProvider.SetUtcNow(T0 + refreshInterval); // Force a reload.
        await sut.GetSigningKeysAsync(ct);

        logger.Entries.Count(e => e.Level == LogLevel.Information).Should().Be(2,
            "the per-certificate status line must repeat on every load, since active/included status can change over time");
    }

    [Fact]
    public async Task GetSigningKeysAsync_per_certificate_log_reflects_active_included_and_excluded_status_as_rotation_progresses()
    {
        var ct = TestContext.Current.CancellationToken;
        var refreshInterval = TimeSpan.FromMinutes(5);
        var retirementWindow = TimeSpan.FromHours(1);
        var reader = new FakeCertificateStoreReader();
        using var predecessor = TestCertificateFactory.CreateRsaSelfSigned("predecessor", T0 - TimeSpan.FromDays(30), T0 + TimeSpan.FromDays(365));
        var successorNotBefore = T0 + TimeSpan.FromDays(1);
        using var successor = TestCertificateFactory.CreateRsaSelfSigned("successor", successorNotBefore, T0 + TimeSpan.FromDays(400));
        reader.AddCertificate(PrimaryThumbprint, predecessor);
        reader.AddCertificate(SecondaryThumbprint, successor);
        var timeProvider = new FakeTimeProvider(T0);
        var logger = new CapturingSanitizingLogger<WindowsCertificateStoreSigningJwtSigningService>();

        await using var sut = BuildService(
            reader, timeProvider, PrimaryThumbprint, [SecondaryThumbprint],
            refreshInterval: refreshInterval, retirementWindow: retirementWindow, logger: logger);

        // Before the successor's NotBefore: predecessor is active, successor is pending.
        await sut.GetSigningKeysAsync(ct);
        logger.Entries.Should().Contain(e => e.Message.Contains(PrimaryThumbprint) && e.Message.Contains("the active signer"));
        logger.Entries.Should().Contain(e => e.Message.Contains(SecondaryThumbprint) && e.Message.Contains("not yet active"));
        logger.Entries.Clear();

        // After the successor activates but within the predecessor's retirement window.
        timeProvider.SetUtcNow(successorNotBefore);
        await sut.GetSigningKeysAsync(ct);
        logger.Entries.Should().Contain(e => e.Message.Contains(SecondaryThumbprint) && e.Message.Contains("the active signer"));
        logger.Entries.Should().Contain(e => e.Message.Contains(PrimaryThumbprint) && e.Message.Contains("retirement window"));
        logger.Entries.Clear();

        // After the predecessor's retirement window has fully elapsed - no longer trusted at all.
        timeProvider.SetUtcNow(successorNotBefore + retirementWindow + TimeSpan.FromMinutes(1));
        await sut.GetSigningKeysAsync(ct);
        logger.Entries.Should().Contain(e => e.Message.Contains(PrimaryThumbprint) && e.Message.Contains("NOT included"),
            "once a registered certificate's retirement window has fully elapsed, the log should say so plainly so an operator knows it can be removed from configuration");
    }
}
