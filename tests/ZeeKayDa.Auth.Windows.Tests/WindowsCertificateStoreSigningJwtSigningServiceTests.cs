using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Microsoft.Extensions.Time.Testing;
using ZeeKayDa.Auth.Logging;
using ZeeKayDa.Auth.Tokens;
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
        TimeSpan? assumedJwksPropagationDelay = null,
        ISanitizingLogger<WindowsCertificateStoreSigningJwtSigningService>? logger = null)
    {
        var settingsOptions = new WindowsCertificateStoreSigningOptions
        {
            Thumbprint = primaryThumbprint,
            StoreLocation = StoreLocation.CurrentUser,
            StoreName = StoreName.My,
            KeyRotationCheckInterval = refreshInterval ?? TimeSpan.FromMinutes(5),
            AssumedJwksPropagationDelay = assumedJwksPropagationDelay,
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
    public async Task GetSigningKeysAsync_logs_one_informational_line_per_registered_certificate_on_first_load()
    {
        var ct = TestContext.Current.CancellationToken;
        var reader = new FakeCertificateStoreReader();
        using var certificate = TestCertificateFactory.CreateRsaSelfSigned("test", T0 - TimeSpan.FromDays(1), T0 + TimeSpan.FromDays(365));
        reader.AddCertificate(PrimaryThumbprint, certificate);
        var timeProvider = new FakeTimeProvider(T0);
        var logger = new CapturingSanitizingLogger<WindowsCertificateStoreSigningJwtSigningService>();

        await using var sut = BuildService(reader, timeProvider, PrimaryThumbprint, logger: logger);

        await sut.GetSigningKeysAsync(ct);

        logger.Entries.Count(e => e.Level == LogLevel.Information).Should().Be(1,
            "AC #2: one informational line for the one registered certificate");
    }

    [Fact]
    public async Task GetSigningKeysAsync_does_not_log_again_when_an_unchanged_cycle_skips_the_reload()
    {
        // HasKeySetChangedAsync reports "no change" here (nothing has rotated), so LoadKeysAsync —
        // and the LogCertificateStatuses call inside it — must not run a second time.
        var ct = TestContext.Current.CancellationToken;
        var refreshInterval = TimeSpan.FromMinutes(5);
        var reader = new FakeCertificateStoreReader();
        using var certificate = TestCertificateFactory.CreateRsaSelfSigned("test", T0 - TimeSpan.FromDays(1), T0 + TimeSpan.FromDays(365));
        reader.AddCertificate(PrimaryThumbprint, certificate);
        var timeProvider = new FakeTimeProvider(T0);
        var logger = new CapturingSanitizingLogger<WindowsCertificateStoreSigningJwtSigningService>();

        await using var sut = BuildService(reader, timeProvider, PrimaryThumbprint, refreshInterval: refreshInterval, logger: logger);
        await sut.GetSigningKeysAsync(ct); // Bootstrap load.

        timeProvider.SetUtcNow(T0 + refreshInterval); // Cache expires -> triggers the "ask" step.
        await sut.GetSigningKeysAsync(ct);

        logger.Entries.Count(e => e.Level == LogLevel.Information).Should().Be(1,
            "with only one registered certificate and no elapsed-time boundary crossed, nothing has " +
            "changed, so the per-certificate status line must not repeat");
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

    // ── AssumedJwksPropagationDelay (issue #413) ─────────────────────────────────────────────────

    [Fact]
    public async Task GetSigningKeysAsync_does_not_warn_when_an_explicit_shorter_AssumedJwksPropagationDelay_is_satisfied()
    {
        // The gap between predecessor's activation and successor's NotBefore is 1 minute — shorter
        // than the 5-minute KeyRotationCheckInterval default, which would trigger the too-soon
        // warning if AssumedJwksPropagationDelay were left unset. An explicit, shorter
        // AssumedJwksPropagationDelay (30 seconds) that the 1-minute gap satisfies proves the
        // explicit value is what actually feeds HasTooSoonPendingActivation.
        var ct = TestContext.Current.CancellationToken;
        var refreshInterval = TimeSpan.FromMinutes(5);
        var reader = new FakeCertificateStoreReader();
        using var predecessor = TestCertificateFactory.CreateRsaSelfSigned("predecessor", T0 - TimeSpan.FromDays(30), T0 + TimeSpan.FromDays(365));
        using var successor = TestCertificateFactory.CreateRsaSelfSigned("successor", T0 + TimeSpan.FromMinutes(1), T0 + TimeSpan.FromDays(400));
        reader.AddCertificate(PrimaryThumbprint, predecessor);
        reader.AddCertificate(SecondaryThumbprint, successor);
        var timeProvider = new FakeTimeProvider(T0);
        var logger = new CapturingSanitizingLogger<WindowsCertificateStoreSigningJwtSigningService>();

        await using var sut = BuildService(
            reader, timeProvider, PrimaryThumbprint, [SecondaryThumbprint],
            refreshInterval: refreshInterval, assumedJwksPropagationDelay: TimeSpan.FromSeconds(30), logger: logger);

        await sut.GetSigningKeysAsync(ct);

        logger.Entries.Should().NotContain(e => e.Level == LogLevel.Warning,
            "the explicit AssumedJwksPropagationDelay (30s) is shorter than the 1-minute activation gap, " +
            "so no warning should fire even though the 5-minute KeyRotationCheckInterval default would have");
    }

    [Fact]
    public async Task GetSigningKeysAsync_warns_when_an_explicit_longer_AssumedJwksPropagationDelay_is_not_satisfied()
    {
        // The gap between predecessor's activation and successor's NotBefore is 10 minutes — longer
        // than the 5-minute KeyRotationCheckInterval default, so the too-soon warning would NOT fire
        // if AssumedJwksPropagationDelay were left unset. An explicit, longer
        // AssumedJwksPropagationDelay (15 minutes) that the 10-minute gap violates proves the
        // explicit value — not the KeyRotationCheckInterval default — is what feeds
        // HasTooSoonPendingActivation.
        var ct = TestContext.Current.CancellationToken;
        var refreshInterval = TimeSpan.FromMinutes(5);
        var reader = new FakeCertificateStoreReader();
        using var predecessor = TestCertificateFactory.CreateRsaSelfSigned("predecessor", T0 - TimeSpan.FromDays(30), T0 + TimeSpan.FromDays(365));
        using var successor = TestCertificateFactory.CreateRsaSelfSigned("successor", T0 + TimeSpan.FromMinutes(10), T0 + TimeSpan.FromDays(400));
        reader.AddCertificate(PrimaryThumbprint, predecessor);
        reader.AddCertificate(SecondaryThumbprint, successor);
        var timeProvider = new FakeTimeProvider(T0);
        var logger = new CapturingSanitizingLogger<WindowsCertificateStoreSigningJwtSigningService>();

        await using var sut = BuildService(
            reader, timeProvider, PrimaryThumbprint, [SecondaryThumbprint],
            refreshInterval: refreshInterval, assumedJwksPropagationDelay: TimeSpan.FromMinutes(15), logger: logger);

        await sut.GetSigningKeysAsync(ct);

        logger.Entries.Should().Contain(e => e.Level == LogLevel.Warning,
            "the explicit AssumedJwksPropagationDelay (15 minutes) is longer than the 10-minute " +
            "activation gap, so the warning must fire even though the 5-minute KeyRotationCheckInterval " +
            "default would not have triggered it");
    }

    // ── HasKeySetChangedAsync: elapsed-time-only change detection, zero store access ────────────────

    [Fact]
    public async Task GetSigningKeysAsync_does_not_reopen_any_certificate_store_handle_when_unchanged_between_polls()
    {
        var ct = TestContext.Current.CancellationToken;
        var refreshInterval = TimeSpan.FromMinutes(5);
        var reader = new FakeCertificateStoreReader();
        using var certificate = TestCertificateFactory.CreateRsaSelfSigned("test", T0 - TimeSpan.FromDays(1), T0 + TimeSpan.FromDays(365));
        reader.AddCertificate(PrimaryThumbprint, certificate);
        var timeProvider = new FakeTimeProvider(T0);

        await using var sut = BuildService(reader, timeProvider, PrimaryThumbprint, refreshInterval: refreshInterval);
        await sut.GetSigningKeysAsync(ct); // Bootstrap load.
        reader.Calls.Clear();

        timeProvider.SetUtcNow(T0 + refreshInterval); // Cache expires -> triggers the "ask" step.
        var keys = await sut.GetSigningKeysAsync(ct);

        keys.Should().HaveCount(1);
        reader.Calls.Should().BeEmpty(
            "nothing has rotated, so HasKeySetChangedAsync must report no change without ever calling " +
            "ICertificateStoreReader.GetCertificate, and LoadKeysAsync must not run");
    }

    [Fact]
    public async Task SignAsync_still_succeeds_after_an_unchanged_poll_skips_the_reload()
    {
        var ct = TestContext.Current.CancellationToken;
        var refreshInterval = TimeSpan.FromMinutes(5);
        var reader = new FakeCertificateStoreReader();
        using var certificate = TestCertificateFactory.CreateRsaSelfSigned("test", T0 - TimeSpan.FromDays(1), T0 + TimeSpan.FromDays(365));
        reader.AddCertificate(PrimaryThumbprint, certificate);
        var timeProvider = new FakeTimeProvider(T0);

        await using var sut = BuildService(reader, timeProvider, PrimaryThumbprint, refreshInterval: refreshInterval);
        await sut.GetSigningKeysAsync(ct); // Bootstrap load.

        timeProvider.SetUtcNow(T0 + refreshInterval); // Unchanged poll -> ask reports "no change".
        var payload = "payload"u8.ToArray();

        var act = async () => await sut.SignAsync(payload, ct);

        await act.Should().NotThrowAsync(
            "the cached SigningKeySet must remain usable (not disposed) when the ask reports no change");
    }

    [Fact]
    public async Task HasKeySetChangedAsync_triggers_rebuild_when_elapsed_time_alone_moves_a_certificate_out_of_its_retirement_window()
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

        await using var sut = BuildService(
            reader, timeProvider, PrimaryThumbprint, [SecondaryThumbprint],
            refreshInterval: refreshInterval, retirementWindow: retirementWindow);
        await sut.GetSigningKeysAsync(ct); // Bootstrap: predecessor active, successor pending.

        timeProvider.SetUtcNow(successorNotBefore); // Successor activates; predecessor retires but stays in-window.
        await sut.GetSigningKeysAsync(ct); // Both still included.
        reader.Calls.Clear();

        // No store-side change at all - just elapsed time pushing the predecessor past its retirement window.
        timeProvider.SetUtcNow(successorNotBefore + retirementWindow + TimeSpan.FromMinutes(1));
        var keys = await sut.GetSigningKeysAsync(ct);

        keys.Should().ContainSingle("the predecessor's retirement window has now fully elapsed");
        reader.Calls.Should().NotBeEmpty(
            "a certificate leaving its retirement window purely from elapsed time must still trigger a " +
            "rebuild, even with no store-side change");
    }

    [Fact]
    public async Task HasKeySetChangedAsync_triggers_rebuild_when_the_active_certificate_changes_with_membership_unchanged()
    {
        // Regression test for the lesson from #350/#351's review: the comparison MUST include
        // which entry is active, not just thumbprint membership. A rotation between two
        // overlapping certificates typically spans two polls: at poll N, the successor is
        // published but not yet active - the included set becomes {predecessor active, successor
        // not-active}, a membership change from the single-certificate bootstrap state, so this
        // poll is correctly reported as a change regardless of whether IsActive is compared. The
        // poll under test here is the *next* one (N+1): no configuration change at all happens
        // between the two polls - same two thumbprints, both still registered - but the successor
        // has now crossed into its activation window and becomes the active signer while the
        // predecessor (still within its retirement window) remains included. Comparing only
        // thumbprint membership would see the same {predecessor, successor} set on both polls and
        // report "no change," silently skipping the reload that promotes the successor and leaving
        // the service signing with the predecessor past the intended handoff.
        var ct = TestContext.Current.CancellationToken;
        var refreshInterval = TimeSpan.FromMinutes(5);
        var retirementWindow = TimeSpan.FromHours(1);
        var reader = new FakeCertificateStoreReader();
        using var predecessor = TestCertificateFactory.CreateRsaSelfSigned("predecessor", T0 - TimeSpan.FromDays(30), T0 + TimeSpan.FromDays(365));
        var successorNotBefore = T0 + TimeSpan.FromMinutes(1);
        using var successor = TestCertificateFactory.CreateRsaSelfSigned("successor", successorNotBefore, T0 + TimeSpan.FromDays(400));
        reader.AddCertificate(PrimaryThumbprint, predecessor);
        reader.AddCertificate(SecondaryThumbprint, successor);
        var timeProvider = new FakeTimeProvider(T0);

        await using var sut = BuildService(
            reader, timeProvider, PrimaryThumbprint, [SecondaryThumbprint],
            refreshInterval: refreshInterval, retirementWindow: retirementWindow);
        await sut.GetSigningKeysAsync(ct); // Bootstrap: predecessor active.

        timeProvider.SetUtcNow(successorNotBefore); // Poll N: successor published but not yet active (membership change).
        await sut.GetSigningKeysAsync(ct); // predecessor active + successor not-active; both now "previously included".
        reader.Calls.Clear();

        // Poll N+1: one KeyRotationCheckInterval later, with no configuration change whatsoever -
        // the successor now activates and the predecessor (still within its retirement window)
        // stays included. Same thumbprints as poll N; only which entry is active differs.
        timeProvider.SetUtcNow(successorNotBefore + refreshInterval);
        var keys = await sut.GetSigningKeysAsync(ct);

        keys.Should().HaveCount(2, "the predecessor is still within its retirement window and the successor is now active");
        using var successorPublicKey = successor.GetRSAPublicKey()!;
        keys[0].Kid.Should().Be(JwkThumbprint.Compute(successorPublicKey.ExportParameters(false)),
            "the handoff must actually happen: the successor must become the active (index 0) signing key at this poll");
        reader.Calls.Should().NotBeEmpty(
            "the active-slot handoff alone must be enough to trigger a real reload, even with thumbprint " +
            "membership unchanged since the previous poll");
    }

    [Fact]
    public async Task HasKeySetChangedAsync_reports_a_change_when_every_registered_certificate_has_expired_since_the_last_load()
    {
        // HasKeySetChangedAsync must never itself decide "configuration is now invalid" - it only
        // ever reports "did the trusted set change," and defers the actual fail-closed behaviour
        // to the subsequent LoadKeysAsync call.
        var ct = TestContext.Current.CancellationToken;
        var refreshInterval = TimeSpan.FromMinutes(5);
        var reader = new FakeCertificateStoreReader();
        using var certificate = TestCertificateFactory.CreateRsaSelfSigned("test", T0 - TimeSpan.FromDays(2), T0 + TimeSpan.FromDays(1));
        reader.AddCertificate(PrimaryThumbprint, certificate);
        var timeProvider = new FakeTimeProvider(T0);

        await using var sut = BuildService(reader, timeProvider, PrimaryThumbprint, refreshInterval: refreshInterval);
        await sut.GetSigningKeysAsync(ct); // Bootstrap load.

        timeProvider.SetUtcNow(T0 + TimeSpan.FromDays(2)); // Past the only certificate's NotAfter.
        var act = async () => await sut.GetSigningKeysAsync(ct);

        await act.Should().ThrowAsync<ZeeKayDaConfigurationException>()
            .WithMessage("*no_active_certificate*",
                "the ask must report a change (never silently keep serving the expired certificate), " +
                "and the real LoadKeysAsync reload is what actually fails closed");
    }

    // ── Near-expiry warning: relocated into HasKeySetChangedAsync's ask (issue #348 follow-up) ─────

    [Fact]
    public async Task GetSigningKeysAsync_warns_when_the_active_certificate_is_within_30_days_of_expiry_on_cold_start()
    {
        var ct = TestContext.Current.CancellationToken;
        var reader = new FakeCertificateStoreReader();
        using var certificate = TestCertificateFactory.CreateRsaSelfSigned("test", T0 - TimeSpan.FromDays(1), T0 + TimeSpan.FromDays(10));
        reader.AddCertificate(PrimaryThumbprint, certificate);
        var timeProvider = new FakeTimeProvider(T0);
        var logger = new CapturingSanitizingLogger<WindowsCertificateStoreSigningJwtSigningService>();

        await using var sut = BuildService(reader, timeProvider, PrimaryThumbprint, logger: logger);

        await sut.GetSigningKeysAsync(ct); // Cold start: no ask has ever run yet.

        logger.Entries.Should().ContainSingle(e =>
                e.Level == LogLevel.Warning && e.Message.Contains(PrimaryThumbprint) && e.Message.Contains("within 30 days"),
            "the cold-start LoadKeysAsync call must still perform the expiry check, since no ask has ever run to cover it");
    }

    [Fact]
    public async Task GetSigningKeysAsync_warns_again_on_a_later_unchanged_cycle_once_the_expiry_threshold_is_crossed()
    {
        // Regression test for the follow-up finding on issue #348: an unchanged refresh cycle now
        // skips LoadKeysAsync entirely, so the warning must be re-evaluated inside
        // HasKeySetChangedAsync itself, or a long-running process could cross into the 30-day
        // expiry window with zero signal until signing actually starts failing.
        var ct = TestContext.Current.CancellationToken;
        var refreshInterval = TimeSpan.FromMinutes(5);
        var reader = new FakeCertificateStoreReader();
        using var certificate = TestCertificateFactory.CreateRsaSelfSigned("test", T0 - TimeSpan.FromDays(1), T0 + TimeSpan.FromDays(40));
        reader.AddCertificate(PrimaryThumbprint, certificate);
        var timeProvider = new FakeTimeProvider(T0);
        var logger = new CapturingSanitizingLogger<WindowsCertificateStoreSigningJwtSigningService>();

        await using var sut = BuildService(reader, timeProvider, PrimaryThumbprint, refreshInterval: refreshInterval, logger: logger);
        await sut.GetSigningKeysAsync(ct); // Bootstrap load: 40 days to expiry, no warning yet.

        logger.Entries.Should().NotContain(e => e.Level == LogLevel.Warning && e.Message.Contains("within 30 days"));

        timeProvider.SetUtcNow(T0 + TimeSpan.FromDays(25)); // 15 days from expiry now; also past refreshInterval -> triggers the ask.
        reader.Calls.Clear();
        await sut.GetSigningKeysAsync(ct);

        logger.Entries.Should().ContainSingle(e =>
                e.Level == LogLevel.Warning && e.Message.Contains(PrimaryThumbprint) && e.Message.Contains("within 30 days"),
            "the ask itself must re-evaluate the expiry check on every cycle, even one that reports no change and skips LoadKeysAsync entirely");
        reader.Calls.Should().BeEmpty(
            "the relocated expiry check must not reintroduce store access - it only needs the cached active entry's ExpiresAt");
    }

    [Fact]
    public async Task GetSigningKeysAsync_does_not_double_log_the_expiry_warning_on_a_cycle_where_a_reload_also_happens()
    {
        // The ask fires the expiry warning on every cycle, including ones that go on to report a
        // change and trigger LoadKeysAsync. LoadKeysAsync must not also fire it for that same cycle.
        var ct = TestContext.Current.CancellationToken;
        var refreshInterval = TimeSpan.FromMinutes(5);
        var reader = new FakeCertificateStoreReader();
        using var predecessor = TestCertificateFactory.CreateRsaSelfSigned("predecessor", T0 - TimeSpan.FromDays(30), T0 + TimeSpan.FromDays(40));
        var successorNotBefore = T0 + TimeSpan.FromMinutes(1);
        using var successor = TestCertificateFactory.CreateRsaSelfSigned("successor", successorNotBefore, T0 + TimeSpan.FromDays(20));
        reader.AddCertificate(PrimaryThumbprint, predecessor);
        reader.AddCertificate(SecondaryThumbprint, successor);
        var timeProvider = new FakeTimeProvider(T0);
        var logger = new CapturingSanitizingLogger<WindowsCertificateStoreSigningJwtSigningService>();

        await using var sut = BuildService(
            reader, timeProvider, PrimaryThumbprint, [SecondaryThumbprint],
            refreshInterval: refreshInterval, logger: logger);
        await sut.GetSigningKeysAsync(ct); // Bootstrap: predecessor active (40 days to expiry - no warning).
        logger.Entries.Clear();

        // One refreshInterval later, the cache expires and the ask runs. The successor already
        // crossed its own activation window (at successorNotBefore, well before this poll) and is
        // now the active signer - membership unchanged (predecessor still within its retirement
        // window) but the active slot flips, which alone is enough to trigger a real reload. The
        // successor's own ~20-day expiry crosses the warning threshold at this same poll.
        timeProvider.SetUtcNow(T0 + refreshInterval);
        var keys = await sut.GetSigningKeysAsync(ct);

        keys.Should().HaveCount(2, "the predecessor is still within its retirement window");
        logger.Entries.Count(e => e.Level == LogLevel.Warning && e.Message.Contains("within 30 days")).Should().Be(1,
            "the ask already performed the expiry check this cycle, so LoadKeysAsync's own cold-start-only call must not repeat it");
    }
}
