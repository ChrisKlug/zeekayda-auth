using System.Security.Cryptography.X509Certificates;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Microsoft.Extensions.Time.Testing;
using ZeeKayDa.Auth.Logging;
using ZeeKayDa.Auth.MacOS.Tests.Fakes;
using ZeeKayDa.Auth.MacOS.Tests.Fixtures;
using ZeeKayDa.Auth.Tokens;

namespace ZeeKayDa.Auth.MacOS.Tests;

/// <summary>
/// Direct-construction tests for <see cref="MacOsKeychainSigningJwtSigningService"/>, bypassing DI and
/// the platform-gated <c>AddMacOsKeychainSigning</c> extension method entirely. The service class
/// itself has no macOS-specific code (it depends only on <see cref="IKeychainItemReader"/>), so —
/// mirroring <c>ZeeKayDa.Auth.Windows.Tests.WindowsCertificateStoreSigningJwtSigningServiceTests</c>'s
/// pattern for its sibling provider — these tests run on any OS.
/// </summary>
public sealed class MacOsKeychainSigningJwtSigningServiceTests
{
    private static readonly DateTimeOffset T0 = DateTimeOffset.Parse("2026-01-01T00:00:00Z");

    private static MacOsKeychainSigningJwtSigningService BuildService(
        FakeKeychainItemReader reader,
        FakeTimeProvider timeProvider,
        string primaryLabel,
        Action<MacOsKeychainSigningOptions>? configure = null,
        TimeSpan? refreshInterval = null,
        TimeSpan? retirementWindow = null,
        ISanitizingLogger<MacOsKeychainSigningJwtSigningService>? logger = null)
    {
        var options = new MacOsKeychainSigningOptions
        {
            Label = primaryLabel,
            RefreshInterval = refreshInterval ?? TimeSpan.FromMinutes(5),
        };
        configure?.Invoke(options);

        return new MacOsKeychainSigningJwtSigningService(
            Options.Create(options),
            timeProvider,
            reader,
            new FakeRetirementWindowProvider(retirementWindow ?? TimeSpan.FromHours(1)),
            logger ?? NullSanitizingLogger<MacOsKeychainSigningJwtSigningService>.Instance);
    }

    // ── Bootstrap exemption (AC #6) ──────────────────────────────────────────────────────────────

    [Fact]
    public async Task GetSigningKeysAsync_single_certificate_backed_key_activates_immediately_despite_future_NotBefore()
    {
        var ct = TestContext.Current.CancellationToken;
        var reader = new FakeKeychainItemReader();
        using var cert = TestKeyFactory.CreateRsaSelfSigned("test", T0 + TimeSpan.FromDays(30), T0 + TimeSpan.FromDays(365));
        reader.AddCertificate("primary", cert);
        var timeProvider = new FakeTimeProvider(T0);

        await using var sut = BuildService(reader, timeProvider, "primary");
        var act = async () => await sut.GetSigningKeysAsync(ct);

        await act.Should().NotThrowAsync("AC #6: the bootstrap exemption activates the sole certificate immediately");
    }

    [Fact]
    public async Task GetSigningKeysAsync_single_bare_key_with_no_explicit_activation_activates_via_bootstrap_exemption()
    {
        var ct = TestContext.Current.CancellationToken;
        var reader = new FakeKeychainItemReader();
        using var rsa = TestKeyFactory.CreateRsaKey();
        reader.AddKey("bare-primary", rsa);
        var timeProvider = new FakeTimeProvider(T0);

        await using var sut = BuildService(reader, timeProvider, "bare-primary");
        var act = async () => await sut.GetSigningKeysAsync(ct);

        await act.Should().NotThrowAsync("AC #6/#13: a bare sole key needs no explicit activation time");
    }

    [Fact]
    public async Task GetSigningKeysAsync_single_expired_certificate_fails_closed()
    {
        var ct = TestContext.Current.CancellationToken;
        var reader = new FakeKeychainItemReader();
        using var cert = TestKeyFactory.CreateRsaSelfSigned("test", T0 - TimeSpan.FromDays(400), T0 - TimeSpan.FromDays(1));
        reader.AddCertificate("primary", cert);
        var timeProvider = new FakeTimeProvider(T0);

        await using var sut = BuildService(reader, timeProvider, "primary");
        var act = async () => await sut.GetSigningKeysAsync(ct);

        (await act.Should().ThrowAsync<ZeeKayDaConfigurationException>())
            .WithMessage("*no_active_key*", "the bootstrap exemption never overrides an already-expired key");
    }

    // ── kid derivation (AC #3) ────────────────────────────────────────────────────────────────────

    [Fact]
    public async Task GetSigningKeysAsync_kid_is_JWK_thumbprint_not_the_Keychain_label()
    {
        var ct = TestContext.Current.CancellationToken;
        var reader = new FakeKeychainItemReader();
        using var cert = TestKeyFactory.CreateRsaSelfSigned("test", T0 - TimeSpan.FromDays(1), T0 + TimeSpan.FromDays(365));
        reader.AddCertificate("my-signing-key-label", cert);
        var timeProvider = new FakeTimeProvider(T0);

        await using var sut = BuildService(reader, timeProvider, "my-signing-key-label");
        var keys = await sut.GetSigningKeysAsync(ct);

        var expectedKid = JwkThumbprint.Compute(cert.GetRSAPublicKey()!.ExportParameters(false));
        keys[0].Kid.Should().Be(expectedKid);
        keys[0].Kid.Should().NotContain("my-signing-key-label");
    }

    [Fact]
    public async Task GetSigningKeysAsync_kid_is_JWK_thumbprint_for_a_bare_EC_key()
    {
        var ct = TestContext.Current.CancellationToken;
        var reader = new FakeKeychainItemReader();
        using var ecdsa = TestKeyFactory.CreateEcKey();
        reader.AddKey("bare-ec", ecdsa);
        var timeProvider = new FakeTimeProvider(T0);

        await using var sut = BuildService(reader, timeProvider, "bare-ec",
            configure: o => o.Algorithm = SigningAlgorithm.ES256);
        var keys = await sut.GetSigningKeysAsync(ct);

        var expectedKid = JwkThumbprint.Compute(ecdsa.ExportParameters(false));
        keys[0].Kid.Should().Be(expectedKid);
        keys[0].EcPublicParameters.Should().NotBeNull();
    }

    // ── Multi-key registration, both AddKey overloads (AC #4) ────────────────────────────────────

    [Fact]
    public async Task GetSigningKeysAsync_JWKS_includes_both_keys_during_overlap_certificate_backed_AddKey()
    {
        var ct = TestContext.Current.CancellationToken;
        var reader = new FakeKeychainItemReader();
        using var primary = TestKeyFactory.CreateRsaSelfSigned("primary", T0 - TimeSpan.FromDays(30), T0 + TimeSpan.FromDays(365));
        using var secondary = TestKeyFactory.CreateRsaSelfSigned("secondary", T0 + TimeSpan.FromDays(1), T0 + TimeSpan.FromDays(400));
        reader.AddCertificate("primary", primary);
        reader.AddCertificate("secondary", secondary);
        var timeProvider = new FakeTimeProvider(T0);

        await using var sut = BuildService(reader, timeProvider, "primary", configure: o => o.AddKey("secondary"));
        var keys = await sut.GetSigningKeysAsync(ct);

        keys.Should().HaveCount(2, "AC #4: both certificate-backed keys must be exposed during the overlap window");
    }

    [Fact]
    public async Task GetSigningKeysAsync_JWKS_includes_both_keys_during_overlap_explicit_bare_AddKey()
    {
        // The primary label can only safely resolve to a bare key with no explicit activation when
        // it is the *sole* registered key (see AC #13's own carve-out and
        // GetSigningKeysAsync_throws_when_a_bare_key_via_plain_AddKey_has_no_activation_and_2plus_keys_registered
        // above) — so a 2-key overlap test that wants a bare key with an *explicit* activation must
        // register the primary as certificate-backed and add the bare key via the second AddKey
        // overload, exactly as AC #4 itself illustrates ("certificate NotBefore/NotAfter, or an
        // explicit activatesAt/expiresAt for a bare key" describes the two keys' shapes, not that
        // both must be bare).
        var ct = TestContext.Current.CancellationToken;
        var reader = new FakeKeychainItemReader();
        using var primaryCert = TestKeyFactory.CreateRsaSelfSigned("primary", T0 - TimeSpan.FromDays(30), T0 + TimeSpan.FromDays(365));
        using var secondaryRsa = TestKeyFactory.CreateRsaKey();
        reader.AddCertificate("primary", primaryCert);
        reader.AddKey("bare-secondary", secondaryRsa);
        var timeProvider = new FakeTimeProvider(T0);

        await using var sut = BuildService(reader, timeProvider, "primary",
            configure: o => o.AddKey("bare-secondary", T0 + TimeSpan.FromDays(1), T0 + TimeSpan.FromDays(400)));
        var keys = await sut.GetSigningKeysAsync(ct);

        keys.Should().HaveCount(2, "AC #4: both keys must be exposed during the overlap window");
    }

    [Fact]
    public async Task GetSigningKeysAsync_active_signer_switches_when_successors_activation_arrives()
    {
        var ct = TestContext.Current.CancellationToken;
        var reader = new FakeKeychainItemReader();
        using var predecessor = TestKeyFactory.CreateRsaSelfSigned("predecessor", T0 - TimeSpan.FromDays(30), T0 + TimeSpan.FromDays(365));
        var successorActivatesAt = T0 + TimeSpan.FromDays(1);
        using var successor = TestKeyFactory.CreateRsaSelfSigned("successor", successorActivatesAt, T0 + TimeSpan.FromDays(400));
        reader.AddCertificate("predecessor", predecessor);
        reader.AddCertificate("successor", successor);
        var timeProvider = new FakeTimeProvider(T0);

        await using var sut = BuildService(reader, timeProvider, "predecessor",
            configure: o => { o.AddKey("successor"); o.RefreshInterval = TimeSpan.FromMinutes(5); });

        var before = await sut.GetSigningKeysAsync(ct);
        before[0].Kid.Should().Be(JwkThumbprint.Compute(predecessor.GetRSAPublicKey()!.ExportParameters(false)),
            "AC #5: predecessor is active before successor's activation arrives");

        timeProvider.SetUtcNow(successorActivatesAt);
        var after = await sut.GetSigningKeysAsync(ct);
        after[0].Kid.Should().Be(JwkThumbprint.Compute(successor.GetRSAPublicKey()!.ExportParameters(false)),
            "AC #5: successor becomes active once its activation time arrives, retiring predecessor from that moment");
    }

    // ── Too-soon-pending-activation warning (AC #7) ──────────────────────────────────────────────

    [Fact]
    public async Task GetSigningKeysAsync_logs_warning_when_soonest_pending_activation_is_closer_than_RefreshInterval()
    {
        var ct = TestContext.Current.CancellationToken;
        var refreshInterval = TimeSpan.FromMinutes(5);
        var reader = new FakeKeychainItemReader();
        using var primary = TestKeyFactory.CreateRsaSelfSigned("primary", T0 - TimeSpan.FromDays(30), T0 + TimeSpan.FromDays(365));
        using var secondary = TestKeyFactory.CreateRsaSelfSigned("secondary", T0 + TimeSpan.FromMinutes(1), T0 + TimeSpan.FromDays(400));
        reader.AddCertificate("primary", primary);
        reader.AddCertificate("secondary", secondary);
        var timeProvider = new FakeTimeProvider(T0);
        var logger = new CapturingSanitizingLogger<MacOsKeychainSigningJwtSigningService>();

        await using var sut = BuildService(reader, timeProvider, "primary",
            configure: o => { o.AddKey("secondary"); o.RefreshInterval = refreshInterval; }, logger: logger);
        await sut.GetSigningKeysAsync(ct);

        logger.Entries.Should().Contain(e => e.Level == LogLevel.Warning, "AC #7: the too-soon-activation misconfiguration must be surfaced");
    }

    // ── Bare-key-without-activation fail-fast (AC #13) ───────────────────────────────────────────

    [Fact]
    public async Task GetSigningKeysAsync_throws_when_a_bare_key_via_plain_AddKey_has_no_activation_and_2plus_keys_registered()
    {
        var ct = TestContext.Current.CancellationToken;
        var reader = new FakeKeychainItemReader();
        using var primary = TestKeyFactory.CreateRsaSelfSigned("primary", T0 - TimeSpan.FromDays(1), T0 + TimeSpan.FromDays(365));
        using var bareRsa = TestKeyFactory.CreateRsaKey();
        reader.AddCertificate("primary", primary);
        reader.AddKey("bare-secondary", bareRsa); // No certificate registered for this label -> resolves as bare.
        var timeProvider = new FakeTimeProvider(T0);

        await using var sut = BuildService(reader, timeProvider, "primary", configure: o => o.AddKey("bare-secondary"));
        var act = async () => await sut.GetSigningKeysAsync(ct);

        var assertion = await act.Should().ThrowAsync<ZeeKayDaConfigurationException>();
        assertion.WithMessage("*bare_key_requires_activation*")
            .WithMessage("*bare-secondary*", "the exception must name the offending label")
            .WithMessage("*AddKey*", "the exception must point at the AddKey(label, activatesAt) overload");
    }

    [Fact]
    public async Task GetSigningKeysAsync_does_not_throw_when_the_primary_label_itself_is_a_bare_key_with_no_activation_and_is_the_sole_key()
    {
        var ct = TestContext.Current.CancellationToken;
        var reader = new FakeKeychainItemReader();
        using var bareRsa = TestKeyFactory.CreateRsaKey();
        reader.AddKey("solo-bare", bareRsa);
        var timeProvider = new FakeTimeProvider(T0);

        await using var sut = BuildService(reader, timeProvider, "solo-bare");
        var act = async () => await sut.GetSigningKeysAsync(ct);

        await act.Should().NotThrowAsync("a bare sole key is exempt from the fail-fast rule (AC #13's own carve-out)");
    }

    // ── Missing label (AC #8) ────────────────────────────────────────────────────────────────────

    [Fact]
    public async Task GetSigningKeysAsync_throws_clear_exception_when_label_matches_neither_a_certificate_nor_a_key()
    {
        var ct = TestContext.Current.CancellationToken;
        var reader = new FakeKeychainItemReader(); // Nothing registered.
        var timeProvider = new FakeTimeProvider(T0);

        await using var sut = BuildService(reader, timeProvider, "missing-label");
        var act = async () => await sut.GetSigningKeysAsync(ct);

        var assertion = await act.Should().ThrowAsync<ZeeKayDaConfigurationException>();
        assertion.WithMessage("*item_not_found*").WithMessage("*missing-label*");
    }

    // ── Keychain inaccessible (AC #10) ───────────────────────────────────────────────────────────

    [Fact]
    public async Task GetSigningKeysAsync_propagates_keychain_inaccessible_failure_without_swallowing_it()
    {
        var ct = TestContext.Current.CancellationToken;
        var reader = new FakeKeychainItemReader();
        reader.SetCertificateLookupException("primary", new ZeeKayDaConfigurationException(new ZeeKayDaConfigurationFailure(
            "signing.macos_keychain.keychain_inaccessible", "Simulated locked Keychain.")));
        var timeProvider = new FakeTimeProvider(T0);

        await using var sut = BuildService(reader, timeProvider, "primary");
        var act = async () => await sut.GetSigningKeysAsync(ct);

        (await act.Should().ThrowAsync<ZeeKayDaConfigurationException>()).WithMessage("*keychain_inaccessible*");
    }

    [Fact]
    public async Task GetSigningKeysAsync_propagates_key_lacks_signing_capability_failure()
    {
        var ct = TestContext.Current.CancellationToken;
        var reader = new FakeKeychainItemReader();
        reader.SetKeyLookupException("bare-primary", new ZeeKayDaConfigurationException(new ZeeKayDaConfigurationFailure(
            "signing.macos_keychain.lacks_signing_capability", "Simulated symmetric key with no signing capability.")));
        var timeProvider = new FakeTimeProvider(T0);

        await using var sut = BuildService(reader, timeProvider, "bare-primary");
        var act = async () => await sut.GetSigningKeysAsync(ct);

        (await act.Should().ThrowAsync<ZeeKayDaConfigurationException>()).WithMessage("*lacks_signing_capability*");
    }

    // ── Expiry warning (30 days) ──────────────────────────────────────────────────────────────────

    [Fact]
    public async Task GetSigningKeysAsync_logs_warning_when_active_certificate_expires_within_30_days()
    {
        var ct = TestContext.Current.CancellationToken;
        var reader = new FakeKeychainItemReader();
        using var cert = TestKeyFactory.CreateRsaSelfSigned("test", T0 - TimeSpan.FromDays(300), T0 + TimeSpan.FromDays(10));
        reader.AddCertificate("primary", cert);
        var logger = new CapturingSanitizingLogger<MacOsKeychainSigningJwtSigningService>();
        var timeProvider = new FakeTimeProvider(T0);

        await using var sut = BuildService(reader, timeProvider, "primary", logger: logger);
        await sut.GetSigningKeysAsync(ct);

        logger.Entries.Should().Contain(e => e.Level == LogLevel.Warning && e.Message.Contains("expires"));
    }

    [Fact]
    public async Task GetSigningKeysAsync_never_logs_expiry_warning_for_a_bare_key_with_no_explicit_expiry()
    {
        var ct = TestContext.Current.CancellationToken;
        var reader = new FakeKeychainItemReader();
        using var rsa = TestKeyFactory.CreateRsaKey();
        reader.AddKey("bare-primary", rsa);
        var logger = new CapturingSanitizingLogger<MacOsKeychainSigningJwtSigningService>();
        var timeProvider = new FakeTimeProvider(T0);

        await using var sut = BuildService(reader, timeProvider, "bare-primary", logger: logger);
        await sut.GetSigningKeysAsync(ct);

        logger.Entries.Should().NotContain(e => e.Level == LogLevel.Warning && e.Message.Contains("expires"),
            "a bare key with no explicit expiresAt never expires (RotationKey.ExpiresAt is DateTimeOffset.MaxValue)");
    }

    // ── Logging (AC #2) ──────────────────────────────────────────────────────────────────────────

    [Fact]
    public async Task GetSigningKeysAsync_logs_one_informational_line_per_registered_item_on_every_load()
    {
        var ct = TestContext.Current.CancellationToken;
        var refreshInterval = TimeSpan.FromMinutes(5);
        var reader = new FakeKeychainItemReader();
        using var cert = TestKeyFactory.CreateRsaSelfSigned("test", T0 - TimeSpan.FromDays(1), T0 + TimeSpan.FromDays(365));
        reader.AddCertificate("primary", cert);
        var logger = new CapturingSanitizingLogger<MacOsKeychainSigningJwtSigningService>();
        var timeProvider = new FakeTimeProvider(T0);

        await using var sut = BuildService(reader, timeProvider, "primary", refreshInterval: refreshInterval, logger: logger);

        await sut.GetSigningKeysAsync(ct);
        logger.Entries.Count(e => e.Level == LogLevel.Information).Should().Be(1, "AC #2: one informational line for the one registered item");

        timeProvider.SetUtcNow(T0 + refreshInterval);
        await sut.GetSigningKeysAsync(ct);
        logger.Entries.Count(e => e.Level == LogLevel.Information).Should().Be(2,
            "the per-item status line must repeat on every load, since active/included status can change over time");
    }

    [Fact]
    public async Task GetSigningKeysAsync_log_line_identifies_label_key_type_and_key_size()
    {
        var ct = TestContext.Current.CancellationToken;
        var reader = new FakeKeychainItemReader();
        using var cert = TestKeyFactory.CreateRsaSelfSigned("test", T0 - TimeSpan.FromDays(1), T0 + TimeSpan.FromDays(365), keySizeBits: 2048);
        reader.AddCertificate("my-label", cert);
        var logger = new CapturingSanitizingLogger<MacOsKeychainSigningJwtSigningService>();
        var timeProvider = new FakeTimeProvider(T0);

        await using var sut = BuildService(reader, timeProvider, "my-label", logger: logger);
        await sut.GetSigningKeysAsync(ct);

        logger.Entries.Should().Contain(e =>
            e.Level == LogLevel.Information &&
            e.Message.Contains("my-label") &&
            e.Message.Contains("Rsa", StringComparison.OrdinalIgnoreCase) &&
            e.Message.Contains("2048"));
    }

    // ── Algorithm/key-type mismatch ───────────────────────────────────────────────────────────────

    [Fact]
    public async Task GetSigningKeysAsync_throws_when_Algorithm_is_EC_but_the_key_is_RSA()
    {
        var ct = TestContext.Current.CancellationToken;
        var reader = new FakeKeychainItemReader();
        using var cert = TestKeyFactory.CreateRsaSelfSigned("test", T0 - TimeSpan.FromDays(1), T0 + TimeSpan.FromDays(365));
        reader.AddCertificate("primary", cert);
        var timeProvider = new FakeTimeProvider(T0);

        await using var sut = BuildService(reader, timeProvider, "primary", configure: o => o.Algorithm = SigningAlgorithm.ES256);
        var act = async () => await sut.GetSigningKeysAsync(ct);

        (await act.Should().ThrowAsync<ZeeKayDaConfigurationException>()).WithMessage("*algorithm_key_type_mismatch*");
    }
}
