using System.Security.Cryptography.X509Certificates;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Microsoft.Extensions.Time.Testing;
using ZeeKayDa.Auth.FileSystem.Tests.Fakes;
using ZeeKayDa.Auth.FileSystem.Tests.Fixtures;
using ZeeKayDa.Auth.Logging;
using ZeeKayDa.Auth.Tokens;

namespace ZeeKayDa.Auth.FileSystem.Tests;

/// <summary>
/// Direct-construction tests for <see cref="PfxFileSigningJwtSigningService"/>, mirroring
/// <see cref="PemFileSigningJwtSigningServiceTests"/>'s shape and adding the PFX-specific concerns:
/// password handling (AC #5) and its own permission model (AC #6).
/// </summary>
public sealed class PfxFileSigningJwtSigningServiceTests
{
    private static readonly DateTimeOffset T0 = DateTimeOffset.Parse("2026-01-01T00:00:00Z");
    private const string CorrectPassword = "correct horse battery staple";

    private static PfxFileSigningJwtSigningService BuildService(
        string primaryPath,
        Func<CancellationToken, ValueTask<string>> passwordSource,
        FakeTimeProvider timeProvider,
        IReadOnlyList<(string Path, Func<CancellationToken, ValueTask<string>> PasswordSource)>? additionalFiles = null,
        TimeSpan? refreshInterval = null,
        TimeSpan? retirementWindow = null,
        SigningAlgorithm algorithm = SigningAlgorithm.RS256,
        ISanitizingLogger<FileSigningJwtSigningService<PfxFileSigningOptions>>? logger = null)
    {
        var options = new PfxFileSigningOptions
        {
            Path = primaryPath,
            PasswordSource = passwordSource,
            Algorithm = algorithm,
            KeyRotationCheckInterval = refreshInterval ?? TimeSpan.FromMinutes(5),
        };
        foreach (var additional in additionalFiles ?? [])
            options.AddFile(additional.Path, additional.PasswordSource);

        return new PfxFileSigningJwtSigningService(
            Options.Create(options),
            timeProvider,
            new FileSigningKeyReader(NullSanitizingLogger<FileSigningKeyReader>.Instance),
            new FakeRetirementWindowProvider(retirementWindow ?? TimeSpan.FromHours(1)),
            logger ?? NullSanitizingLogger<FileSigningJwtSigningService<PfxFileSigningOptions>>.Instance);
    }

    private static Func<CancellationToken, ValueTask<string>> StaticPassword(string password) =>
        _ => ValueTask.FromResult(password);

    // ── Happy path (AC #4) ───────────────────────────────────────────────────────────────────────

    [Fact]
    public async Task GetSigningKeysAsync_loads_the_certificate_with_the_correct_password()
    {
        var ct = TestContext.Current.CancellationToken;
        using var tempDir = new TempSigningKeyDirectory();
        using var certificate = TestCertificateFactory.CreateRsaSelfSigned("test", T0 - TimeSpan.FromDays(1), T0 + TimeSpan.FromDays(365));
        var path = tempDir.WritePfxFile("key.pfx", certificate, CorrectPassword);
        await using var sut = BuildService(path, StaticPassword(CorrectPassword), new FakeTimeProvider(T0));

        var keys = await sut.GetSigningKeysAsync(ct);

        keys.Should().ContainSingle();
        keys[0].KeyType.Should().Be(SigningKeyType.Rsa);
        keys[0].RsaPublicParameters.Should().NotBeNull();
    }

    [Fact]
    public async Task SignAsync_signs_with_the_loaded_certificates_private_key()
    {
        var ct = TestContext.Current.CancellationToken;
        using var tempDir = new TempSigningKeyDirectory();
        using var certificate = TestCertificateFactory.CreateRsaSelfSigned("test", T0 - TimeSpan.FromDays(1), T0 + TimeSpan.FromDays(365));
        var path = tempDir.WritePfxFile("key.pfx", certificate, CorrectPassword);
        await using var sut = BuildService(path, StaticPassword(CorrectPassword), new FakeTimeProvider(T0));
        var payloadSegment = SigningTestHelpers.Base64UrlEncode("{\"sub\":\"test-subject\"}"u8.ToArray());

        var result = await sut.SignAsync(payloadSegment, ct);
        var keys = await sut.GetSigningKeysAsync(ct);
        var descriptor = keys.Single(k => k.Kid == result.Kid);

        SigningTestHelpers.VerifyRsaSignature(descriptor, result, payloadSegment).Should().BeTrue();
    }

    // ── Missing file (AC #14) ────────────────────────────────────────────────────────────────────

    [Fact]
    public async Task GetSigningKeysAsync_throws_ZeeKayDaConfigurationException_when_the_file_does_not_exist()
    {
        var ct = TestContext.Current.CancellationToken;
        using var tempDir = new TempSigningKeyDirectory();
        var missingPath = tempDir.GetPath("does-not-exist.pfx");
        await using var sut = BuildService(missingPath, StaticPassword(CorrectPassword), new FakeTimeProvider(T0));

        var act = async () => await sut.GetSigningKeysAsync(ct);

        var exception = await act.Should().ThrowAsync<ZeeKayDaConfigurationException>();
        exception.Which.AggregatedFailures.Should().ContainSingle(f => f.Code == "signing.file_signing.file_not_found");
    }

    // ── Wrong/missing password (AC #5) ───────────────────────────────────────────────────────────

    [Fact]
    public async Task GetSigningKeysAsync_throws_ZeeKayDaConfigurationException_for_an_incorrect_password_and_never_leaks_it()
    {
        var ct = TestContext.Current.CancellationToken;
        using var tempDir = new TempSigningKeyDirectory();
        using var certificate = TestCertificateFactory.CreateRsaSelfSigned("test", T0 - TimeSpan.FromDays(1), T0 + TimeSpan.FromDays(365));
        var path = tempDir.WritePfxFile("key.pfx", certificate, CorrectPassword);
        await using var sut = BuildService(path, StaticPassword("wrong-password"), new FakeTimeProvider(T0));

        var act = async () => await sut.GetSigningKeysAsync(ct);

        var exception = await act.Should().ThrowAsync<ZeeKayDaConfigurationException>();
        exception.Which.AggregatedFailures.Should().ContainSingle(f => f.Code == "signing.file_signing.invalid_pfx");
        exception.Which.Message.Should().NotContain(CorrectPassword);
        exception.Which.Message.Should().NotContain("wrong-password");
    }

    [Fact]
    public async Task GetSigningKeysAsync_throws_ZeeKayDaConfigurationException_for_an_empty_password()
    {
        var ct = TestContext.Current.CancellationToken;
        using var tempDir = new TempSigningKeyDirectory();
        using var certificate = TestCertificateFactory.CreateRsaSelfSigned("test", T0 - TimeSpan.FromDays(1), T0 + TimeSpan.FromDays(365));
        var path = tempDir.WritePfxFile("key.pfx", certificate, CorrectPassword);
        await using var sut = BuildService(path, StaticPassword(string.Empty), new FakeTimeProvider(T0));

        var act = async () => await sut.GetSigningKeysAsync(ct);

        var exception = await act.Should().ThrowAsync<ZeeKayDaConfigurationException>();
        exception.Which.AggregatedFailures.Should().ContainSingle(f => f.Code == "signing.file_signing.invalid_pfx");
        exception.Which.Message.Should().NotContain(CorrectPassword);
    }

    // ── Permission enforcement (AC #6) ───────────────────────────────────────────────────────────

    [Fact]
    public async Task GetSigningKeysAsync_throws_when_the_file_is_broader_than_0600_on_Unix()
    {
        Assert.SkipWhen(OperatingSystem.IsWindows(), "0600-mode enforcement is the Unix permission model.");

        var ct = TestContext.Current.CancellationToken;
        using var tempDir = new TempSigningKeyDirectory();
        using var certificate = TestCertificateFactory.CreateRsaSelfSigned("test", T0 - TimeSpan.FromDays(1), T0 + TimeSpan.FromDays(365));
        var path = tempDir.WritePfxFile("key.pfx", certificate, CorrectPassword);
        tempDir.MakeTooPermissive(path);
        await using var sut = BuildService(path, StaticPassword(CorrectPassword), new FakeTimeProvider(T0));

        var act = async () => await sut.GetSigningKeysAsync(ct);

        var exception = await act.Should().ThrowAsync<ZeeKayDaConfigurationException>();
        exception.Which.AggregatedFailures.Should().ContainSingle(f => f.Code == "signing.file_signing.file_too_permissive");
    }

    [Fact]
    public async Task GetSigningKeysAsync_throws_when_the_ACL_grants_a_broad_principal_on_Windows()
    {
        Assert.SkipUnless(OperatingSystem.IsWindows(), "broad-principal ACL enforcement is the Windows permission model.");

        var ct = TestContext.Current.CancellationToken;
        using var tempDir = new TempSigningKeyDirectory();
        using var certificate = TestCertificateFactory.CreateRsaSelfSigned("test", T0 - TimeSpan.FromDays(1), T0 + TimeSpan.FromDays(365));
        var path = tempDir.WritePfxFile("key.pfx", certificate, CorrectPassword);
        tempDir.MakeTooPermissive(path);
        await using var sut = BuildService(path, StaticPassword(CorrectPassword), new FakeTimeProvider(T0));

        var act = async () => await sut.GetSigningKeysAsync(ct);

        var exception = await act.Should().ThrowAsync<ZeeKayDaConfigurationException>();
        exception.Which.AggregatedFailures.Should().ContainSingle(f => f.Code == "signing.file_signing.file_too_permissive");
    }

    // ── Symlink rejection ─────────────────────────────────────────────────────────────────────────

    [Fact]
    public async Task GetSigningKeysAsync_throws_when_the_registered_path_is_a_symlink()
    {
        var ct = TestContext.Current.CancellationToken;
        using var tempDir = new TempSigningKeyDirectory();
        using var certificate = TestCertificateFactory.CreateRsaSelfSigned("test", T0 - TimeSpan.FromDays(1), T0 + TimeSpan.FromDays(365));
        var realPath = tempDir.WritePfxFile("real.pfx", certificate, CorrectPassword);
        var symlinkPath = tempDir.GetPath("link.pfx");

        try
        {
            File.CreateSymbolicLink(symlinkPath, realPath);
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            Assert.Skip("Creating a symlink requires elevated privileges/Developer Mode on this platform.");
            return;
        }

        await using var sut = BuildService(symlinkPath, StaticPassword(CorrectPassword), new FakeTimeProvider(T0));

        var act = async () => await sut.GetSigningKeysAsync(ct);

        var exception = await act.Should().ThrowAsync<ZeeKayDaConfigurationException>();
        exception.Which.AggregatedFailures.Should().ContainSingle(f => f.Code == "signing.file_signing.symlink_detected");
    }

    // ── Multi-file rotation via AddFile, each with its own password (AC #9/#10) ─────────────────

    [Fact]
    public async Task GetSigningKeysAsync_exposes_both_files_during_a_rotation_overlap_with_independent_passwords()
    {
        var ct = TestContext.Current.CancellationToken;
        var refreshInterval = TimeSpan.FromMinutes(5);
        using var tempDir = new TempSigningKeyDirectory();
        using var predecessor = TestCertificateFactory.CreateRsaSelfSigned("predecessor", T0 - TimeSpan.FromDays(30), T0 + TimeSpan.FromDays(365));
        var successorNotBefore = T0 + TimeSpan.FromDays(1);
        using var successor = TestCertificateFactory.CreateRsaSelfSigned("successor", successorNotBefore, T0 + TimeSpan.FromDays(400));
        var predecessorPath = tempDir.WritePfxFile("predecessor.pfx", predecessor, "predecessor-password");
        var successorPath = tempDir.WritePfxFile("successor.pfx", successor, "successor-password");
        var timeProvider = new FakeTimeProvider(T0);
        await using var sut = BuildService(
            predecessorPath, StaticPassword("predecessor-password"), timeProvider,
            [(successorPath, StaticPassword("successor-password"))], refreshInterval: refreshInterval);

        var keys = await sut.GetSigningKeysAsync(ct);

        keys.Should().HaveCount(2, "AC #9: both files must be exposed during the overlap window, each decrypted with its own password");
    }

    [Fact]
    public async Task GetSigningKeysAsync_active_signer_switches_when_the_successors_NotBefore_arrives()
    {
        var ct = TestContext.Current.CancellationToken;
        var refreshInterval = TimeSpan.FromMinutes(5);
        using var tempDir = new TempSigningKeyDirectory();
        using var predecessor = TestCertificateFactory.CreateRsaSelfSigned("predecessor", T0 - TimeSpan.FromDays(30), T0 + TimeSpan.FromDays(365));
        var successorNotBefore = T0 + TimeSpan.FromDays(1);
        using var successor = TestCertificateFactory.CreateRsaSelfSigned("successor", successorNotBefore, T0 + TimeSpan.FromDays(400));
        var predecessorPath = tempDir.WritePfxFile("predecessor.pfx", predecessor, CorrectPassword);
        var successorPath = tempDir.WritePfxFile("successor.pfx", successor, CorrectPassword);
        var timeProvider = new FakeTimeProvider(T0);
        await using var sut = BuildService(
            predecessorPath, StaticPassword(CorrectPassword), timeProvider,
            [(successorPath, StaticPassword(CorrectPassword))], refreshInterval: refreshInterval);

        var before = await sut.GetSigningKeysAsync(ct);
        before[0].Kid.Should().Be(JwkThumbprint.Compute(predecessor.GetRSAPublicKey()!.ExportParameters(false)));

        timeProvider.SetUtcNow(successorNotBefore);
        var after = await sut.GetSigningKeysAsync(ct);
        after[0].Kid.Should().Be(JwkThumbprint.Compute(successor.GetRSAPublicKey()!.ExportParameters(false)));
    }

    // ── Single-file bootstrap exemption (AC #11) ─────────────────────────────────────────────────

    [Fact]
    public async Task GetSigningKeysAsync_the_sole_registered_file_is_active_immediately_despite_a_future_NotBefore()
    {
        var ct = TestContext.Current.CancellationToken;
        using var tempDir = new TempSigningKeyDirectory();
        using var certificate = TestCertificateFactory.CreateRsaSelfSigned("test", T0 + TimeSpan.FromDays(30), T0 + TimeSpan.FromDays(365));
        var path = tempDir.WritePfxFile("key.pfx", certificate, CorrectPassword);
        await using var sut = BuildService(path, StaticPassword(CorrectPassword), new FakeTimeProvider(T0));

        var act = async () => await sut.GetSigningKeysAsync(ct);

        await act.Should().NotThrowAsync("AC #11: the bootstrap exemption activates the sole file immediately");
    }

    // ── Too-soon-NotBefore startup warning (AC #12) ──────────────────────────────────────────────

    [Fact]
    public async Task GetSigningKeysAsync_logs_a_warning_when_the_soonest_pending_NotBefore_is_closer_than_KeyRotationCheckInterval()
    {
        var ct = TestContext.Current.CancellationToken;
        var refreshInterval = TimeSpan.FromMinutes(5);
        using var tempDir = new TempSigningKeyDirectory();
        using var primary = TestCertificateFactory.CreateRsaSelfSigned("primary", T0 - TimeSpan.FromDays(30), T0 + TimeSpan.FromDays(365));
        using var secondary = TestCertificateFactory.CreateRsaSelfSigned("secondary", T0 + TimeSpan.FromMinutes(1), T0 + TimeSpan.FromDays(400));
        var primaryPath = tempDir.WritePfxFile("primary.pfx", primary, CorrectPassword);
        var secondaryPath = tempDir.WritePfxFile("secondary.pfx", secondary, CorrectPassword);
        var logger = new CapturingSanitizingLogger<FileSigningJwtSigningService<PfxFileSigningOptions>>();
        await using var sut = BuildService(
            primaryPath, StaticPassword(CorrectPassword), new FakeTimeProvider(T0),
            [(secondaryPath, StaticPassword(CorrectPassword))], refreshInterval: refreshInterval, logger: logger);

        await sut.GetSigningKeysAsync(ct);

        logger.Entries.Should().Contain(e => e.Level == LogLevel.Warning,
            "AC #12: the too-soon-NotBefore misconfiguration must be surfaced");
    }

    // ── Algorithm/key-type mismatch ───────────────────────────────────────────────────────────────

    [Fact]
    public async Task GetSigningKeysAsync_throws_when_Algorithm_does_not_match_the_certificates_key_type()
    {
        var ct = TestContext.Current.CancellationToken;
        using var tempDir = new TempSigningKeyDirectory();
        using var certificate = TestCertificateFactory.CreateRsaSelfSigned("test", T0 - TimeSpan.FromDays(1), T0 + TimeSpan.FromDays(365));
        var path = tempDir.WritePfxFile("key.pfx", certificate, CorrectPassword);
        await using var sut = BuildService(path, StaticPassword(CorrectPassword), new FakeTimeProvider(T0), algorithm: SigningAlgorithm.ES256);

        var act = async () => await sut.GetSigningKeysAsync(ct);

        var exception = await act.Should().ThrowAsync<ZeeKayDaConfigurationException>();
        exception.Which.AggregatedFailures.Should().ContainSingle(f => f.Code == "signing.file_signing.algorithm_key_type_mismatch");
    }

    [Fact]
    public async Task GetSigningKeysAsync_throws_when_Algorithm_is_RSA_but_the_certificate_is_EC()
    {
        // The RSA-mismatch direction is covered above; this covers the other half of the shared
        // FileSigningJwtSigningService{TOptions}.BuildKeyDescriptor mismatch-message branch.
        var ct = TestContext.Current.CancellationToken;
        using var tempDir = new TempSigningKeyDirectory();
        using var certificate = TestCertificateFactory.CreateEcSelfSigned("test", T0 - TimeSpan.FromDays(1), T0 + TimeSpan.FromDays(365));
        var path = tempDir.WritePfxFile("key.pfx", certificate, CorrectPassword);
        await using var sut = BuildService(path, StaticPassword(CorrectPassword), new FakeTimeProvider(T0), algorithm: SigningAlgorithm.RS256);

        var act = async () => await sut.GetSigningKeysAsync(ct);

        var exception = await act.Should().ThrowAsync<ZeeKayDaConfigurationException>();
        exception.Which.AggregatedFailures.Should().ContainSingle(f => f.Code == "signing.file_signing.algorithm_key_type_mismatch");
        exception.Which.Message.Should().Contain("EC certificate");
    }

    // ── EC certificates ───────────────────────────────────────────────────────────────────────────

    [Fact]
    public async Task SignAsync_signs_with_an_EC_certificates_private_key()
    {
        var ct = TestContext.Current.CancellationToken;
        using var tempDir = new TempSigningKeyDirectory();
        using var certificate = TestCertificateFactory.CreateEcSelfSigned("test", T0 - TimeSpan.FromDays(1), T0 + TimeSpan.FromDays(365));
        var path = tempDir.WritePfxFile("key.pfx", certificate, CorrectPassword);
        await using var sut = BuildService(path, StaticPassword(CorrectPassword), new FakeTimeProvider(T0), algorithm: SigningAlgorithm.ES256);
        var payloadSegment = SigningTestHelpers.Base64UrlEncode("{\"sub\":\"test-subject\"}"u8.ToArray());

        var result = await sut.SignAsync(payloadSegment, ct);

        result.Kid.Should().NotBeNullOrEmpty();
        result.Algorithm.Should().Be(SigningAlgorithm.ES256);
    }

    // ── HasKeySetChangedAsync: metadata-only change detection (ADR 0011 §3.5 / issue #349) ─────────
    //
    // FileSigningJwtSigningService{TOptions} is now exercised only via this PFX provider — the PEM
    // provider migrated to the ADR 0015 KeySetOptions contract (issue #422) and no longer shares
    // this base class, so these scenarios (previously covered once via the PEM tests, per issue
    // #350/#351's "cover the shared base once" convention) now live here instead.

    [Fact]
    public async Task GetSigningKeysAsync_reloads_when_a_registered_files_contents_change()
    {
        var ct = TestContext.Current.CancellationToken;
        var refreshInterval = TimeSpan.FromMinutes(5);
        using var tempDir = new TempSigningKeyDirectory();
        using var original = TestCertificateFactory.CreateRsaSelfSigned("original", T0 - TimeSpan.FromDays(1), T0 + TimeSpan.FromDays(365));
        using var replacement = TestCertificateFactory.CreateRsaSelfSigned("replacement", T0 - TimeSpan.FromDays(1), T0 + TimeSpan.FromDays(365));
        var path = tempDir.WritePfxFile("key.pfx", original, CorrectPassword);
        var timeProvider = new FakeTimeProvider(T0);
        await using var sut = BuildService(path, StaticPassword(CorrectPassword), timeProvider, refreshInterval: refreshInterval);

        var first = await sut.GetSigningKeysAsync(ct);
        tempDir.WritePfxFile("key.pfx", replacement, CorrectPassword); // Overwrites both content and mtime.
        timeProvider.SetUtcNow(T0 + refreshInterval);

        var second = await sut.GetSigningKeysAsync(ct);

        second[0].Kid.Should().NotBe(first[0].Kid,
            "the file's content (and mtime) changed, so HasKeySetChangedAsync must report a change and " +
            "LoadKeysAsync must reread and reparse it");
    }

    [Fact]
    public async Task GetSigningKeysAsync_reloads_when_a_new_path_is_added_to_configuration()
    {
        var ct = TestContext.Current.CancellationToken;
        var refreshInterval = TimeSpan.FromMinutes(5);
        using var tempDir = new TempSigningKeyDirectory();
        using var primary = TestCertificateFactory.CreateRsaSelfSigned("primary", T0 - TimeSpan.FromDays(30), T0 + TimeSpan.FromDays(365));
        using var secondary = TestCertificateFactory.CreateRsaSelfSigned("secondary", T0 + TimeSpan.FromDays(30), T0 + TimeSpan.FromDays(400));
        var primaryPath = tempDir.WritePfxFile("primary.pfx", primary, CorrectPassword);
        var secondaryPath = tempDir.WritePfxFile("secondary.pfx", secondary, CorrectPassword);
        var options = new PfxFileSigningOptions
        {
            Path = primaryPath,
            PasswordSource = StaticPassword(CorrectPassword),
            KeyRotationCheckInterval = refreshInterval,
        };
        var timeProvider = new FakeTimeProvider(T0);
        await using var sut = new PfxFileSigningJwtSigningService(
            Options.Create(options),
            timeProvider,
            new FileSigningKeyReader(NullSanitizingLogger<FileSigningKeyReader>.Instance),
            new FakeRetirementWindowProvider(TimeSpan.FromHours(1)),
            NullSanitizingLogger<FileSigningJwtSigningService<PfxFileSigningOptions>>.Instance);

        var first = await sut.GetSigningKeysAsync(ct);
        first.Should().ContainSingle("only the primary path is registered so far");

        options.AddFile(secondaryPath, StaticPassword(CorrectPassword)); // Registered path set changes with zero file I/O.
        timeProvider.SetUtcNow(T0 + refreshInterval);
        var second = await sut.GetSigningKeysAsync(ct);

        second.Should().HaveCount(2,
            "the registered path set changed, so HasKeySetChangedAsync must report a change even " +
            "though neither file's content changed");
    }

    [Fact]
    public async Task HasKeySetChangedAsync_reports_a_change_when_elapsed_time_alone_moves_a_certificate_out_of_its_retirement_window()
    {
        var ct = TestContext.Current.CancellationToken;
        var refreshInterval = TimeSpan.FromMinutes(5);
        var retirementWindow = TimeSpan.FromHours(1);
        using var tempDir = new TempSigningKeyDirectory();
        using var predecessor = TestCertificateFactory.CreateRsaSelfSigned("predecessor", T0 - TimeSpan.FromDays(30), T0 + TimeSpan.FromDays(365));
        var successorNotBefore = T0 + TimeSpan.FromMinutes(10);
        using var successor = TestCertificateFactory.CreateRsaSelfSigned("successor", successorNotBefore, T0 + TimeSpan.FromDays(400));
        var predecessorPath = tempDir.WritePfxFile("predecessor.pfx", predecessor, CorrectPassword);
        var successorPath = tempDir.WritePfxFile("successor.pfx", successor, CorrectPassword);
        var timeProvider = new FakeTimeProvider(T0);
        await using var sut = BuildService(
            predecessorPath, StaticPassword(CorrectPassword), timeProvider,
            [(successorPath, StaticPassword(CorrectPassword))], refreshInterval: refreshInterval, retirementWindow: retirementWindow);

        await sut.GetSigningKeysAsync(ct); // Cold start: predecessor active, successor pending.

        timeProvider.SetUtcNow(successorNotBefore); // Successor activates; predecessor now retiring but still within its window.
        var duringRetirement = await sut.GetSigningKeysAsync(ct);
        duringRetirement.Should().HaveCount(2, "the predecessor is still within its retirement window");

        timeProvider.SetUtcNow(successorNotBefore + retirementWindow + TimeSpan.FromSeconds(1)); // Retirement window fully elapsed, with zero file changes.
        var afterRetirement = await sut.GetSigningKeysAsync(ct);

        afterRetirement.Should().HaveCount(1,
            "elapsed time alone moved the predecessor out of its retirement window, so " +
            "HasKeySetChangedAsync must report a change and LoadKeysAsync must rebuild the set even " +
            "though no file changed");
    }

    [Fact]
    public async Task GetSigningKeysAsync_reports_a_change_rather_than_throwing_when_every_registered_certificate_has_since_expired()
    {
        var ct = TestContext.Current.CancellationToken;
        var refreshInterval = TimeSpan.FromMinutes(5);
        using var tempDir = new TempSigningKeyDirectory();
        using var certificate = TestCertificateFactory.CreateRsaSelfSigned("test", T0 - TimeSpan.FromDays(30), T0 + TimeSpan.FromDays(1));
        var path = tempDir.WritePfxFile("key.pfx", certificate, CorrectPassword);
        var timeProvider = new FakeTimeProvider(T0);
        await using var sut = BuildService(path, StaticPassword(CorrectPassword), timeProvider, refreshInterval: refreshInterval);

        await sut.GetSigningKeysAsync(ct); // Cold start: the certificate is active.

        // Every registered file's certificate has now expired, with zero file changes. This must not
        // surface as an unhandled exception from HasKeySetChangedAsync's own ask (its contract is only
        // ever "did the trusted set change," never "is the configuration currently valid" — see that
        // method's remarks); the real failure belongs to the subsequent LoadKeysAsync call.
        timeProvider.SetUtcNow(T0 + TimeSpan.FromDays(2));
        var act = async () => await sut.GetSigningKeysAsync(ct);

        var exception = await act.Should().ThrowAsync<ZeeKayDaConfigurationException>();
        exception.Which.AggregatedFailures.Should().ContainSingle(f => f.Code == "signing.file_signing.no_active_certificate",
            "HasKeySetChangedAsync must report a change (never throw) so LoadKeysAsync runs and fails " +
            "closed with its own actionable error");
    }

    // ── Expiring-soon warning ─────────────────────────────────────────────────────────────────────

    [Fact]
    public async Task GetSigningKeysAsync_warns_when_the_active_certificate_expires_within_30_days()
    {
        var ct = TestContext.Current.CancellationToken;
        using var tempDir = new TempSigningKeyDirectory();
        using var certificate = TestCertificateFactory.CreateRsaSelfSigned("test", T0 - TimeSpan.FromDays(1), T0 + TimeSpan.FromDays(10));
        var path = tempDir.WritePfxFile("key.pfx", certificate, CorrectPassword);
        var logger = new CapturingSanitizingLogger<FileSigningJwtSigningService<PfxFileSigningOptions>>();
        await using var sut = BuildService(path, StaticPassword(CorrectPassword), new FakeTimeProvider(T0), logger: logger);

        await sut.GetSigningKeysAsync(ct);

        logger.Entries.Should().Contain(e => e.Level == LogLevel.Warning && e.Message.Contains("expires"),
            "the active certificate expiring within 30 days must be surfaced");
    }

    // ── Logging: never leaks key material or password (issue #291's explicit requirement) ──────

    [Fact]
    public async Task GetSigningKeysAsync_logs_path_key_type_and_key_size_but_never_key_material_or_password()
    {
        var ct = TestContext.Current.CancellationToken;
        using var tempDir = new TempSigningKeyDirectory();
        using var certificate = TestCertificateFactory.CreateRsaSelfSigned("test", T0 - TimeSpan.FromDays(1), T0 + TimeSpan.FromDays(365), keySizeBits: 2048);
        var path = tempDir.WritePfxFile("key.pfx", certificate, CorrectPassword);
        var logger = new CapturingSanitizingLogger<FileSigningJwtSigningService<PfxFileSigningOptions>>();
        await using var sut = BuildService(path, StaticPassword(CorrectPassword), new FakeTimeProvider(T0), logger: logger);

        await sut.GetSigningKeysAsync(ct);

        logger.Entries.Should().ContainSingle(e => e.Level == LogLevel.Information
            && e.Message.Contains(path)
            && e.Message.Contains("RSA")
            && e.Message.Contains("2048"));
        logger.Entries.Should().NotContain(e => e.Message.Contains(CorrectPassword),
            "the PFX password must never reach a log line");
    }
}
