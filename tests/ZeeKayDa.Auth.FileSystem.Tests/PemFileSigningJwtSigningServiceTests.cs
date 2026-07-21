using System.Reflection;
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
/// Direct-construction tests for <see cref="PemFileSigningJwtSigningService"/>, bypassing DI and the
/// <c>AddPemFileSigning</c> extension method entirely — mirroring
/// <c>WindowsCertificateStoreSigningJwtSigningServiceTests</c>'s pattern for its sibling provider.
/// Unlike that provider's tests, a fake reader is never substituted here: this provider's whole job
/// is real filesystem interaction (permission enforcement, symlink detection), so every test below
/// exercises the real <see cref="FileSigningKeyReader"/> against real temporary files.
/// </summary>
/// <remarks>
/// This provider is on ADR 0015's Tier A (<see cref="KeySetOptions"/>) contract (issue #422):
/// <c>ListKeysAsync</c> runs exactly once, ever, for the lifetime of a service instance, so there is
/// no reload/change-detection surface to test here — unlike the pre-migration ADR 0011 contract, a
/// changed or newly-added file is never picked up without a restart. Rotation between already-known
/// files still switches the active signer purely from elapsed wall-clock time, with zero further
/// file I/O — that behaviour is covered below.
/// </remarks>
public sealed class PemFileSigningJwtSigningServiceTests
{
    private static readonly DateTimeOffset T0 = DateTimeOffset.Parse("2026-01-01T00:00:00Z");

    private static PemFileSigningJwtSigningService BuildService(
        string primaryPath,
        FakeTimeProvider timeProvider,
        IReadOnlyList<string>? additionalPaths = null,
        TimeSpan? retirementWindow = null,
        SigningAlgorithm algorithm = SigningAlgorithm.RS256,
        string? keyPath = null,
        TimeSpan? publicationLead = null,
        ISanitizingLogger<JwtSigningService<PemFileSigningOptions>>? logger = null)
    {
        var options = new PemFileSigningOptions
        {
            Path = primaryPath,
            KeyPath = keyPath,
            Algorithm = algorithm,
            PublicationLead = publicationLead ?? TimeSpan.FromHours(1),
        };
        foreach (var additional in additionalPaths ?? [])
            options.AddFile(additional);

        return new PemFileSigningJwtSigningService(
            Options.Create(options),
            timeProvider,
            new FileSigningKeyReader(NullSanitizingLogger<FileSigningKeyReader>.Instance),
            new FakeRetirementWindowProvider(retirementWindow ?? TimeSpan.FromHours(1)),
            logger ?? NullSanitizingLogger<JwtSigningService<PemFileSigningOptions>>.Instance);
    }

    // ── Happy path (AC #1) ───────────────────────────────────────────────────────────────────────

    [Fact]
    public async Task GetSigningKeysAsync_loads_the_certificate_and_returns_its_public_key()
    {
        var ct = TestContext.Current.CancellationToken;
        using var tempDir = new TempSigningKeyDirectory();
        using var certificate = TestCertificateFactory.CreateRsaSelfSigned("test", T0 - TimeSpan.FromDays(1), T0 + TimeSpan.FromDays(365));
        var path = tempDir.WritePemFile("key.pem", certificate);
        await using var sut = BuildService(path, new FakeTimeProvider(T0));

        var keys = await sut.GetSigningKeysAsync(ct);

        keys.Should().ContainSingle();
        keys[0].KeyType.Should().Be(SigningKeyType.Rsa);
        keys[0].RsaPublicParameters.Should().NotBeNull("only the public key may ever be exposed via the descriptor");
        keys[0].Algorithm.Should().Be(SigningAlgorithm.RS256);
    }

    [Fact]
    public async Task SignAsync_signs_with_the_loaded_certificates_private_key()
    {
        var ct = TestContext.Current.CancellationToken;
        using var tempDir = new TempSigningKeyDirectory();
        using var certificate = TestCertificateFactory.CreateRsaSelfSigned("test", T0 - TimeSpan.FromDays(1), T0 + TimeSpan.FromDays(365));
        var path = tempDir.WritePemFile("key.pem", certificate);
        await using var sut = BuildService(path, new FakeTimeProvider(T0));
        var payloadSegment = SigningTestHelpers.Base64UrlEncode("{\"sub\":\"test-subject\"}"u8.ToArray());

        var result = await sut.SignAsync(payloadSegment, ct);
        var keys = await sut.GetSigningKeysAsync(ct);
        var descriptor = keys.Single(k => k.Kid == result.Kid);

        SigningTestHelpers.VerifyRsaSignature(descriptor, result, payloadSegment).Should().BeTrue(
            "the signature must verify against the same certificate's public key");
    }

    // ── Missing file (AC #14) ────────────────────────────────────────────────────────────────────

    [Fact]
    public async Task GetSigningKeysAsync_throws_ZeeKayDaConfigurationException_when_the_file_does_not_exist()
    {
        var ct = TestContext.Current.CancellationToken;
        using var tempDir = new TempSigningKeyDirectory();
        var missingPath = tempDir.GetPath("does-not-exist.pem");
        await using var sut = BuildService(missingPath, new FakeTimeProvider(T0));

        var act = async () => await sut.GetSigningKeysAsync(ct);

        var exception = await act.Should().ThrowAsync<ZeeKayDaConfigurationException>();
        exception.Which.AggregatedFailures.Should().ContainSingle(f => f.Code == "signing.file_signing.file_not_found");
        exception.Which.Message.Should().Contain(missingPath);
    }

    // ── Invalid PEM content (AC #3) ──────────────────────────────────────────────────────────────

    [Fact]
    public async Task GetSigningKeysAsync_throws_ZeeKayDaConfigurationException_for_invalid_PEM_content()
    {
        var ct = TestContext.Current.CancellationToken;
        using var tempDir = new TempSigningKeyDirectory();
        var path = tempDir.WriteTextFile("key.pem", "this is not a valid PEM file");
        await using var sut = BuildService(path, new FakeTimeProvider(T0));

        var act = async () => await sut.GetSigningKeysAsync(ct);

        var exception = await act.Should().ThrowAsync<ZeeKayDaConfigurationException>();
        exception.Which.AggregatedFailures.Should().ContainSingle(f => f.Code == "signing.file_signing.invalid_pem");
    }

    // ── Permission enforcement (AC #2) ───────────────────────────────────────────────────────────

    [Fact]
    public async Task GetSigningKeysAsync_throws_when_the_file_is_broader_than_0600_on_Unix()
    {
        Assert.SkipWhen(OperatingSystem.IsWindows(), "0600-mode enforcement is the Unix permission model.");

        var ct = TestContext.Current.CancellationToken;
        using var tempDir = new TempSigningKeyDirectory();
        using var certificate = TestCertificateFactory.CreateRsaSelfSigned("test", T0 - TimeSpan.FromDays(1), T0 + TimeSpan.FromDays(365));
        var path = tempDir.WritePemFile("key.pem", certificate);
        tempDir.MakeTooPermissive(path);
        await using var sut = BuildService(path, new FakeTimeProvider(T0));

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
        var path = tempDir.WritePemFile("key.pem", certificate);
        tempDir.MakeTooPermissive(path);
        await using var sut = BuildService(path, new FakeTimeProvider(T0));

        var act = async () => await sut.GetSigningKeysAsync(ct);

        var exception = await act.Should().ThrowAsync<ZeeKayDaConfigurationException>();
        exception.Which.AggregatedFailures.Should().ContainSingle(f => f.Code == "signing.file_signing.file_too_permissive");
    }

    [Fact]
    public async Task GetSigningKeysAsync_succeeds_when_the_file_is_secured_to_the_current_identity()
    {
        // Positive counterpart to the two permission tests above: proves the default fixture output
        // (what a correctly-configured operator deployment looks like) is accepted on every OS.
        var ct = TestContext.Current.CancellationToken;
        using var tempDir = new TempSigningKeyDirectory();
        using var certificate = TestCertificateFactory.CreateRsaSelfSigned("test", T0 - TimeSpan.FromDays(1), T0 + TimeSpan.FromDays(365));
        var path = tempDir.WritePemFile("key.pem", certificate);
        await using var sut = BuildService(path, new FakeTimeProvider(T0));

        var act = async () => await sut.GetSigningKeysAsync(ct);

        await act.Should().NotThrowAsync();
    }

    // ── Symlink rejection ─────────────────────────────────────────────────────────────────────────

    [Fact]
    public async Task GetSigningKeysAsync_throws_when_the_registered_path_is_a_symlink()
    {
        var ct = TestContext.Current.CancellationToken;
        using var tempDir = new TempSigningKeyDirectory();
        using var certificate = TestCertificateFactory.CreateRsaSelfSigned("test", T0 - TimeSpan.FromDays(1), T0 + TimeSpan.FromDays(365));
        var realPath = tempDir.WritePemFile("real.pem", certificate);
        var symlinkPath = tempDir.GetPath("link.pem");

        try
        {
            File.CreateSymbolicLink(symlinkPath, realPath);
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            Assert.Skip("Creating a symlink requires elevated privileges/Developer Mode on this platform.");
            return;
        }

        await using var sut = BuildService(symlinkPath, new FakeTimeProvider(T0));

        var act = async () => await sut.GetSigningKeysAsync(ct);

        var exception = await act.Should().ThrowAsync<ZeeKayDaConfigurationException>();
        exception.Which.AggregatedFailures.Should().ContainSingle(f => f.Code == "signing.file_signing.symlink_detected");
    }

    // ── Split cert/key files (issue #405) ────────────────────────────────────────────────────────

    [Fact]
    public async Task GetSigningKeysAsync_loads_the_certificate_from_separate_cert_and_key_files()
    {
        var ct = TestContext.Current.CancellationToken;
        using var tempDir = new TempSigningKeyDirectory();
        using var certificate = TestCertificateFactory.CreateRsaSelfSigned("test", T0 - TimeSpan.FromDays(1), T0 + TimeSpan.FromDays(365));
        var certPath = tempDir.WriteCertificateOnlyPemFile("cert.pem", certificate);
        var keyPath = tempDir.WriteKeyOnlyPemFile("key.pem", certificate);
        await using var sut = BuildService(certPath, new FakeTimeProvider(T0), keyPath: keyPath);

        var keys = await sut.GetSigningKeysAsync(ct);

        keys.Should().ContainSingle();
        keys[0].KeyType.Should().Be(SigningKeyType.Rsa);
    }

    [Fact]
    public async Task SignAsync_signs_with_the_private_key_from_the_separately_registered_key_file()
    {
        var ct = TestContext.Current.CancellationToken;
        using var tempDir = new TempSigningKeyDirectory();
        using var certificate = TestCertificateFactory.CreateRsaSelfSigned("test", T0 - TimeSpan.FromDays(1), T0 + TimeSpan.FromDays(365));
        var certPath = tempDir.WriteCertificateOnlyPemFile("cert.pem", certificate);
        var keyPath = tempDir.WriteKeyOnlyPemFile("key.pem", certificate);
        await using var sut = BuildService(certPath, new FakeTimeProvider(T0), keyPath: keyPath);
        var payloadSegment = SigningTestHelpers.Base64UrlEncode("{\"sub\":\"test-subject\"}"u8.ToArray());

        var result = await sut.SignAsync(payloadSegment, ct);
        var keys = await sut.GetSigningKeysAsync(ct);
        var descriptor = keys.Single(k => k.Kid == result.Kid);

        SigningTestHelpers.VerifyRsaSignature(descriptor, result, payloadSegment).Should().BeTrue(
            "the signature must verify against the certificate's public key even though the private " +
            "key came from a separately-registered file");
    }

    [Fact]
    public async Task GetSigningKeysAsync_throws_when_the_separately_registered_key_file_is_broader_than_0600_on_Unix()
    {
        Assert.SkipWhen(OperatingSystem.IsWindows(), "0600-mode enforcement is the Unix permission model.");

        var ct = TestContext.Current.CancellationToken;
        using var tempDir = new TempSigningKeyDirectory();
        using var certificate = TestCertificateFactory.CreateRsaSelfSigned("test", T0 - TimeSpan.FromDays(1), T0 + TimeSpan.FromDays(365));
        var certPath = tempDir.WriteCertificateOnlyPemFile("cert.pem", certificate);
        var keyPath = tempDir.WriteKeyOnlyPemFile("key.pem", certificate);
        tempDir.MakeTooPermissive(keyPath); // Widen only the separate key file, not the cert file.
        await using var sut = BuildService(certPath, new FakeTimeProvider(T0), keyPath: keyPath);

        var act = async () => await sut.GetSigningKeysAsync(ct);

        var exception = await act.Should().ThrowAsync<ZeeKayDaConfigurationException>();
        exception.Which.AggregatedFailures.Should().ContainSingle(f => f.Code == "signing.file_signing.file_too_permissive");
    }

    [Fact]
    public async Task GetSigningKeysAsync_throws_when_the_separately_registered_key_files_ACL_grants_a_broad_principal_on_Windows()
    {
        Assert.SkipUnless(OperatingSystem.IsWindows(), "broad-principal ACL enforcement is the Windows permission model.");

        var ct = TestContext.Current.CancellationToken;
        using var tempDir = new TempSigningKeyDirectory();
        using var certificate = TestCertificateFactory.CreateRsaSelfSigned("test", T0 - TimeSpan.FromDays(1), T0 + TimeSpan.FromDays(365));
        var certPath = tempDir.WriteCertificateOnlyPemFile("cert.pem", certificate);
        var keyPath = tempDir.WriteKeyOnlyPemFile("key.pem", certificate);
        tempDir.MakeTooPermissive(keyPath); // Widen only the separate key file, not the cert file.
        await using var sut = BuildService(certPath, new FakeTimeProvider(T0), keyPath: keyPath);

        var act = async () => await sut.GetSigningKeysAsync(ct);

        var exception = await act.Should().ThrowAsync<ZeeKayDaConfigurationException>();
        exception.Which.AggregatedFailures.Should().ContainSingle(f => f.Code == "signing.file_signing.file_too_permissive");
    }

    [Fact]
    public async Task GetSigningKeysAsync_throws_when_the_separately_registered_key_file_does_not_exist()
    {
        var ct = TestContext.Current.CancellationToken;
        using var tempDir = new TempSigningKeyDirectory();
        using var certificate = TestCertificateFactory.CreateRsaSelfSigned("test", T0 - TimeSpan.FromDays(1), T0 + TimeSpan.FromDays(365));
        var certPath = tempDir.WriteCertificateOnlyPemFile("cert.pem", certificate);
        var missingKeyPath = tempDir.GetPath("does-not-exist.key");
        await using var sut = BuildService(certPath, new FakeTimeProvider(T0), keyPath: missingKeyPath);

        var act = async () => await sut.GetSigningKeysAsync(ct);

        var exception = await act.Should().ThrowAsync<ZeeKayDaConfigurationException>();
        exception.Which.AggregatedFailures.Should().ContainSingle(f => f.Code == "signing.file_signing.file_not_found");
    }

    // ── Multi-file rotation via AddFile (AC #9/#10) ──────────────────────────────────────────────
    //
    // ADR 0015 Tier A: ListKeysAsync runs exactly once and builds one immutable snapshot/timeline;
    // active-key selection is then recomputed lazily against the wall clock on every call, with zero
    // further file I/O — so a rotation between already-known files still switches the active signer
    // purely from elapsed time.

    [Fact]
    public async Task GetSigningKeysAsync_exposes_both_files_during_a_rotation_overlap()
    {
        var ct = TestContext.Current.CancellationToken;
        using var tempDir = new TempSigningKeyDirectory();
        using var predecessor = TestCertificateFactory.CreateRsaSelfSigned("predecessor", T0 - TimeSpan.FromDays(30), T0 + TimeSpan.FromDays(365));
        var successorNotBefore = T0 + TimeSpan.FromDays(1);
        using var successor = TestCertificateFactory.CreateRsaSelfSigned("successor", successorNotBefore, T0 + TimeSpan.FromDays(400));
        var predecessorPath = tempDir.WritePemFile("predecessor.pem", predecessor);
        var successorPath = tempDir.WritePemFile("successor.pem", successor);
        var timeProvider = new FakeTimeProvider(T0);
        await using var sut = BuildService(predecessorPath, timeProvider, [successorPath]);

        var keys = await sut.GetSigningKeysAsync(ct);

        keys.Should().HaveCount(2, "AC #9: both files must be exposed during the overlap window");
    }

    [Fact]
    public async Task GetSigningKeysAsync_active_signer_switches_when_the_successors_NotBefore_arrives()
    {
        var ct = TestContext.Current.CancellationToken;
        using var tempDir = new TempSigningKeyDirectory();
        using var predecessor = TestCertificateFactory.CreateRsaSelfSigned("predecessor", T0 - TimeSpan.FromDays(30), T0 + TimeSpan.FromDays(365));
        var successorNotBefore = T0 + TimeSpan.FromDays(1);
        using var successor = TestCertificateFactory.CreateRsaSelfSigned("successor", successorNotBefore, T0 + TimeSpan.FromDays(400));
        var predecessorPath = tempDir.WritePemFile("predecessor.pem", predecessor);
        var successorPath = tempDir.WritePemFile("successor.pem", successor);
        var timeProvider = new FakeTimeProvider(T0);
        await using var sut = BuildService(predecessorPath, timeProvider, [successorPath]);

        var before = await sut.GetSigningKeysAsync(ct);
        before[0].Kid.Should().Be(JwkThumbprint.Compute(predecessor.GetRSAPublicKey()!.ExportParameters(false)),
            "AC #10: predecessor is active before the successor's NotBefore arrives");

        timeProvider.SetUtcNow(successorNotBefore);
        var after = await sut.GetSigningKeysAsync(ct);
        after[0].Kid.Should().Be(JwkThumbprint.Compute(successor.GetRSAPublicKey()!.ExportParameters(false)),
            "AC #10: successor becomes active once its NotBefore arrives, with zero further file I/O " +
            "(ListKeysAsync already ran exactly once)");
    }

    // ── Per-file status logging at the single ListKeysAsync evaluation ──────────────────────────

    [Fact]
    public async Task GetSigningKeysAsync_excludes_a_predecessor_whose_retirement_window_had_already_elapsed_at_startup()
    {
        var ct = TestContext.Current.CancellationToken;
        var retirementWindow = TimeSpan.FromHours(1);
        using var tempDir = new TempSigningKeyDirectory();
        using var predecessor = TestCertificateFactory.CreateRsaSelfSigned("predecessor", T0 - TimeSpan.FromDays(60), T0 + TimeSpan.FromDays(365));
        using var successor = TestCertificateFactory.CreateRsaSelfSigned("successor", T0 - TimeSpan.FromDays(10), T0 + TimeSpan.FromDays(400));
        var predecessorPath = tempDir.WritePemFile("predecessor.pem", predecessor);
        var successorPath = tempDir.WritePemFile("successor.pem", successor);
        await using var sut = BuildService(predecessorPath, new FakeTimeProvider(T0), [successorPath], retirementWindow: retirementWindow);

        var keys = await sut.GetSigningKeysAsync(ct);

        keys.Should().ContainSingle(
            "the predecessor's retirement window (relative to the successor's activation 10 days ago) " +
            "had already fully elapsed by the single ListKeysAsync evaluation at startup");
        keys[0].Kid.Should().Be(JwkThumbprint.Compute(successor.GetRSAPublicKey()!.ExportParameters(false)));
    }

    [Fact]
    public async Task GetSigningKeysAsync_includes_a_predecessor_still_within_its_retirement_window_at_startup()
    {
        var ct = TestContext.Current.CancellationToken;
        var retirementWindow = TimeSpan.FromHours(1);
        using var tempDir = new TempSigningKeyDirectory();
        using var predecessor = TestCertificateFactory.CreateRsaSelfSigned("predecessor", T0 - TimeSpan.FromDays(30), T0 + TimeSpan.FromDays(365));
        using var successor = TestCertificateFactory.CreateRsaSelfSigned("successor", T0 - TimeSpan.FromMinutes(10), T0 + TimeSpan.FromDays(400));
        var predecessorPath = tempDir.WritePemFile("predecessor.pem", predecessor);
        var successorPath = tempDir.WritePemFile("successor.pem", successor);
        await using var sut = BuildService(predecessorPath, new FakeTimeProvider(T0), [successorPath], retirementWindow: retirementWindow);

        var keys = await sut.GetSigningKeysAsync(ct);

        keys.Should().HaveCount(2,
            "the successor activated 10 minutes ago, so the predecessor is retired but still within " +
            "its 1-hour retirement window at the single ListKeysAsync evaluation at startup");
    }

    // ── Single-file bootstrap exemption (AC #11) ─────────────────────────────────────────────────

    [Fact]
    public async Task GetSigningKeysAsync_the_sole_registered_file_is_active_immediately_despite_a_future_NotBefore()
    {
        var ct = TestContext.Current.CancellationToken;
        using var tempDir = new TempSigningKeyDirectory();
        using var certificate = TestCertificateFactory.CreateRsaSelfSigned("test", T0 + TimeSpan.FromDays(30), T0 + TimeSpan.FromDays(365));
        var path = tempDir.WritePemFile("key.pem", certificate);
        await using var sut = BuildService(path, new FakeTimeProvider(T0));

        var act = async () => await sut.GetSigningKeysAsync(ct);

        await act.Should().NotThrowAsync("AC #11: the bootstrap exemption activates the sole file immediately");
    }

    // ── Every registered certificate already expired at startup ─────────────────────────────────
    //
    // ADR 0015 Security Considerations item 6: Tier A never re-reads, so an already-(or
    // eventually-)expired sole key with no eligible successor drifts to (or starts as)
    // SelectActiveKey == null and signing fails closed at request time via the base class's own
    // generic "signing.no_active_key" error — there is no provider-specific "no active certificate"
    // special case any more, since ListKeysAsync no longer owns "is this configuration currently
    // usable," only "what keys exist."

    [Fact]
    public async Task GetSigningKeysAsync_throws_the_base_classes_no_active_key_error_when_every_registered_certificate_has_expired()
    {
        var ct = TestContext.Current.CancellationToken;
        using var tempDir = new TempSigningKeyDirectory();
        using var certificate = TestCertificateFactory.CreateRsaSelfSigned("test", T0 - TimeSpan.FromDays(30), T0 - TimeSpan.FromDays(1));
        var path = tempDir.WritePemFile("key.pem", certificate);
        await using var sut = BuildService(path, new FakeTimeProvider(T0));

        var act = async () => await sut.GetSigningKeysAsync(ct);

        var exception = await act.Should().ThrowAsync<ZeeKayDaConfigurationException>();
        exception.Which.AggregatedFailures.Should().ContainSingle(f => f.Code == "signing.no_active_key");
    }

    // ── Too-soon-NotBefore startup warning (ADR 0015 §1, issue #422) ─────────────────────────────

    [Fact]
    public async Task GetSigningKeysAsync_logs_a_warning_when_the_soonest_pending_NotBefore_is_closer_than_PublicationLead()
    {
        var ct = TestContext.Current.CancellationToken;
        using var tempDir = new TempSigningKeyDirectory();
        using var primary = TestCertificateFactory.CreateRsaSelfSigned("primary", T0 - TimeSpan.FromDays(30), T0 + TimeSpan.FromDays(365));
        using var secondary = TestCertificateFactory.CreateRsaSelfSigned("secondary", T0 + TimeSpan.FromMinutes(1), T0 + TimeSpan.FromDays(400));
        var primaryPath = tempDir.WritePemFile("primary.pem", primary);
        var secondaryPath = tempDir.WritePemFile("secondary.pem", secondary);
        var logger = new CapturingSanitizingLogger<JwtSigningService<PemFileSigningOptions>>();
        await using var sut = BuildService(primaryPath, new FakeTimeProvider(T0), [secondaryPath], logger: logger);

        await sut.GetSigningKeysAsync(ct);

        logger.Entries.Should().Contain(e => e.Level == LogLevel.Warning,
            "the too-soon-NotBefore misconfiguration must be surfaced (default PublicationLead is 1 hour)");
    }

    [Fact]
    public async Task GetSigningKeysAsync_does_not_warn_when_an_explicit_shorter_PublicationLead_is_satisfied()
    {
        // The gap between primary's activation and secondary's NotBefore is 1 minute — shorter than
        // the default 1-hour PublicationLead, which would trigger the warning if PublicationLead
        // were left at its default. Setting an explicit, shorter PublicationLead (30 seconds) that
        // the 1-minute gap satisfies proves the explicit value is actually what feeds
        // HasTooSoonPendingActivation, not merely the default.
        var ct = TestContext.Current.CancellationToken;
        using var tempDir = new TempSigningKeyDirectory();
        using var primary = TestCertificateFactory.CreateRsaSelfSigned("primary", T0 - TimeSpan.FromDays(30), T0 + TimeSpan.FromDays(365));
        using var secondary = TestCertificateFactory.CreateRsaSelfSigned("secondary", T0 + TimeSpan.FromMinutes(1), T0 + TimeSpan.FromDays(400));
        var primaryPath = tempDir.WritePemFile("primary.pem", primary);
        var secondaryPath = tempDir.WritePemFile("secondary.pem", secondary);
        var logger = new CapturingSanitizingLogger<JwtSigningService<PemFileSigningOptions>>();
        await using var sut = BuildService(
            primaryPath, new FakeTimeProvider(T0), [secondaryPath],
            publicationLead: TimeSpan.FromSeconds(30), logger: logger);

        await sut.GetSigningKeysAsync(ct);

        logger.Entries.Should().NotContain(e => e.Level == LogLevel.Warning,
            "the explicit PublicationLead (30s) is shorter than the 1-minute activation gap, so no " +
            "warning should fire even though the 1-hour default would have");
    }

    [Fact]
    public async Task GetSigningKeysAsync_warns_when_an_explicit_longer_PublicationLead_is_not_satisfied()
    {
        var ct = TestContext.Current.CancellationToken;
        using var tempDir = new TempSigningKeyDirectory();
        using var primary = TestCertificateFactory.CreateRsaSelfSigned("primary", T0 - TimeSpan.FromDays(30), T0 + TimeSpan.FromDays(365));
        using var secondary = TestCertificateFactory.CreateRsaSelfSigned("secondary", T0 + TimeSpan.FromMinutes(10), T0 + TimeSpan.FromDays(400));
        var primaryPath = tempDir.WritePemFile("primary.pem", primary);
        var secondaryPath = tempDir.WritePemFile("secondary.pem", secondary);
        var logger = new CapturingSanitizingLogger<JwtSigningService<PemFileSigningOptions>>();
        await using var sut = BuildService(
            primaryPath, new FakeTimeProvider(T0), [secondaryPath],
            publicationLead: TimeSpan.FromMinutes(15), logger: logger);

        await sut.GetSigningKeysAsync(ct);

        logger.Entries.Should().Contain(e => e.Level == LogLevel.Warning,
            "the explicit PublicationLead (15 minutes) is longer than the 10-minute activation gap, so " +
            "the warning must fire");
    }

    // ── kid stability ─────────────────────────────────────────────────────────────────────────────

    [Fact]
    public async Task GetSigningKeysAsync_kid_is_stable_across_multiple_calls()
    {
        var ct = TestContext.Current.CancellationToken;
        using var tempDir = new TempSigningKeyDirectory();
        using var certificate = TestCertificateFactory.CreateRsaSelfSigned("test", T0 - TimeSpan.FromDays(1), T0 + TimeSpan.FromDays(365));
        var path = tempDir.WritePemFile("key.pem", certificate);
        var timeProvider = new FakeTimeProvider(T0);
        await using var sut = BuildService(path, timeProvider);

        var first = await sut.GetSigningKeysAsync(ct);
        timeProvider.Advance(TimeSpan.FromDays(365));
        var second = await sut.GetSigningKeysAsync(ct);

        second[0].Kid.Should().Be(first[0].Kid,
            "kid must be derived from the key material; ListKeysAsync runs exactly once for this " +
            "ADR 0015 Tier A provider regardless of elapsed time");
    }

    // ── Algorithm/key-type mismatch ───────────────────────────────────────────────────────────────

    [Fact]
    public async Task GetSigningKeysAsync_throws_when_Algorithm_does_not_match_the_certificates_key_type()
    {
        var ct = TestContext.Current.CancellationToken;
        using var tempDir = new TempSigningKeyDirectory();
        using var certificate = TestCertificateFactory.CreateRsaSelfSigned("test", T0 - TimeSpan.FromDays(1), T0 + TimeSpan.FromDays(365));
        var path = tempDir.WritePemFile("key.pem", certificate);
        await using var sut = BuildService(path, new FakeTimeProvider(T0), algorithm: SigningAlgorithm.ES256);

        var act = async () => await sut.GetSigningKeysAsync(ct);

        var exception = await act.Should().ThrowAsync<ZeeKayDaConfigurationException>();
        exception.Which.AggregatedFailures.Should().ContainSingle(f => f.Code == "signing.file_signing.algorithm_key_type_mismatch");
    }

    [Fact]
    public async Task GetSigningKeysAsync_supports_EC_certificates_with_a_matching_EC_algorithm()
    {
        var ct = TestContext.Current.CancellationToken;
        using var tempDir = new TempSigningKeyDirectory();
        using var certificate = TestCertificateFactory.CreateEcSelfSigned("test", T0 - TimeSpan.FromDays(1), T0 + TimeSpan.FromDays(365));
        var path = tempDir.WritePemFile("key.pem", certificate);
        await using var sut = BuildService(path, new FakeTimeProvider(T0), algorithm: SigningAlgorithm.ES256);

        var keys = await sut.GetSigningKeysAsync(ct);

        keys.Should().ContainSingle();
        keys[0].KeyType.Should().Be(SigningKeyType.Ec);
        keys[0].EcPublicParameters.Should().NotBeNull();
    }

    [Fact]
    public async Task SignAsync_signs_with_an_EC_certificates_private_key()
    {
        // ADR 0015 §2/§5's least-privilege loading means CreateSignerAsync (and therefore an EC
        // private-key extraction) is only ever invoked by a real SignAsync call, never by
        // GetSigningKeysAsync alone — this exercises that path directly.
        var ct = TestContext.Current.CancellationToken;
        using var tempDir = new TempSigningKeyDirectory();
        using var certificate = TestCertificateFactory.CreateEcSelfSigned("test", T0 - TimeSpan.FromDays(1), T0 + TimeSpan.FromDays(365));
        var path = tempDir.WritePemFile("key.pem", certificate);
        await using var sut = BuildService(path, new FakeTimeProvider(T0), algorithm: SigningAlgorithm.ES256);
        var payloadSegment = SigningTestHelpers.Base64UrlEncode("{\"sub\":\"test-subject\"}"u8.ToArray());

        var result = await sut.SignAsync(payloadSegment, ct);

        result.Kid.Should().NotBeNullOrEmpty();
        result.Algorithm.Should().Be(SigningAlgorithm.ES256);
    }

    [Fact]
    public async Task GetSigningKeysAsync_throws_when_Algorithm_is_RSA_but_the_certificate_is_EC()
    {
        // The RSA-mismatch direction is covered above; this covers the other half of
        // BuildValidatedPublicKey's mismatch-message branch.
        var ct = TestContext.Current.CancellationToken;
        using var tempDir = new TempSigningKeyDirectory();
        using var certificate = TestCertificateFactory.CreateEcSelfSigned("test", T0 - TimeSpan.FromDays(1), T0 + TimeSpan.FromDays(365));
        var path = tempDir.WritePemFile("key.pem", certificate);
        await using var sut = BuildService(path, new FakeTimeProvider(T0), algorithm: SigningAlgorithm.RS256);

        var act = async () => await sut.GetSigningKeysAsync(ct);

        var exception = await act.Should().ThrowAsync<ZeeKayDaConfigurationException>();
        exception.Which.AggregatedFailures.Should().ContainSingle(f => f.Code == "signing.file_signing.algorithm_key_type_mismatch");
        exception.Which.Message.Should().Contain("EC certificate");
    }

    // ── Logging: never leaks key material (issue #291's explicit requirement) ───────────────────

    [Fact]
    public async Task GetSigningKeysAsync_logs_path_key_type_and_key_size_but_never_key_material()
    {
        var ct = TestContext.Current.CancellationToken;
        using var tempDir = new TempSigningKeyDirectory();
        using var certificate = TestCertificateFactory.CreateRsaSelfSigned("test", T0 - TimeSpan.FromDays(1), T0 + TimeSpan.FromDays(365), keySizeBits: 2048);
        var path = tempDir.WritePemFile("key.pem", certificate);
        var logger = new CapturingSanitizingLogger<JwtSigningService<PemFileSigningOptions>>();
        await using var sut = BuildService(path, new FakeTimeProvider(T0), logger: logger);

        await sut.GetSigningKeysAsync(ct);

        logger.Entries.Should().ContainSingle(e => e.Level == LogLevel.Information
            && e.Message.Contains(path)
            && e.Message.Contains("RSA")
            && e.Message.Contains("2048"));
        logger.Entries.Should().NotContain(e => e.Message.Contains("BEGIN") || e.Message.Contains("PRIVATE KEY"),
            "no PEM block or key material may ever reach a log line");
    }

    // ── Expiring-soon warning ─────────────────────────────────────────────────────────────────────

    [Fact]
    public async Task GetSigningKeysAsync_warns_when_the_active_certificate_expires_within_30_days()
    {
        var ct = TestContext.Current.CancellationToken;
        using var tempDir = new TempSigningKeyDirectory();
        using var certificate = TestCertificateFactory.CreateRsaSelfSigned("test", T0 - TimeSpan.FromDays(1), T0 + TimeSpan.FromDays(10));
        var path = tempDir.WritePemFile("key.pem", certificate);
        var logger = new CapturingSanitizingLogger<JwtSigningService<PemFileSigningOptions>>();
        await using var sut = BuildService(path, new FakeTimeProvider(T0), logger: logger);

        await sut.GetSigningKeysAsync(ct);

        logger.Entries.Should().Contain(e => e.Level == LogLevel.Warning && e.Message.Contains("expires"),
            "the active certificate expiring within 30 days must be surfaced");
    }

    // ── Defensive invariant: CreateSignerAsync is only ever called for a listed key ─────────────
    //
    // Unreachable via the public API in normal operation — the base class only ever calls
    // CreateSignerAsync with a KeyId it previously observed on a ListKeysAsync-returned KeyListing,
    // and this ADR 0015 Tier A provider's registered files never change after startup — but invoked
    // directly via reflection here to prove the defensive check fails loudly rather than silently,
    // should that invariant ever be violated (e.g. a future base-class bug).

    [Fact]
    public async Task CreateSignerAsync_throws_when_called_for_a_key_id_that_is_not_a_registered_file()
    {
        var ct = TestContext.Current.CancellationToken;
        using var tempDir = new TempSigningKeyDirectory();
        using var certificate = TestCertificateFactory.CreateRsaSelfSigned("test", T0 - TimeSpan.FromDays(1), T0 + TimeSpan.FromDays(365));
        var path = tempDir.WritePemFile("key.pem", certificate);
        await using var sut = BuildService(path, new FakeTimeProvider(T0));

        var createSignerAsync = typeof(PemFileSigningJwtSigningService).GetMethod(
            "CreateSignerAsync", BindingFlags.NonPublic | BindingFlags.Instance)!;

        // An async method's exceptions (even ones thrown before its first await) are captured into
        // the returned ValueTask by the compiler-generated state machine, not thrown synchronously
        // from Invoke — so the faulted task is awaited here rather than expecting Invoke itself to throw.
        var task = (ValueTask<ISigner>)createSignerAsync.Invoke(sut, [new KeyId("/no/such/file.pem"), ct])!;
        var act = async () => await task;

        await act.Should().ThrowAsync<InvalidOperationException>();
    }
}
