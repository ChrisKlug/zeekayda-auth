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
public sealed class PemFileSigningJwtSigningServiceTests
{
    private static readonly DateTimeOffset T0 = DateTimeOffset.Parse("2026-01-01T00:00:00Z");

    private static PemFileSigningJwtSigningService BuildService(
        string primaryPath,
        FakeTimeProvider timeProvider,
        IReadOnlyList<string>? additionalPaths = null,
        TimeSpan? refreshInterval = null,
        TimeSpan? retirementWindow = null,
        SigningAlgorithm algorithm = SigningAlgorithm.RS256,
        string? keyPath = null,
        ISanitizingLogger<FileSigningJwtSigningService<PemFileSigningOptions>>? logger = null)
    {
        var options = new PemFileSigningOptions
        {
            Path = primaryPath,
            KeyPath = keyPath,
            Algorithm = algorithm,
            KeySourceRefreshInterval = refreshInterval ?? TimeSpan.FromMinutes(5),
        };
        foreach (var additional in additionalPaths ?? [])
            options.AddFile(additional);

        return new PemFileSigningJwtSigningService(
            Options.Create(options),
            timeProvider,
            new FileSigningKeyReader(NullSanitizingLogger<FileSigningKeyReader>.Instance),
            new FakeRetirementWindowProvider(retirementWindow ?? TimeSpan.FromHours(1)),
            logger ?? NullSanitizingLogger<FileSigningJwtSigningService<PemFileSigningOptions>>.Instance);
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

    [Fact]
    public async Task GetSigningKeysAsync_reloads_when_only_the_separately_registered_key_files_mtime_changes()
    {
        var ct = TestContext.Current.CancellationToken;
        var refreshInterval = TimeSpan.FromMinutes(5);
        using var tempDir = new TempSigningKeyDirectory();
        using var certificate = TestCertificateFactory.CreateRsaSelfSigned("test", T0 - TimeSpan.FromDays(1), T0 + TimeSpan.FromDays(365));
        var certPath = tempDir.WriteCertificateOnlyPemFile("cert.pem", certificate);
        var keyPath = tempDir.WriteKeyOnlyPemFile("key.pem", certificate);
        var timeProvider = new FakeTimeProvider(T0);
        await using var sut = BuildService(certPath, timeProvider, keyPath: keyPath, refreshInterval: refreshInterval);

        await sut.GetSigningKeysAsync(ct); // Bootstrap load.

        // Corrupts only the separately-registered key file's content (the certificate file's mtime
        // is untouched) — mirroring cert-manager's "rotate privkey.pem, leave fullchain.pem alone"
        // pattern. If HasKeySetChangedAsync only tracked the certificate path's mtime (missing the
        // companion key path), this corruption would go undetected and the stale-but-valid keys
        // would keep being served instead of the load failing on the corrupted key file.
        File.WriteAllText(keyPath, "this is not a valid PEM file");
        timeProvider.SetUtcNow(T0 + refreshInterval);

        var act = async () => await sut.GetSigningKeysAsync(ct);

        var exception = await act.Should().ThrowAsync<ZeeKayDaConfigurationException>(
            "the separately-registered key file's mtime change must be detected and force a reread, " +
            "which then fails on the now-corrupted content");
        exception.Which.AggregatedFailures.Should().ContainSingle(f => f.Code == "signing.file_signing.invalid_pem");
    }

    [Fact]
    public async Task HasKeySetChangedAsync_reports_a_change_when_only_the_separately_registered_key_files_mtime_changes()
    {
        var ct = TestContext.Current.CancellationToken;
        var refreshInterval = TimeSpan.FromMinutes(5);
        using var tempDir = new TempSigningKeyDirectory();
        using var original = TestCertificateFactory.CreateRsaSelfSigned("original", T0 - TimeSpan.FromDays(1), T0 + TimeSpan.FromDays(365));
        using var replacement = TestCertificateFactory.CreateRsaSelfSigned("replacement", T0 - TimeSpan.FromDays(1), T0 + TimeSpan.FromDays(365));
        var certPath = tempDir.WriteCertificateOnlyPemFile("cert.pem", original);
        var keyPath = tempDir.WriteKeyOnlyPemFile("key.pem", original);
        var timeProvider = new FakeTimeProvider(T0);
        await using var sut = BuildService(certPath, timeProvider, keyPath: keyPath, refreshInterval: refreshInterval);

        var first = await sut.GetSigningKeysAsync(ct);

        // Only the certificate file is rewritten (with a different key pair) — the separately
        // registered key file's mtime is left untouched by this write. A correct implementation must
        // still detect the certificate path's own mtime change; this test's sibling above proves the
        // reverse (only the key file's mtime changing is also detected).
        tempDir.WriteCertificateOnlyPemFile("cert.pem", replacement);
        tempDir.WriteKeyOnlyPemFile("key.pem", replacement); // A cert file needs its matching key to load successfully.
        timeProvider.SetUtcNow(T0 + refreshInterval);

        var second = await sut.GetSigningKeysAsync(ct);

        second[0].Kid.Should().NotBe(first[0].Kid,
            "the certificate file's content (and mtime) changed, so HasKeySetChangedAsync must report " +
            "a change and LoadKeysAsync must reread and reparse it");
    }

    // ── Multi-file rotation via AddFile (AC #9/#10) ──────────────────────────────────────────────

    [Fact]
    public async Task GetSigningKeysAsync_exposes_both_files_during_a_rotation_overlap()
    {
        var ct = TestContext.Current.CancellationToken;
        var refreshInterval = TimeSpan.FromMinutes(5);
        using var tempDir = new TempSigningKeyDirectory();
        using var predecessor = TestCertificateFactory.CreateRsaSelfSigned("predecessor", T0 - TimeSpan.FromDays(30), T0 + TimeSpan.FromDays(365));
        var successorNotBefore = T0 + TimeSpan.FromDays(1);
        using var successor = TestCertificateFactory.CreateRsaSelfSigned("successor", successorNotBefore, T0 + TimeSpan.FromDays(400));
        var predecessorPath = tempDir.WritePemFile("predecessor.pem", predecessor);
        var successorPath = tempDir.WritePemFile("successor.pem", successor);
        var timeProvider = new FakeTimeProvider(T0);
        await using var sut = BuildService(predecessorPath, timeProvider, [successorPath], refreshInterval: refreshInterval);

        var keys = await sut.GetSigningKeysAsync(ct);

        keys.Should().HaveCount(2, "AC #9: both files must be exposed during the overlap window");
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
        var predecessorPath = tempDir.WritePemFile("predecessor.pem", predecessor);
        var successorPath = tempDir.WritePemFile("successor.pem", successor);
        var timeProvider = new FakeTimeProvider(T0);
        await using var sut = BuildService(predecessorPath, timeProvider, [successorPath], refreshInterval: refreshInterval);

        var before = await sut.GetSigningKeysAsync(ct);
        before[0].Kid.Should().Be(JwkThumbprint.Compute(predecessor.GetRSAPublicKey()!.ExportParameters(false)),
            "AC #10: predecessor is active before the successor's NotBefore arrives");

        timeProvider.SetUtcNow(successorNotBefore);
        var after = await sut.GetSigningKeysAsync(ct);
        after[0].Kid.Should().Be(JwkThumbprint.Compute(successor.GetRSAPublicKey()!.ExportParameters(false)),
            "AC #10: successor becomes active once its NotBefore arrives");
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

    // ── Too-soon-NotBefore startup warning (AC #12) ──────────────────────────────────────────────

    [Fact]
    public async Task GetSigningKeysAsync_logs_a_warning_when_the_soonest_pending_NotBefore_is_closer_than_KeySourceRefreshInterval()
    {
        var ct = TestContext.Current.CancellationToken;
        var refreshInterval = TimeSpan.FromMinutes(5);
        using var tempDir = new TempSigningKeyDirectory();
        using var primary = TestCertificateFactory.CreateRsaSelfSigned("primary", T0 - TimeSpan.FromDays(30), T0 + TimeSpan.FromDays(365));
        using var secondary = TestCertificateFactory.CreateRsaSelfSigned("secondary", T0 + TimeSpan.FromMinutes(1), T0 + TimeSpan.FromDays(400));
        var primaryPath = tempDir.WritePemFile("primary.pem", primary);
        var secondaryPath = tempDir.WritePemFile("secondary.pem", secondary);
        var logger = new CapturingSanitizingLogger<FileSigningJwtSigningService<PemFileSigningOptions>>();
        await using var sut = BuildService(primaryPath, new FakeTimeProvider(T0), [secondaryPath], refreshInterval: refreshInterval, logger: logger);

        await sut.GetSigningKeysAsync(ct);

        logger.Entries.Should().Contain(e => e.Level == LogLevel.Warning,
            "AC #12: the too-soon-NotBefore misconfiguration must be surfaced");
    }

    // ── kid stability ─────────────────────────────────────────────────────────────────────────────

    [Fact]
    public async Task GetSigningKeysAsync_kid_is_stable_across_reloads_of_the_same_file()
    {
        var ct = TestContext.Current.CancellationToken;
        var refreshInterval = TimeSpan.FromMinutes(5);
        using var tempDir = new TempSigningKeyDirectory();
        using var certificate = TestCertificateFactory.CreateRsaSelfSigned("test", T0 - TimeSpan.FromDays(1), T0 + TimeSpan.FromDays(365));
        var path = tempDir.WritePemFile("key.pem", certificate);
        var timeProvider = new FakeTimeProvider(T0);
        await using var sut = BuildService(path, timeProvider, refreshInterval: refreshInterval);

        var first = await sut.GetSigningKeysAsync(ct);
        timeProvider.SetUtcNow(T0 + refreshInterval); // Force a reload.
        var second = await sut.GetSigningKeysAsync(ct);

        second[0].Kid.Should().Be(first[0].Kid, "kid must be derived from the key material, not regenerated per load");
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

    // ── Logging: never leaks key material (issue #291's explicit requirement) ───────────────────

    [Fact]
    public async Task GetSigningKeysAsync_logs_path_key_type_and_key_size_but_never_key_material()
    {
        var ct = TestContext.Current.CancellationToken;
        using var tempDir = new TempSigningKeyDirectory();
        using var certificate = TestCertificateFactory.CreateRsaSelfSigned("test", T0 - TimeSpan.FromDays(1), T0 + TimeSpan.FromDays(365), keySizeBits: 2048);
        var path = tempDir.WritePemFile("key.pem", certificate);
        var logger = new CapturingSanitizingLogger<FileSigningJwtSigningService<PemFileSigningOptions>>();
        await using var sut = BuildService(path, new FakeTimeProvider(T0), logger: logger);

        await sut.GetSigningKeysAsync(ct);

        logger.Entries.Should().ContainSingle(e => e.Level == LogLevel.Information
            && e.Message.Contains(path)
            && e.Message.Contains("RSA")
            && e.Message.Contains("2048"));
        logger.Entries.Should().NotContain(e => e.Message.Contains("BEGIN") || e.Message.Contains("PRIVATE KEY"),
            "no PEM block or key material may ever reach a log line");
    }

    // ── HasKeySetChangedAsync: metadata-only change detection (ADR 0011 §3.5 / issue #349) ─────────
    //
    // Only PemFileSigningJwtSigningService is exercised below: the HasKeySetChangedAsync override
    // lives entirely on the shared FileSigningJwtSigningService<TOptions> base class, so covering it
    // once here also covers PfxFileSigningJwtSigningService — mirroring how #350/#351 tested each
    // Key Vault provider once against its own LoadKeysAsync, not by duplicating the same assertions
    // across every subclass.

    [Fact]
    public async Task GetSigningKeysAsync_does_not_reread_the_file_when_nothing_has_changed_since_the_last_load()
    {
        var ct = TestContext.Current.CancellationToken;
        var refreshInterval = TimeSpan.FromMinutes(5);
        using var tempDir = new TempSigningKeyDirectory();
        using var certificate = TestCertificateFactory.CreateRsaSelfSigned("test", T0 - TimeSpan.FromDays(1), T0 + TimeSpan.FromDays(365));
        var path = tempDir.WritePemFile("key.pem", certificate);
        var timeProvider = new FakeTimeProvider(T0);
        await using var sut = BuildService(path, timeProvider, refreshInterval: refreshInterval);

        var first = await sut.GetSigningKeysAsync(ct); // Bootstrap load.
        var lastWriteTimeUtc = File.GetLastWriteTimeUtc(path);

        // Corrupts the file's content while preserving its recorded mtime. If HasKeySetChangedAsync
        // incorrectly reported a change here, the subsequent LoadKeysAsync would try to reparse this
        // invalid content and throw — proving a reread happened. A correct "unchanged" report never
        // touches this corrupted content at all.
        File.WriteAllText(path, "this is not a valid PEM file");
        File.SetLastWriteTimeUtc(path, lastWriteTimeUtc);
        timeProvider.SetUtcNow(T0 + refreshInterval);

        var second = await sut.GetSigningKeysAsync(ct);

        second[0].Kid.Should().Be(first[0].Kid,
            "nothing changed since the last load, so HasKeySetChangedAsync must report no change and " +
            "LoadKeysAsync must not reread the corrupted file");
    }

    [Fact]
    public async Task SignAsync_still_succeeds_after_an_unchanged_poll_skips_the_reload()
    {
        var ct = TestContext.Current.CancellationToken;
        var refreshInterval = TimeSpan.FromMinutes(5);
        using var tempDir = new TempSigningKeyDirectory();
        using var certificate = TestCertificateFactory.CreateRsaSelfSigned("test", T0 - TimeSpan.FromDays(1), T0 + TimeSpan.FromDays(365));
        var path = tempDir.WritePemFile("key.pem", certificate);
        var timeProvider = new FakeTimeProvider(T0);
        await using var sut = BuildService(path, timeProvider, refreshInterval: refreshInterval);

        await sut.GetSigningKeysAsync(ct); // Bootstrap load.
        timeProvider.SetUtcNow(T0 + refreshInterval); // Unchanged poll -> ask reports "no change".
        var payloadSegment = SigningTestHelpers.Base64UrlEncode("{\"sub\":\"test-subject\"}"u8.ToArray());

        var act = async () => await sut.SignAsync(payloadSegment, ct);

        await act.Should().NotThrowAsync(
            "the cached SigningKeySet must remain usable (not disposed) when the ask reports no change");
    }

    [Fact]
    public async Task GetSigningKeysAsync_reloads_when_a_registered_files_contents_change()
    {
        var ct = TestContext.Current.CancellationToken;
        var refreshInterval = TimeSpan.FromMinutes(5);
        using var tempDir = new TempSigningKeyDirectory();
        using var original = TestCertificateFactory.CreateRsaSelfSigned("original", T0 - TimeSpan.FromDays(1), T0 + TimeSpan.FromDays(365));
        using var replacement = TestCertificateFactory.CreateRsaSelfSigned("replacement", T0 - TimeSpan.FromDays(1), T0 + TimeSpan.FromDays(365));
        var path = tempDir.WritePemFile("key.pem", original);
        var timeProvider = new FakeTimeProvider(T0);
        await using var sut = BuildService(path, timeProvider, refreshInterval: refreshInterval);

        var first = await sut.GetSigningKeysAsync(ct);
        tempDir.WritePemFile("key.pem", replacement); // Overwrites both content and mtime.
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
        var primaryPath = tempDir.WritePemFile("primary.pem", primary);
        var secondaryPath = tempDir.WritePemFile("secondary.pem", secondary);
        var options = new PemFileSigningOptions { Path = primaryPath, KeySourceRefreshInterval = refreshInterval };
        var timeProvider = new FakeTimeProvider(T0);
        await using var sut = new PemFileSigningJwtSigningService(
            Options.Create(options),
            timeProvider,
            new FileSigningKeyReader(NullSanitizingLogger<FileSigningKeyReader>.Instance),
            new FakeRetirementWindowProvider(TimeSpan.FromHours(1)),
            NullSanitizingLogger<FileSigningJwtSigningService<PemFileSigningOptions>>.Instance);

        var first = await sut.GetSigningKeysAsync(ct);
        first.Should().ContainSingle("only the primary path is registered so far");

        options.AddFile(secondaryPath); // Registered path set changes with zero file I/O.
        timeProvider.SetUtcNow(T0 + refreshInterval);
        var second = await sut.GetSigningKeysAsync(ct);

        second.Should().HaveCount(2,
            "the registered path set changed, so HasKeySetChangedAsync must report a change even " +
            "though neither file's content changed");
    }

    [Fact]
    public async Task GetSigningKeysAsync_reloads_when_the_registered_path_is_replaced_in_configuration()
    {
        var ct = TestContext.Current.CancellationToken;
        var refreshInterval = TimeSpan.FromMinutes(5);
        using var tempDir = new TempSigningKeyDirectory();
        using var original = TestCertificateFactory.CreateRsaSelfSigned("original", T0 - TimeSpan.FromDays(1), T0 + TimeSpan.FromDays(365));
        using var replacement = TestCertificateFactory.CreateRsaSelfSigned("replacement", T0 - TimeSpan.FromDays(1), T0 + TimeSpan.FromDays(365));
        var originalPath = tempDir.WritePemFile("original.pem", original);
        var replacementPath = tempDir.WritePemFile("replacement.pem", replacement);
        var options = new PemFileSigningOptions { Path = originalPath, KeySourceRefreshInterval = refreshInterval };
        var timeProvider = new FakeTimeProvider(T0);
        await using var sut = new PemFileSigningJwtSigningService(
            Options.Create(options),
            timeProvider,
            new FileSigningKeyReader(NullSanitizingLogger<FileSigningKeyReader>.Instance),
            new FakeRetirementWindowProvider(TimeSpan.FromHours(1)),
            NullSanitizingLogger<FileSigningJwtSigningService<PemFileSigningOptions>>.Instance);

        var first = await sut.GetSigningKeysAsync(ct);

        options.Path = replacementPath; // The original path is removed from configuration, a new one takes its place.
        timeProvider.SetUtcNow(T0 + refreshInterval);
        var second = await sut.GetSigningKeysAsync(ct);

        second[0].Kid.Should().NotBe(first[0].Kid,
            "the registered path set changed (original path removed, replacement added), so " +
            "HasKeySetChangedAsync must report a change");
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
        var predecessorPath = tempDir.WritePemFile("predecessor.pem", predecessor);
        var successorPath = tempDir.WritePemFile("successor.pem", successor);
        var timeProvider = new FakeTimeProvider(T0);
        await using var sut = BuildService(
            predecessorPath, timeProvider, [successorPath], refreshInterval: refreshInterval, retirementWindow: retirementWindow);

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
        var path = tempDir.WritePemFile("key.pem", certificate);
        var timeProvider = new FakeTimeProvider(T0);
        await using var sut = BuildService(path, timeProvider, refreshInterval: refreshInterval);

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
}
