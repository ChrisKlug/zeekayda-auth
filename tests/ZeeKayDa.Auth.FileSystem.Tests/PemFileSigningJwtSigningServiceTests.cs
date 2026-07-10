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
        ISanitizingLogger<FileSigningJwtSigningService<PemFileSigningOptions>>? logger = null)
    {
        var options = new PemFileSigningOptions
        {
            Path = primaryPath,
            Algorithm = algorithm,
            RefreshInterval = refreshInterval ?? TimeSpan.FromMinutes(5),
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
    public async Task GetSigningKeysAsync_logs_a_warning_when_the_soonest_pending_NotBefore_is_closer_than_RefreshInterval()
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
}
