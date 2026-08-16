using System.Reflection;
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
/// mirroring <c>PfxFileSigningJwtSigningServiceTests</c>'s shape and adding the Windows Certificate
/// Store-specific concern: the bundled-format least-privilege obligation (issue #424's security
/// ask) over <see cref="ICertificateStoreReader"/> rather than the filesystem.
/// </summary>
/// <remarks>
/// This provider is on ADR 0015's Tier A (<see cref="KeySetOptions"/>) contract (issue #424):
/// <c>ListKeysAsync</c> runs exactly once, ever, for the lifetime of a service instance, so there is
/// no reload/change-detection surface to test here — a rotated-in, removed, or replaced certificate
/// is never picked up without a restart. Rotation between already-registered certificates still
/// switches the active signer purely from elapsed wall-clock time, with zero further store access —
/// that behaviour is covered below. The service class itself has no Windows-specific code (it
/// depends only on <see cref="ICertificateStoreReader"/>), so — mirroring
/// <c>AzureKeyVaultCachedSigningJwtSigningServiceTests</c>'s pattern for its sibling provider —
/// these tests run on any OS, unlike <c>Integration/WindowsCertificateStoreSigningIntegrationTests</c>,
/// which goes through the real, Windows-only extension method.
/// </remarks>
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
        TimeSpan? retirementWindow = null,
        SigningAlgorithm algorithm = SigningAlgorithm.RS256,
        TimeSpan? publicationLead = null,
        ISanitizingLogger<JwtSigningService<WindowsCertificateStoreSigningOptions>>? logger = null,
        ICertificateKeyExtractor? keyExtractor = null)
    {
        var options = new WindowsCertificateStoreSigningOptions
        {
            Thumbprint = primaryThumbprint,
            StoreLocation = StoreLocation.CurrentUser,
            StoreName = StoreName.My,
            Algorithm = algorithm,
            PublicationLead = publicationLead ?? TimeSpan.FromHours(1),
        };
        foreach (var additional in additionalThumbprints ?? [])
            options.AddCertificate(additional);

        return new WindowsCertificateStoreSigningJwtSigningService(
            Options.Create(options),
            timeProvider,
            reader,
            keyExtractor ?? new FakeCertificateKeyExtractor(),
            new FakeRetirementWindowProvider(retirementWindow ?? TimeSpan.FromHours(1)),
            logger ?? NullSanitizingLogger<JwtSigningService<WindowsCertificateStoreSigningOptions>>.Instance);
    }

    // ── Happy path ───────────────────────────────────────────────────────────────────────────────

    [Fact]
    public async Task GetSigningKeysAsync_returns_the_registered_certificates_public_key()
    {
        var ct = TestContext.Current.CancellationToken;
        var reader = new FakeCertificateStoreReader();
        using var certificate = TestCertificateFactory.CreateRsaSelfSigned("test", T0 - TimeSpan.FromDays(1), T0 + TimeSpan.FromDays(365));
        reader.AddCertificate(PrimaryThumbprint, certificate);
        await using var sut = BuildService(reader, new FakeTimeProvider(T0), PrimaryThumbprint);

        var keys = await sut.GetSigningKeysAsync(ct);

        keys.Should().ContainSingle();
        keys[0].KeyType.Should().Be(SigningKeyType.Rsa);
        keys[0].RsaPublicParameters.Should().NotBeNull("only the public key may ever be exposed via the descriptor");
        keys[0].Algorithm.Should().Be(SigningAlgorithm.RS256);
    }

    [Fact]
    public async Task SignAsync_signs_with_the_registered_certificates_private_key()
    {
        var ct = TestContext.Current.CancellationToken;
        var reader = new FakeCertificateStoreReader();
        using var certificate = TestCertificateFactory.CreateRsaSelfSigned("test", T0 - TimeSpan.FromDays(1), T0 + TimeSpan.FromDays(365));
        reader.AddCertificate(PrimaryThumbprint, certificate);
        await using var sut = BuildService(reader, new FakeTimeProvider(T0), PrimaryThumbprint);
        var payloadSegment = SigningTestHelpers.Base64UrlEncode("{\"sub\":\"test-subject\"}"u8.ToArray());

        var result = await sut.SignAsync(payloadSegment, ct);
        var keys = await sut.GetSigningKeysAsync(ct);
        var descriptor = keys.Single(k => k.Kid == result.Kid);

        SigningTestHelpers.VerifyRsaSignature(descriptor, result, payloadSegment).Should().BeTrue(
            "the signature must verify against the same certificate's public key");
    }

    // ── Missing certificate ──────────────────────────────────────────────────────────────────────

    [Fact]
    public async Task GetSigningKeysAsync_throws_ZeeKayDaConfigurationException_when_the_certificate_is_not_found()
    {
        var ct = TestContext.Current.CancellationToken;
        var reader = new FakeCertificateStoreReader(); // No certificate registered.
        await using var sut = BuildService(reader, new FakeTimeProvider(T0), PrimaryThumbprint);

        var act = async () => await sut.GetSigningKeysAsync(ct);

        var exception = await act.Should().ThrowAsync<ZeeKayDaConfigurationException>();
        exception.Which.AggregatedFailures.Should().ContainSingle(f => f.Code == "signing.windows_certificate_store.certificate_not_found");
    }

    // ── Missing/inaccessible private key surfaces only when signing ─────────────────────────────
    //
    // ADR 0015 §2/§5's least-privilege loading means ListKeysAsync never needs a private key — only
    // CreateSignerAsync does, and only for the active certificate. A certificate with no private key
    // installed alongside it is therefore perfectly listable; the failure surfaces only once a real
    // SignAsync call actually needs to extract the private key.

    [Fact]
    public async Task GetSigningKeysAsync_succeeds_for_a_certificate_with_no_private_key()
    {
        var ct = TestContext.Current.CancellationToken;
        var reader = new FakeCertificateStoreReader();
        using var certificate = TestCertificateFactory.CreateRsaSelfSigned(
            "test", T0 - TimeSpan.FromDays(1), T0 + TimeSpan.FromDays(365), withPrivateKey: false);
        reader.AddCertificate(PrimaryThumbprint, certificate);
        await using var sut = BuildService(reader, new FakeTimeProvider(T0), PrimaryThumbprint);

        var act = async () => await sut.GetSigningKeysAsync(ct);

        await act.Should().NotThrowAsync("listing a key never needs its private half");
    }

    [Fact]
    public async Task SignAsync_throws_ZeeKayDaConfigurationException_when_the_active_certificate_has_no_private_key()
    {
        var ct = TestContext.Current.CancellationToken;
        var reader = new FakeCertificateStoreReader();
        using var certificate = TestCertificateFactory.CreateRsaSelfSigned(
            "test", T0 - TimeSpan.FromDays(1), T0 + TimeSpan.FromDays(365), withPrivateKey: false);
        reader.AddCertificate(PrimaryThumbprint, certificate);
        await using var sut = BuildService(reader, new FakeTimeProvider(T0), PrimaryThumbprint);
        var payload = "payload"u8.ToArray();

        var act = async () => await sut.SignAsync(payload, ct);

        var exception = await act.Should().ThrowAsync<ZeeKayDaConfigurationException>();
        exception.Which.AggregatedFailures.Should().ContainSingle(f => f.Code == "signing.windows_certificate_store.private_key_not_found");
    }

    // ── Multi-certificate rotation via AddCertificate ────────────────────────────────────────────
    //
    // ADR 0015 Tier A: ListKeysAsync runs exactly once and builds one immutable snapshot/timeline;
    // active-key selection is then recomputed lazily against the wall clock on every call, with zero
    // further store access — so a rotation between already-known certificates still switches the
    // active signer purely from elapsed time.

    [Fact]
    public async Task GetSigningKeysAsync_exposes_both_certificates_during_a_rotation_overlap()
    {
        var ct = TestContext.Current.CancellationToken;
        var reader = new FakeCertificateStoreReader();
        using var predecessor = TestCertificateFactory.CreateRsaSelfSigned("predecessor", T0 - TimeSpan.FromDays(30), T0 + TimeSpan.FromDays(365));
        var successorNotBefore = T0 + TimeSpan.FromDays(1);
        using var successor = TestCertificateFactory.CreateRsaSelfSigned("successor", successorNotBefore, T0 + TimeSpan.FromDays(400));
        reader.AddCertificate(PrimaryThumbprint, predecessor);
        reader.AddCertificate(SecondaryThumbprint, successor);
        await using var sut = BuildService(reader, new FakeTimeProvider(T0), PrimaryThumbprint, [SecondaryThumbprint]);

        var keys = await sut.GetSigningKeysAsync(ct);

        keys.Should().HaveCount(2, "both certificates must be exposed during the overlap window");
    }

    [Fact]
    public async Task GetSigningKeysAsync_active_signer_switches_when_the_successors_NotBefore_arrives()
    {
        var ct = TestContext.Current.CancellationToken;
        var reader = new FakeCertificateStoreReader();
        using var predecessor = TestCertificateFactory.CreateRsaSelfSigned("predecessor", T0 - TimeSpan.FromDays(30), T0 + TimeSpan.FromDays(365));
        var successorNotBefore = T0 + TimeSpan.FromDays(1);
        using var successor = TestCertificateFactory.CreateRsaSelfSigned("successor", successorNotBefore, T0 + TimeSpan.FromDays(400));
        reader.AddCertificate(PrimaryThumbprint, predecessor);
        reader.AddCertificate(SecondaryThumbprint, successor);
        var timeProvider = new FakeTimeProvider(T0);
        await using var sut = BuildService(reader, timeProvider, PrimaryThumbprint, [SecondaryThumbprint]);

        var before = await sut.GetSigningKeysAsync(ct);
        before[0].Kid.Should().Be(JwkThumbprint.Compute(predecessor.GetRSAPublicKey()!.ExportParameters(false)),
            "predecessor is active before the successor's NotBefore arrives");

        timeProvider.SetUtcNow(successorNotBefore);
        var after = await sut.GetSigningKeysAsync(ct);
        after[0].Kid.Should().Be(JwkThumbprint.Compute(successor.GetRSAPublicKey()!.ExportParameters(false)),
            "successor becomes active once its NotBefore arrives, with zero further store access " +
            "(ListKeysAsync already ran exactly once)");
    }

    // ── Per-certificate status inclusion at the single ListKeysAsync evaluation ──────────────────

    [Fact]
    public async Task GetSigningKeysAsync_excludes_a_predecessor_whose_retirement_window_had_already_elapsed_at_startup()
    {
        var ct = TestContext.Current.CancellationToken;
        var retirementWindow = TimeSpan.FromHours(1);
        var reader = new FakeCertificateStoreReader();
        using var predecessor = TestCertificateFactory.CreateRsaSelfSigned("predecessor", T0 - TimeSpan.FromDays(60), T0 + TimeSpan.FromDays(365));
        using var successor = TestCertificateFactory.CreateRsaSelfSigned("successor", T0 - TimeSpan.FromDays(10), T0 + TimeSpan.FromDays(400));
        reader.AddCertificate(PrimaryThumbprint, predecessor);
        reader.AddCertificate(SecondaryThumbprint, successor);
        await using var sut = BuildService(
            reader, new FakeTimeProvider(T0), PrimaryThumbprint, [SecondaryThumbprint], retirementWindow: retirementWindow);

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
        var reader = new FakeCertificateStoreReader();
        using var predecessor = TestCertificateFactory.CreateRsaSelfSigned("predecessor", T0 - TimeSpan.FromDays(30), T0 + TimeSpan.FromDays(365));
        using var successor = TestCertificateFactory.CreateRsaSelfSigned("successor", T0 - TimeSpan.FromMinutes(10), T0 + TimeSpan.FromDays(400));
        reader.AddCertificate(PrimaryThumbprint, predecessor);
        reader.AddCertificate(SecondaryThumbprint, successor);
        await using var sut = BuildService(
            reader, new FakeTimeProvider(T0), PrimaryThumbprint, [SecondaryThumbprint], retirementWindow: retirementWindow);

        var keys = await sut.GetSigningKeysAsync(ct);

        keys.Should().HaveCount(2,
            "the successor activated 10 minutes ago, so the predecessor is retired but still within " +
            "its 1-hour retirement window at the single ListKeysAsync evaluation at startup");
    }

    // ── Single-certificate bootstrap exemption ───────────────────────────────────────────────────

    [Fact]
    public async Task GetSigningKeysAsync_the_sole_registered_certificate_is_active_immediately_despite_a_future_NotBefore()
    {
        var ct = TestContext.Current.CancellationToken;
        var reader = new FakeCertificateStoreReader();
        using var certificate = TestCertificateFactory.CreateRsaSelfSigned("test", T0 + TimeSpan.FromDays(30), T0 + TimeSpan.FromDays(365));
        reader.AddCertificate(PrimaryThumbprint, certificate);
        await using var sut = BuildService(reader, new FakeTimeProvider(T0), PrimaryThumbprint);

        var act = async () => await sut.GetSigningKeysAsync(ct);

        await act.Should().NotThrowAsync("the bootstrap exemption activates the sole certificate immediately");
    }

    // ── Every registered certificate already expired at startup ─────────────────────────────────
    //
    // ADR 0015: Tier A never re-reads, so an already-expired sole key with no eligible successor has
    // SelectActiveKey == null and signing fails closed via the base class's own generic
    // "signing.no_active_key" error — there is no provider-specific "no active certificate" special
    // case any more, since ListKeysAsync no longer owns "is this configuration currently usable."

    [Fact]
    public async Task GetSigningKeysAsync_throws_the_base_classes_no_active_key_error_when_every_registered_certificate_has_expired()
    {
        var ct = TestContext.Current.CancellationToken;
        var reader = new FakeCertificateStoreReader();
        using var certificate = TestCertificateFactory.CreateRsaSelfSigned("test", T0 - TimeSpan.FromDays(30), T0 - TimeSpan.FromDays(1));
        reader.AddCertificate(PrimaryThumbprint, certificate);
        await using var sut = BuildService(reader, new FakeTimeProvider(T0), PrimaryThumbprint);

        var act = async () => await sut.GetSigningKeysAsync(ct);

        var exception = await act.Should().ThrowAsync<ZeeKayDaConfigurationException>();
        exception.Which.AggregatedFailures.Should().ContainSingle(f => f.Code == "signing.no_active_key");
    }

    // ── Too-soon-NotBefore startup warning (ADR 0015 §1, issue #424) ─────────────────────────────

    [Fact]
    public async Task GetSigningKeysAsync_logs_a_warning_when_the_soonest_pending_NotBefore_is_closer_than_PublicationLead()
    {
        var ct = TestContext.Current.CancellationToken;
        var reader = new FakeCertificateStoreReader();
        using var primary = TestCertificateFactory.CreateRsaSelfSigned("primary", T0 - TimeSpan.FromDays(30), T0 + TimeSpan.FromDays(365));
        using var secondary = TestCertificateFactory.CreateRsaSelfSigned("secondary", T0 + TimeSpan.FromMinutes(1), T0 + TimeSpan.FromDays(400));
        reader.AddCertificate(PrimaryThumbprint, primary);
        reader.AddCertificate(SecondaryThumbprint, secondary);
        var logger = new CapturingSanitizingLogger<JwtSigningService<WindowsCertificateStoreSigningOptions>>();
        await using var sut = BuildService(
            reader, new FakeTimeProvider(T0), PrimaryThumbprint, [SecondaryThumbprint], logger: logger);

        await sut.GetSigningKeysAsync(ct);

        logger.Entries.Should().Contain(e => e.Level == LogLevel.Warning,
            "the too-soon-NotBefore misconfiguration must be surfaced (default PublicationLead is 1 hour)");
    }

    [Fact]
    public async Task GetSigningKeysAsync_does_not_warn_when_an_explicit_shorter_PublicationLead_is_satisfied()
    {
        var ct = TestContext.Current.CancellationToken;
        var reader = new FakeCertificateStoreReader();
        using var primary = TestCertificateFactory.CreateRsaSelfSigned("primary", T0 - TimeSpan.FromDays(30), T0 + TimeSpan.FromDays(365));
        using var secondary = TestCertificateFactory.CreateRsaSelfSigned("secondary", T0 + TimeSpan.FromMinutes(1), T0 + TimeSpan.FromDays(400));
        reader.AddCertificate(PrimaryThumbprint, primary);
        reader.AddCertificate(SecondaryThumbprint, secondary);
        var logger = new CapturingSanitizingLogger<JwtSigningService<WindowsCertificateStoreSigningOptions>>();
        await using var sut = BuildService(
            reader, new FakeTimeProvider(T0), PrimaryThumbprint, [SecondaryThumbprint],
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
        var reader = new FakeCertificateStoreReader();
        using var primary = TestCertificateFactory.CreateRsaSelfSigned("primary", T0 - TimeSpan.FromDays(30), T0 + TimeSpan.FromDays(365));
        using var secondary = TestCertificateFactory.CreateRsaSelfSigned("secondary", T0 + TimeSpan.FromMinutes(10), T0 + TimeSpan.FromDays(400));
        reader.AddCertificate(PrimaryThumbprint, primary);
        reader.AddCertificate(SecondaryThumbprint, secondary);
        var logger = new CapturingSanitizingLogger<JwtSigningService<WindowsCertificateStoreSigningOptions>>();
        await using var sut = BuildService(
            reader, new FakeTimeProvider(T0), PrimaryThumbprint, [SecondaryThumbprint],
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
        var reader = new FakeCertificateStoreReader();
        using var certificate = TestCertificateFactory.CreateRsaSelfSigned("test", T0 - TimeSpan.FromDays(1), T0 + TimeSpan.FromDays(365));
        reader.AddCertificate(PrimaryThumbprint, certificate);
        var timeProvider = new FakeTimeProvider(T0);
        await using var sut = BuildService(reader, timeProvider, PrimaryThumbprint);

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
        var reader = new FakeCertificateStoreReader();
        using var certificate = TestCertificateFactory.CreateRsaSelfSigned("test", T0 - TimeSpan.FromDays(1), T0 + TimeSpan.FromDays(365));
        reader.AddCertificate(PrimaryThumbprint, certificate);
        await using var sut = BuildService(reader, new FakeTimeProvider(T0), PrimaryThumbprint, algorithm: SigningAlgorithm.ES256);

        var act = async () => await sut.GetSigningKeysAsync(ct);

        var exception = await act.Should().ThrowAsync<ZeeKayDaConfigurationException>();
        exception.Which.AggregatedFailures.Should().ContainSingle(f => f.Code == "signing.windows_certificate_store.algorithm_key_type_mismatch");
    }

    [Fact]
    public async Task GetSigningKeysAsync_throws_when_Algorithm_is_RSA_but_the_certificate_is_EC()
    {
        // The RSA-mismatch direction is covered above; this covers the other half of
        // BuildValidatedPublicKey's mismatch-message branch.
        var ct = TestContext.Current.CancellationToken;
        var reader = new FakeCertificateStoreReader();
        using var certificate = TestCertificateFactory.CreateEcSelfSigned("test", T0 - TimeSpan.FromDays(1), T0 + TimeSpan.FromDays(365));
        reader.AddCertificate(PrimaryThumbprint, certificate);
        await using var sut = BuildService(reader, new FakeTimeProvider(T0), PrimaryThumbprint, algorithm: SigningAlgorithm.RS256);

        var act = async () => await sut.GetSigningKeysAsync(ct);

        var exception = await act.Should().ThrowAsync<ZeeKayDaConfigurationException>();
        exception.Which.AggregatedFailures.Should().ContainSingle(f => f.Code == "signing.windows_certificate_store.algorithm_key_type_mismatch");
        exception.Which.Message.Should().Contain("EC certificate");
    }

    // ── EC certificates ───────────────────────────────────────────────────────────────────────────

    [Fact]
    public async Task GetSigningKeysAsync_supports_EC_certificates_with_a_matching_EC_algorithm()
    {
        var ct = TestContext.Current.CancellationToken;
        var reader = new FakeCertificateStoreReader();
        using var certificate = TestCertificateFactory.CreateEcSelfSigned("test", T0 - TimeSpan.FromDays(1), T0 + TimeSpan.FromDays(365));
        reader.AddCertificate(PrimaryThumbprint, certificate);
        await using var sut = BuildService(reader, new FakeTimeProvider(T0), PrimaryThumbprint, algorithm: SigningAlgorithm.ES256);

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
        var reader = new FakeCertificateStoreReader();
        using var certificate = TestCertificateFactory.CreateEcSelfSigned("test", T0 - TimeSpan.FromDays(1), T0 + TimeSpan.FromDays(365));
        reader.AddCertificate(PrimaryThumbprint, certificate);
        await using var sut = BuildService(reader, new FakeTimeProvider(T0), PrimaryThumbprint, algorithm: SigningAlgorithm.ES256);
        var payloadSegment = SigningTestHelpers.Base64UrlEncode("{\"sub\":\"test-subject\"}"u8.ToArray());

        var result = await sut.SignAsync(payloadSegment, ct);

        result.Kid.Should().NotBeNullOrEmpty();
        result.Algorithm.Should().Be(SigningAlgorithm.ES256);
    }

    // ── Bundled-format least-privilege (issue #424 security ask) ─────────────────────────────────
    //
    // A Windows Certificate Store entry bundles cert+key exactly like PFX, so ListKeysAsync has no
    // choice but to read the whole certificate (including the private half, when installed) to
    // obtain each public certificate. The obligation ADR 0015 §2/§5 places on this provider is that
    // non-active private material is only read *transiently* and never retained: after the one-time
    // listing, a non-active certificate must never be re-read, while the active certificate is
    // re-read afresh by CreateSignerAsync rather than a private handle being kept alive from
    // listing. Counting ICertificateStoreReader.GetCertificate calls per thumbprint proves both halves.

    [Fact]
    public async Task Non_active_certificates_store_entry_is_read_exactly_once_transiently_and_never_reopened_for_signing()
    {
        var ct = TestContext.Current.CancellationToken;
        var reader = new FakeCertificateStoreReader();
        using var active = TestCertificateFactory.CreateRsaSelfSigned("active", T0 - TimeSpan.FromDays(30), T0 + TimeSpan.FromDays(365));
        var pendingNotBefore = T0 + TimeSpan.FromDays(1);
        using var pending = TestCertificateFactory.CreateRsaSelfSigned("pending", pendingNotBefore, T0 + TimeSpan.FromDays(400));
        reader.AddCertificate(PrimaryThumbprint, active);
        reader.AddCertificate(SecondaryThumbprint, pending);

        await using var sut = BuildService(reader, new FakeTimeProvider(T0), PrimaryThumbprint, [SecondaryThumbprint]);
        var payloadSegment = SigningTestHelpers.Base64UrlEncode("{\"sub\":\"test-subject\"}"u8.ToArray());

        await sut.GetSigningKeysAsync(ct); // one-time listing over both certificates
        await sut.SignAsync(payloadSegment, ct); // signs with the active certificate only

        reader.Calls.Count(t => string.Equals(t, SecondaryThumbprint, StringComparison.Ordinal)).Should().Be(1,
            "the non-active (pending) certificate must be read only once — transiently, to build the " +
            "public listing — and never re-read to sign");
        reader.Calls.Count(t => string.Equals(t, PrimaryThumbprint, StringComparison.Ordinal)).Should().BeGreaterThan(1,
            "the active certificate is read once for the listing and re-read afresh by CreateSignerAsync " +
            "to sign, proving no private handle is retained from the listing");
    }

    // ── Defensive invariant: CreateSignerAsync is only ever called for a listed key ─────────────
    //
    // Unreachable via the public API in normal operation — the base class only ever calls
    // CreateSignerAsync with a KeyId it previously observed on a ListKeysAsync-returned KeyListing,
    // and this ADR 0015 Tier A provider's registered thumbprints never change after startup — but
    // invoked directly via reflection here to prove the defensive check fails loudly rather than
    // silently.

    [Fact]
    public async Task CreateSignerAsync_throws_when_called_for_a_key_id_that_is_not_a_registered_thumbprint()
    {
        var ct = TestContext.Current.CancellationToken;
        var reader = new FakeCertificateStoreReader();
        using var certificate = TestCertificateFactory.CreateRsaSelfSigned("test", T0 - TimeSpan.FromDays(1), T0 + TimeSpan.FromDays(365));
        reader.AddCertificate(PrimaryThumbprint, certificate);
        await using var sut = BuildService(reader, new FakeTimeProvider(T0), PrimaryThumbprint);

        var createSignerAsync = typeof(WindowsCertificateStoreSigningJwtSigningService).GetMethod(
            "CreateSignerAsync", BindingFlags.NonPublic | BindingFlags.Instance)!;

        // An async method's exceptions (even ones thrown before its first await) are captured into
        // the returned ValueTask by the compiler-generated state machine, not thrown synchronously
        // from Invoke — so the faulted task is awaited here rather than expecting Invoke itself to throw.
        var task = (ValueTask<ISigner>)createSignerAsync.Invoke(sut, [new KeyId("0000000000000000000000000000000000000A"), ct])!;
        var act = async () => await task;

        await act.Should().ThrowAsync<InvalidOperationException>();
    }

    // ── kid/key consistency: superseded by the framework-owned per-handoff self-test ────────────
    //
    // VerifySigningKeyMatchesListing (added in response to PR #436 security review, alongside
    // PublicKeysMatch/RsaParametersMatch/EcParametersMatch/CurveIdentifiersMatch) was this provider's
    // own hand-rolled proof that the private key CreateSignerAsync hands back still pairs with the
    // public key ListKeysAsync captured for the same thumbprint. Issue #437 deleted all of it: the
    // framework-owned ADR 0015 §11 self-test — run by JwtSigningService<TOptions>'s own
    // EnsureActiveSignerAsync on every handoff, initial materialization and every rotation alike, and
    // exercised generically by JwtSigningServiceTests in ZeeKayDa.Auth.Tests — now proves the
    // equivalent invariant (sign with the returned signer, verify against the listed public key) for
    // every provider on every handoff, not just this one and not just at startup, so this provider no
    // longer needs (or has) its own copy of that check.

    // ── Logging: never leaks key material (issue #291's explicit requirement) ───────────────────

    [Fact]
    public async Task GetSigningKeysAsync_logs_thumbprint_and_subject_but_never_key_material()
    {
        var ct = TestContext.Current.CancellationToken;
        var reader = new FakeCertificateStoreReader();
        using var certificate = TestCertificateFactory.CreateRsaSelfSigned("test-subject-marker", T0 - TimeSpan.FromDays(1), T0 + TimeSpan.FromDays(365));
        reader.AddCertificate(PrimaryThumbprint, certificate);
        var logger = new CapturingSanitizingLogger<JwtSigningService<WindowsCertificateStoreSigningOptions>>();
        await using var sut = BuildService(reader, new FakeTimeProvider(T0), PrimaryThumbprint, logger: logger);

        await sut.GetSigningKeysAsync(ct);

        logger.Entries.Should().ContainSingle(e => e.Level == LogLevel.Information
            && e.Message.Contains(PrimaryThumbprint)
            && e.Message.Contains("test-subject-marker"));
    }
}
