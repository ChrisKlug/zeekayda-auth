using System.Security.Cryptography;
using Azure.Security.KeyVault.Certificates;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Microsoft.Extensions.Time.Testing;
using ZeeKayDa.Auth.AzureKeyVault.Tests.Fakes;
using ZeeKayDa.Auth.Logging;
using ZeeKayDa.Auth.Tokens;

namespace ZeeKayDa.Auth.AzureKeyVault.Tests;

public sealed class AzureKeyVaultCachedSigningJwtSigningServiceTests
{
    private static readonly Uri CertificateIdentifierUri = new("https://fake-vault.vault.azure.net/certificates/fake-cert");
    private static readonly TimeSpan DefaultRefreshInterval = TimeSpan.FromMinutes(5);
    private static readonly TimeSpan DefaultRetirementWindow = TimeSpan.FromHours(1);

    // ── Fake infrastructure ───────────────────────────────────────────────────────────────────────

    /// <summary>
    /// Captures every log call, including the raw structured <c>state</c> passed to
    /// <see cref="ILogger.Log{TState}"/> — needed (unlike <see cref="NullSanitizingLogger{T}"/>) to
    /// assert both on the rendered message and on exactly which named values were logged, per
    /// <see cref="WarnIfPreviouslyPublishedKidVanished"/>'s no-key-material contract.
    /// </summary>
    private sealed class CapturingLogger<T> : ISanitizingLogger<T>
    {
        public List<(LogLevel Level, string Message, object? State)> Entries { get; } = [];

        public IDisposable? BeginScope<TState>(TState state) where TState : notnull => null;

        public bool IsEnabled(LogLevel logLevel) => true;

        public void Log<TState>(
            LogLevel logLevel,
            EventId eventId,
            TState state,
            Exception? exception,
            Func<TState, Exception?, string> formatter)
            => Entries.Add((logLevel, formatter(state, exception), state));
    }

    private static AzureKeyVaultCachedSigningJwtSigningService BuildService(
        FakeKeyVaultCertificateReader reader,
        FakeTimeProvider timeProvider,
        TimeSpan? refreshInterval = null,
        TimeSpan? retirementWindow = null,
        SigningAlgorithm algorithm = SigningAlgorithm.RS256,
        ISanitizingLogger<AzureKeyVaultCachedSigningJwtSigningService>? logger = null)
    {
        var options = Options.Create(new AzureKeyVaultCachedSigningOptions
        {
            CertificateIdentifier = new KeyVaultCertificateIdentifier(CertificateIdentifierUri),
            Credential = new FakeTokenCredential(),
            Algorithm = algorithm,
            KeyRotationCheckInterval = refreshInterval ?? DefaultRefreshInterval,
        });

        return new AzureKeyVaultCachedSigningJwtSigningService(
            options,
            timeProvider,
            reader,
            new FakeRetirementWindowProvider(retirementWindow ?? DefaultRetirementWindow),
            logger ?? NullSanitizingLogger<AzureKeyVaultCachedSigningJwtSigningService>.Instance);
    }

    // ── Bootstrap ────────────────────────────────────────────────────────────────────────────────

    [Fact]
    public async Task GetSigningKeysAsync_first_ever_version_is_active_immediately_no_bootstrap_wait()
    {
        var ct = TestContext.Current.CancellationToken;
        var t0 = DateTimeOffset.Parse("2026-01-01T00:00:00Z");
        var reader = new FakeKeyVaultCertificateReader();
        var v1 = reader.AddRsaVersion("v1", createdOn: t0);
        var timeProvider = new FakeTimeProvider(t0);

        await using var sut = BuildService(reader, timeProvider, refreshInterval: DefaultRefreshInterval);

        var keys = await sut.GetSigningKeysAsync(ct);

        keys.Should().HaveCount(1);
        keys[0].Kid.Should().Be(JwkThumbprint.Compute(reader.GetRsaMaterial(v1.Version)));
    }

    // ── Normal rotation: publish-then-activate, overlap, retirement ────────────────────────────────

    [Fact]
    public async Task GetSigningKeysAsync_rotated_in_version_is_published_but_not_yet_active()
    {
        var ct = TestContext.Current.CancellationToken;
        var t0 = DateTimeOffset.Parse("2026-01-01T00:00:00Z");
        var t1 = t0 + TimeSpan.FromDays(1);
        var reader = new FakeKeyVaultCertificateReader();
        reader.AddRsaVersion("v1", createdOn: t0);
        var timeProvider = new FakeTimeProvider(t0);

        await using var sut = BuildService(reader, timeProvider, refreshInterval: DefaultRefreshInterval);
        await sut.GetSigningKeysAsync(ct); // Prime the initial (bootstrap) load.

        reader.AddRsaVersion("v2", createdOn: t1);
        timeProvider.SetUtcNow(t1); // Cache has expired (> KeyRotationCheckInterval since the first load).

        var keys = await sut.GetSigningKeysAsync(ct);

        keys.Should().HaveCount(2, "v2 must be published (AC #4) even though it is not yet active");
        keys[0].Kid.Should().Be(JwkThumbprint.Compute(reader.GetRsaMaterial("v1")), "v1 is still the active signer");
    }

    [Fact]
    public async Task GetSigningKeysAsync_rotated_in_version_becomes_active_after_refresh_interval_and_predecessor_overlaps()
    {
        var ct = TestContext.Current.CancellationToken;
        var t0 = DateTimeOffset.Parse("2026-01-01T00:00:00Z");
        var t1 = t0 + TimeSpan.FromDays(1);
        var reader = new FakeKeyVaultCertificateReader();
        reader.AddRsaVersion("v1", createdOn: t0);
        var timeProvider = new FakeTimeProvider(t0);

        await using var sut = BuildService(
            reader, timeProvider, refreshInterval: DefaultRefreshInterval, retirementWindow: DefaultRetirementWindow);
        await sut.GetSigningKeysAsync(ct); // Bootstrap load.

        reader.AddRsaVersion("v2", createdOn: t1);
        timeProvider.SetUtcNow(t1 + DefaultRefreshInterval); // v2's ActivatesAt, exactly.

        var keys = await sut.GetSigningKeysAsync(ct);

        keys.Should().HaveCount(2, "both versions must appear in JWKS during the overlap window (AC #4)");
        keys[0].Kid.Should().Be(JwkThumbprint.Compute(reader.GetRsaMaterial("v2")), "v2 has now activated");
        keys.Should().Contain(k => k.Kid == JwkThumbprint.Compute(reader.GetRsaMaterial("v1")), "v1 is retired but still within its retirement window");
    }

    [Fact]
    public async Task GetSigningKeysAsync_predecessor_excluded_once_retirement_window_elapses()
    {
        var ct = TestContext.Current.CancellationToken;
        var t0 = DateTimeOffset.Parse("2026-01-01T00:00:00Z");
        var t1 = t0 + TimeSpan.FromDays(1);
        var retirementWindow = TimeSpan.FromHours(1);
        var reader = new FakeKeyVaultCertificateReader();
        reader.AddRsaVersion("v1", createdOn: t0);
        var timeProvider = new FakeTimeProvider(t0);

        await using var sut = BuildService(
            reader, timeProvider, refreshInterval: DefaultRefreshInterval, retirementWindow: retirementWindow);
        await sut.GetSigningKeysAsync(ct);

        reader.AddRsaVersion("v2", createdOn: t1);
        timeProvider.SetUtcNow(t1 + DefaultRefreshInterval + retirementWindow + TimeSpan.FromMinutes(1));

        var keys = await sut.GetSigningKeysAsync(ct);

        keys.Should().HaveCount(1, "v1's retirement window has fully elapsed since v2 took over");
        keys[0].Kid.Should().Be(JwkThumbprint.Compute(reader.GetRsaMaterial("v2")));
    }

    [Fact]
    public async Task GetSigningKeysAsync_disabled_key_is_excluded_immediately_regardless_of_retirement_window()
    {
        var ct = TestContext.Current.CancellationToken;
        var t0 = DateTimeOffset.Parse("2026-01-01T00:00:00Z");
        var t1 = t0 + TimeSpan.FromDays(1);
        var reader = new FakeKeyVaultCertificateReader();
        reader.AddRsaVersion("v1", createdOn: t0);
        var timeProvider = new FakeTimeProvider(t0);

        await using var sut = BuildService(reader, timeProvider, refreshInterval: DefaultRefreshInterval);
        reader.AddRsaVersion("v2", createdOn: t1);
        timeProvider.SetUtcNow(t1 + DefaultRefreshInterval);
        await sut.GetSigningKeysAsync(ct); // v1 and v2 now overlap.

        reader.SetEnabled("v1", enabled: false);
        timeProvider.SetUtcNow(t1 + DefaultRefreshInterval + DefaultRefreshInterval + TimeSpan.FromSeconds(1));
        var keys = await sut.GetSigningKeysAsync(ct);

        keys.Should().ContainSingle();
        keys[0].Kid.Should().Be(JwkThumbprint.Compute(reader.GetRsaMaterial("v2")),
            "a disabled certificate version is excluded at once, bypassing the retirement window entirely");
    }

    // ── Kid derivation (AC #3): thumbprint, never a Key Vault URI ────────────────────────────────

    [Fact]
    public async Task GetSigningKeysAsync_kid_is_thumbprint_and_never_contains_vault_or_certificate_identifiers()
    {
        var ct = TestContext.Current.CancellationToken;
        var t0 = DateTimeOffset.Parse("2026-01-01T00:00:00Z");
        var reader = new FakeKeyVaultCertificateReader();
        reader.AddRsaVersion("super-secret-version-guid-1234", createdOn: t0);
        var timeProvider = new FakeTimeProvider(t0);

        await using var sut = BuildService(reader, timeProvider);
        var keys = await sut.GetSigningKeysAsync(ct);

        keys[0].Kid.Should().NotContain("fake-vault");
        keys[0].Kid.Should().NotContain("fake-cert");
        keys[0].Kid.Should().NotContain("super-secret-version-guid-1234");
        keys[0].Kid.Should().Be(JwkThumbprint.Compute(reader.GetRsaMaterial("super-secret-version-guid-1234")),
            "kid must be the RFC 7638 thumbprint (via JwkThumbprint.Compute), per AC #3");
    }

    [Fact]
    public async Task GetSigningKeysAsync_two_simultaneously_live_versions_with_identical_material_fail_closed_on_duplicate_kid()
    {
        var ct = TestContext.Current.CancellationToken;
        var t0 = DateTimeOffset.Parse("2026-01-01T00:00:00Z");
        var reader = new FakeKeyVaultCertificateReader();
        reader.AddRsaVersion("v1", createdOn: t0);
        reader.AddRsaVersionWithSameMaterialAs("v1-copy", sourceVersion: "v1", createdOn: t0);
        var timeProvider = new FakeTimeProvider(t0);

        await using var sut = BuildService(reader, timeProvider);

        var act = async () => await sut.GetSigningKeysAsync(ct);

        (await act.Should().ThrowAsync<ZeeKayDaConfigurationException>())
            .WithMessage("*duplicate_kid*");
    }

    // ── Key types: RSA / EC ───────────────────────────────────────────────────────────────────────

    [Fact]
    public async Task GetSigningKeysAsync_builds_correct_descriptor_for_rsa_certificate()
    {
        var ct = TestContext.Current.CancellationToken;
        var t0 = DateTimeOffset.Parse("2026-01-01T00:00:00Z");
        var reader = new FakeKeyVaultCertificateReader();
        reader.AddRsaVersion("v1", createdOn: t0);
        var timeProvider = new FakeTimeProvider(t0);

        await using var sut = BuildService(reader, timeProvider, algorithm: SigningAlgorithm.RS256);
        var keys = await sut.GetSigningKeysAsync(ct);

        keys[0].KeyType.Should().Be(SigningKeyType.Rsa);
        keys[0].RsaPublicParameters.Should().NotBeNull();
    }

    [Fact]
    public async Task GetSigningKeysAsync_builds_correct_descriptor_for_ec_certificate()
    {
        var ct = TestContext.Current.CancellationToken;
        var t0 = DateTimeOffset.Parse("2026-01-01T00:00:00Z");
        var reader = new FakeKeyVaultCertificateReader();
        reader.AddEcVersion("v1", createdOn: t0);
        var timeProvider = new FakeTimeProvider(t0);

        await using var sut = BuildService(reader, timeProvider, algorithm: SigningAlgorithm.ES256);
        var keys = await sut.GetSigningKeysAsync(ct);

        keys[0].KeyType.Should().Be(SigningKeyType.Ec);
        keys[0].EcPublicParameters.Should().NotBeNull();
    }

    // ── Algorithm / key-type mismatch ────────────────────────────────────────────────────────────

    [Fact]
    public async Task GetSigningKeysAsync_throws_clear_exception_when_ec_algorithm_configured_against_rsa_certificate()
    {
        var ct = TestContext.Current.CancellationToken;
        var t0 = DateTimeOffset.Parse("2026-01-01T00:00:00Z");
        var reader = new FakeKeyVaultCertificateReader();
        reader.AddRsaVersion("v1", createdOn: t0);
        var timeProvider = new FakeTimeProvider(t0);

        await using var sut = BuildService(reader, timeProvider, algorithm: SigningAlgorithm.ES256);

        var act = async () => await sut.GetSigningKeysAsync(ct);

        (await act.Should().ThrowAsync<ZeeKayDaConfigurationException>())
            .WithMessage("*algorithm_key_type_mismatch*");
    }

    [Fact]
    public async Task GetSigningKeysAsync_throws_clear_exception_when_rsa_algorithm_configured_against_ec_certificate()
    {
        var ct = TestContext.Current.CancellationToken;
        var t0 = DateTimeOffset.Parse("2026-01-01T00:00:00Z");
        var reader = new FakeKeyVaultCertificateReader();
        reader.AddEcVersion("v1", createdOn: t0);
        var timeProvider = new FakeTimeProvider(t0);

        await using var sut = BuildService(reader, timeProvider, algorithm: SigningAlgorithm.RS256);

        var act = async () => await sut.GetSigningKeysAsync(ct);

        (await act.Should().ThrowAsync<ZeeKayDaConfigurationException>())
            .WithMessage("*algorithm_key_type_mismatch*");
    }

    // ── No certificate versions / no active version ─────────────────────────────────────────────

    [Fact]
    public async Task GetSigningKeysAsync_throws_clear_exception_when_certificate_has_no_versions()
    {
        var ct = TestContext.Current.CancellationToken;
        var reader = new FakeKeyVaultCertificateReader();
        var timeProvider = new FakeTimeProvider(DateTimeOffset.Parse("2026-01-01T00:00:00Z"));

        await using var sut = BuildService(reader, timeProvider);

        var act = async () => await sut.GetSigningKeysAsync(ct);

        (await act.Should().ThrowAsync<ZeeKayDaConfigurationException>())
            .WithMessage("*no_certificate_versions*");
    }

    [Fact]
    public async Task GetSigningKeysAsync_throws_clear_exception_when_no_version_has_activated_yet()
    {
        var ct = TestContext.Current.CancellationToken;
        var t0 = DateTimeOffset.Parse("2026-01-01T00:00:00Z");
        var reader = new FakeKeyVaultCertificateReader();
        reader.AddRsaVersion("v1", createdOn: t0, notBefore: t0 + TimeSpan.FromDays(1));
        var timeProvider = new FakeTimeProvider(t0);

        await using var sut = BuildService(reader, timeProvider);

        var act = async () => await sut.GetSigningKeysAsync(ct);

        (await act.Should().ThrowAsync<ZeeKayDaConfigurationException>())
            .WithMessage("*no_active_key*");
    }

    // ── Startup failure propagation: non-exportable / bad credentials / not found (AC #5, #6, #7) ──

    [Fact]
    public async Task GetSigningKeysAsync_propagates_non_exportable_certificate_failure_from_the_reader_seam()
    {
        var ct = TestContext.Current.CancellationToken;
        var t0 = DateTimeOffset.Parse("2026-01-01T00:00:00Z");
        var reader = new FakeKeyVaultCertificateReader();
        reader.AddRsaVersion("v1", createdOn: t0);
        reader.SetPrivateKeyException("v1", new ZeeKayDaConfigurationException(
            new ZeeKayDaConfigurationFailure(
                "signing.azure_key_vault.certificate_not_exportable",
                "Simulated non-exportable certificate policy failure.")));
        var timeProvider = new FakeTimeProvider(t0);

        await using var sut = BuildService(reader, timeProvider);

        var act = async () => await sut.GetSigningKeysAsync(ct);

        (await act.Should().ThrowAsync<ZeeKayDaConfigurationException>())
            .WithMessage("*certificate_not_exportable*");
    }

    [Fact]
    public async Task GetSigningKeysAsync_propagates_access_denied_failure_from_the_reader_seam()
    {
        var ct = TestContext.Current.CancellationToken;
        var t0 = DateTimeOffset.Parse("2026-01-01T00:00:00Z");
        var reader = new FakeKeyVaultCertificateReader
        {
            VersionsException = new ZeeKayDaConfigurationException(
                new ZeeKayDaConfigurationFailure(
                    "signing.azure_key_vault.access_denied",
                    "Simulated bad-credentials failure from the Key Vault certificate reader seam.")),
        };
        var timeProvider = new FakeTimeProvider(t0);

        await using var sut = BuildService(reader, timeProvider);

        var act = async () => await sut.GetSigningKeysAsync(ct);

        (await act.Should().ThrowAsync<ZeeKayDaConfigurationException>())
            .WithMessage("*access_denied*");
    }

    [Fact]
    public async Task GetSigningKeysAsync_propagates_certificate_not_found_failure_from_the_reader_seam()
    {
        var ct = TestContext.Current.CancellationToken;
        var t0 = DateTimeOffset.Parse("2026-01-01T00:00:00Z");
        var reader = new FakeKeyVaultCertificateReader
        {
            VersionsException = new ZeeKayDaConfigurationException(
                new ZeeKayDaConfigurationFailure(
                    "signing.azure_key_vault.certificate_not_found",
                    "Simulated missing-certificate failure from the Key Vault certificate reader seam.")),
        };
        var timeProvider = new FakeTimeProvider(t0);

        await using var sut = BuildService(reader, timeProvider);

        var act = async () => await sut.GetSigningKeysAsync(ct);

        (await act.Should().ThrowAsync<ZeeKayDaConfigurationException>())
            .WithMessage("*certificate_not_found*");
    }

    [Fact]
    public async Task GetSigningKeysAsync_disposes_already_downloaded_active_private_key_when_a_later_version_fails_to_load()
    {
        // v0 is the active version, so real private key material has already been downloaded and
        // extracted for it (via GetPrivateKeyMaterialAsync) by the time v1's public-key-only
        // download (via GetPublicKeyMaterialAsync — v1 is published but not yet active) fails. The
        // base class must not leak v0's live private key handle.
        var ct = TestContext.Current.CancellationToken;
        var t0 = DateTimeOffset.Parse("2026-01-01T00:00:00Z");
        var reader = new FakeKeyVaultCertificateReader();
        reader.AddRsaVersion("v1", createdOn: t0, notBefore: t0 + TimeSpan.FromDays(2)); // Not yet active -> published alongside the active v0.
        reader.AddRsaVersion("v0", createdOn: t0 - TimeSpan.FromDays(1));
        reader.SetPublicKeyException("v1", new ZeeKayDaConfigurationException(
            new ZeeKayDaConfigurationFailure("signing.azure_key_vault.access_denied", "Simulated failure for v1.")));
        AsymmetricAlgorithm? capturedKey = null;
        reader.OnPrivateKeyExtracted = (version, key) =>
        {
            if (version == "v0")
                capturedKey = key;
        };
        var timeProvider = new FakeTimeProvider(t0);

        await using var sut = BuildService(reader, timeProvider);

        var act = async () => await sut.GetSigningKeysAsync(ct);
        (await act.Should().ThrowAsync<ZeeKayDaConfigurationException>())
            .WithMessage("*access_denied*");

        capturedKey.Should().NotBeNull();
        var useAfterFailure = () => ((RSA)capturedKey!).ExportParameters(includePrivateParameters: false);
        useAfterFailure.Should().Throw<ObjectDisposedException>(
            "v0's already-downloaded active private key handle must not be leaked when v1's later load fails");
    }

    [Fact]
    public async Task GetSigningKeysAsync_disposes_active_public_only_handle_when_BuildDescriptor_throws_for_it()
    {
        // Regression test for the mid-load key-handle leak: ValidateAlgorithmFamilyMatchesKeyType
        // throws inside BuildDescriptor for an ES256/RSA mismatch. Since every included version's
        // descriptor — including the active version's — is now built from the public-only handle
        // (fix for #312's kid-derivation unification finding), it is that public-only handle, not
        // a private key, which must not be leaked; GetPrivateKeyMaterialAsync is never even called
        // in this scenario, since the descriptor build fails before the active-only private-key
        // download step is reached.
        var ct = TestContext.Current.CancellationToken;
        var t0 = DateTimeOffset.Parse("2026-01-01T00:00:00Z");
        var reader = new FakeKeyVaultCertificateReader();
        reader.AddRsaVersion("v1", createdOn: t0);
        AsymmetricAlgorithm? capturedKey = null;
        reader.OnPublicKeyExtracted = (_, key) => capturedKey = key;
        var timeProvider = new FakeTimeProvider(t0);

        await using var sut = BuildService(reader, timeProvider, algorithm: SigningAlgorithm.ES256);

        var act = async () => await sut.GetSigningKeysAsync(ct);
        (await act.Should().ThrowAsync<ZeeKayDaConfigurationException>())
            .WithMessage("*algorithm_key_type_mismatch*");

        capturedKey.Should().NotBeNull();
        reader.PrivateKeyMaterialCalls.Should().BeEmpty(
            "the descriptor build fails before the active-only private-key download step is ever reached");
        var useAfterFailure = () => ((RSA)capturedKey!).ExportParameters(includePrivateParameters: false);
        useAfterFailure.Should().Throw<ObjectDisposedException>(
            "the public-only key handle extracted before BuildDescriptor's failure must not be leaked");
    }

    // ── Fix for #312 (medium finding): only the active key holds real private key material ──────

    [Fact]
    public async Task GetSigningKeysAsync_only_downloads_real_private_key_material_for_the_active_version()
    {
        var ct = TestContext.Current.CancellationToken;
        var t0 = DateTimeOffset.Parse("2026-01-01T00:00:00Z");
        var t1 = t0 + TimeSpan.FromDays(1);
        var reader = new FakeKeyVaultCertificateReader();
        reader.AddRsaVersion("v1", createdOn: t0);
        var timeProvider = new FakeTimeProvider(t0);

        await using var sut = BuildService(reader, timeProvider, refreshInterval: DefaultRefreshInterval);
        await sut.GetSigningKeysAsync(ct); // Bootstrap: v1 is the (only, active) version.

        reader.AddRsaVersion("v2", createdOn: t1);
        timeProvider.SetUtcNow(t1); // Cache expired -> reload; v2 is published but not yet active.
        var keys = await sut.GetSigningKeysAsync(ct);

        keys.Should().HaveCount(2, "v1 is still active and v2 is published-but-not-yet-active");
        reader.PrivateKeyMaterialCalls.Should().OnlyContain(v => v == "v1",
            "real private key material must only ever be downloaded for the active version, per ADR 0011 §3.3(c)");
        reader.PublicKeyMaterialCalls.Should().Contain("v2",
            "a published-but-not-yet-active version is only ever exposed via JWKS, so it needs only a public key");
        reader.PublicKeyMaterialCalls.Should().Contain("v1",
            "every included version's descriptor — including the active one's — is now built from the same " +
            "public-only source (fix for #312's kid-derivation unification finding), so the active version " +
            "calls both GetPublicKeyMaterialAsync (for its descriptor) and GetPrivateKeyMaterialAsync (for signing)");
    }

    [Fact]
    public async Task GetSigningKeysAsync_only_downloads_public_key_material_for_a_retired_version_still_in_its_retirement_window()
    {
        var ct = TestContext.Current.CancellationToken;
        var t0 = DateTimeOffset.Parse("2026-01-01T00:00:00Z");
        var t1 = t0 + TimeSpan.FromDays(1);
        var reader = new FakeKeyVaultCertificateReader();
        reader.AddRsaVersion("v1", createdOn: t0);
        var timeProvider = new FakeTimeProvider(t0);

        await using var sut = BuildService(
            reader, timeProvider, refreshInterval: DefaultRefreshInterval, retirementWindow: DefaultRetirementWindow);
        await sut.GetSigningKeysAsync(ct); // Bootstrap: v1 active.
        reader.PrivateKeyMaterialCalls.Clear(); // Only the second load (below) is under test.

        reader.AddRsaVersion("v2", createdOn: t1);
        timeProvider.SetUtcNow(t1 + DefaultRefreshInterval); // v2 activates; v1 retires but stays in-window.
        var keys = await sut.GetSigningKeysAsync(ct);

        keys.Should().HaveCount(2, "v1 is retired but still within its retirement window");
        reader.PrivateKeyMaterialCalls.Should().OnlyContain(v => v == "v2",
            "v2 is now the active version, so only it needs real private key material");
        reader.PublicKeyMaterialCalls.Should().Contain("v1",
            "a retired-but-still-in-window version is only exposed via JWKS, so it needs only a public key");
        reader.PublicKeyMaterialCalls.Should().Contain("v2",
            "v2's descriptor, like every other included version's, is built from the public-only source " +
            "even though v2 is also the active signer");
    }

    // ── Fix for #312 (kid-derivation unification): descriptor always built from the public-only ──
    // source, for every included version including the active one, with no leaked handles on any
    // partial failure of the now-two-step active-version path.

    [Fact]
    public async Task GetSigningKeysAsync_active_kid_matches_thumbprint_of_the_public_only_material()
    {
        var ct = TestContext.Current.CancellationToken;
        var t0 = DateTimeOffset.Parse("2026-01-01T00:00:00Z");
        var reader = new FakeKeyVaultCertificateReader();
        var v1 = reader.AddRsaVersion("v1", createdOn: t0);
        var timeProvider = new FakeTimeProvider(t0);

        await using var sut = BuildService(reader, timeProvider);
        var keys = await sut.GetSigningKeysAsync(ct);

        keys[0].Kid.Should().Be(JwkThumbprint.Compute(reader.GetRsaMaterial(v1.Version)),
            "the active version's kid must be derived from the public-only material, the same source used for every other included version");
    }

    [Fact]
    public async Task GetSigningKeysAsync_disposes_active_public_only_handle_when_private_key_download_fails()
    {
        // Regression test for the now-two-step active-version path: the public-only handle is
        // fetched and used to build the descriptor successfully, but the subsequent private-key
        // download for signing then fails — the public-only handle must not leak.
        var ct = TestContext.Current.CancellationToken;
        var t0 = DateTimeOffset.Parse("2026-01-01T00:00:00Z");
        var reader = new FakeKeyVaultCertificateReader();
        reader.AddRsaVersion("v1", createdOn: t0);
        reader.SetPrivateKeyException("v1", new ZeeKayDaConfigurationException(
            new ZeeKayDaConfigurationFailure(
                "signing.azure_key_vault.access_denied", "Simulated private-key download failure for v1.")));
        AsymmetricAlgorithm? capturedKey = null;
        reader.OnPublicKeyExtracted = (_, key) => capturedKey = key;
        var timeProvider = new FakeTimeProvider(t0);

        await using var sut = BuildService(reader, timeProvider);

        var act = async () => await sut.GetSigningKeysAsync(ct);
        (await act.Should().ThrowAsync<ZeeKayDaConfigurationException>())
            .WithMessage("*access_denied*");

        capturedKey.Should().NotBeNull();
        var useAfterFailure = () => ((RSA)capturedKey!).ExportParameters(includePrivateParameters: false);
        useAfterFailure.Should().Throw<ObjectDisposedException>(
            "the public-only key handle used to build the active version's descriptor must not be leaked when the subsequent private-key download fails");
    }

    // ── AC #1: private key downloaded once and cached — no reader call per sign ─────────────────

    [Fact]
    public async Task GetPrivateKeyMaterialAsync_is_called_exactly_once_per_included_version_per_load()
    {
        var ct = TestContext.Current.CancellationToken;
        var t0 = DateTimeOffset.Parse("2026-01-01T00:00:00Z");
        var reader = new FakeKeyVaultCertificateReader();
        reader.AddRsaVersion("v1", createdOn: t0);
        var timeProvider = new FakeTimeProvider(t0);

        await using var sut = BuildService(reader, timeProvider);
        await sut.GetSigningKeysAsync(ct);
        await sut.GetSigningKeysAsync(ct); // Still within the cache's KeyRotationCheckInterval — no reload.

        reader.PrivateKeyMaterialCalls.Should().ContainSingle(
            "the private key must be downloaded once at load and cached, not re-downloaded on every call within the refresh interval");
    }

    [Fact]
    public async Task SignAsync_does_not_call_the_key_vault_certificate_reader_no_network_round_trip_per_sign()
    {
        // The crux of AC #1: once cached, signing must be entirely local. Since
        // AzureKeyVaultCachedSigningJwtSigningService never overrides SignInputAsync, signing goes
        // through JwtSigningService<TOptions>'s default local-signing path — this test proves that
        // choice holds in practice by asserting the reader is never touched again after the initial
        // load, no matter how many times SignAsync is subsequently called.
        var ct = TestContext.Current.CancellationToken;
        var t0 = DateTimeOffset.Parse("2026-01-01T00:00:00Z");
        var reader = new FakeKeyVaultCertificateReader();
        reader.AddRsaVersion("v1", createdOn: t0);
        var timeProvider = new FakeTimeProvider(t0);

        await using var sut = BuildService(reader, timeProvider);
        await sut.GetSigningKeysAsync(ct); // Bootstrap load: exactly one reader call expected.
        var callsAfterLoad = reader.PrivateKeyMaterialCalls.Count;

        await sut.SignAsync("payload-1"u8.ToArray(), ct);
        await sut.SignAsync("payload-2"u8.ToArray(), ct);
        await sut.SignAsync("payload-3"u8.ToArray(), ct);

        reader.PrivateKeyMaterialCalls.Should().HaveCount(callsAfterLoad,
            "signing must use the already-cached local private key — no Key Vault round trip per sign");
    }

    [Fact]
    public async Task SignAsync_produces_a_signature_verifiable_with_the_certificate_s_public_key()
    {
        // Proves signing is genuinely local: the produced signature is verifiable offline against
        // the exact public key material the fake registered for the active version, with no
        // involvement from the (fake) Key Vault signer seam — there is none for this provider.
        var ct = TestContext.Current.CancellationToken;
        var t0 = DateTimeOffset.Parse("2026-01-01T00:00:00Z");
        var reader = new FakeKeyVaultCertificateReader();
        reader.AddRsaVersion("v1", createdOn: t0);
        var timeProvider = new FakeTimeProvider(t0);

        await using var sut = BuildService(reader, timeProvider, algorithm: SigningAlgorithm.RS256);
        await sut.GetSigningKeysAsync(ct);

        // SignAsync's payloadSegment parameter is passed through verbatim, unmodified, into the
        // signing input (see IJwtSigningService.SignAsync's doc: the caller is expected to have
        // already base64url-encoded it) — the base class never re-encodes it. These raw ASCII bytes
        // are therefore the exact payload segment bytes used to build the real signing input below.
        var payloadSegment = "payload"u8.ToArray();
        var result = await sut.SignAsync(payloadSegment, ct);

        using var rsa = RSA.Create();
        rsa.ImportParameters(reader.GetRsaMaterial("v1"));

        // Reconstruct the exact JWS signing input the base class built: base64url(header) + '.' +
        // payloadSegment (HeaderSegment is already the base64url-encoded header bytes).
        var actualSigningInput = new byte[result.HeaderSegment.Length + 1 + payloadSegment.Length];
        result.HeaderSegment.Span.CopyTo(actualSigningInput);
        actualSigningInput[result.HeaderSegment.Length] = (byte)'.';
        payloadSegment.CopyTo(actualSigningInput.AsSpan(result.HeaderSegment.Length + 1));
        var signatureBytes = Base64UrlDecode(result.SignatureSegment.ToArray());

        var isValid = rsa.VerifyData(
            actualSigningInput, signatureBytes, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);

        isValid.Should().BeTrue("the signature must be verifiable against the certificate's own public key");
    }

    // ── HasKeySetChangedAsync: metadata-only change detection (ADR 0011 §3.5) ───────────────────────

    [Fact]
    public async Task GetSigningKeysAsync_skips_key_material_download_when_versions_are_unchanged_between_polls()
    {
        var ct = TestContext.Current.CancellationToken;
        var t0 = DateTimeOffset.Parse("2026-01-01T00:00:00Z");
        var reader = new FakeKeyVaultCertificateReader();
        reader.AddRsaVersion("v1", createdOn: t0);
        var timeProvider = new FakeTimeProvider(t0);

        await using var sut = BuildService(reader, timeProvider, refreshInterval: DefaultRefreshInterval);
        await sut.GetSigningKeysAsync(ct); // Bootstrap load.
        reader.PrivateKeyMaterialCalls.Clear();
        reader.PublicKeyMaterialCalls.Clear();

        timeProvider.SetUtcNow(t0 + DefaultRefreshInterval); // Cache expires -> triggers the "ask" step.
        var keys = await sut.GetSigningKeysAsync(ct);

        keys.Should().HaveCount(1);
        reader.PrivateKeyMaterialCalls.Should().BeEmpty(
            "no version changed since the last load, so HasKeySetChangedAsync must report no change and LoadKeysAsync must not run");
        reader.PublicKeyMaterialCalls.Should().BeEmpty();
    }

    [Fact]
    public async Task SignAsync_still_succeeds_after_an_unchanged_poll_skips_the_reload()
    {
        var ct = TestContext.Current.CancellationToken;
        var t0 = DateTimeOffset.Parse("2026-01-01T00:00:00Z");
        var reader = new FakeKeyVaultCertificateReader();
        reader.AddRsaVersion("v1", createdOn: t0);
        var timeProvider = new FakeTimeProvider(t0);

        await using var sut = BuildService(reader, timeProvider, refreshInterval: DefaultRefreshInterval);
        await sut.GetSigningKeysAsync(ct); // Bootstrap load.

        timeProvider.SetUtcNow(t0 + DefaultRefreshInterval); // Unchanged poll -> ask reports "no change".
        var payload = "payload"u8.ToArray();

        var act = async () => await sut.SignAsync(payload, ct);

        await act.Should().NotThrowAsync(
            "the cached SigningKeySet must remain usable (not disposed) when the ask reports no change");
    }

    [Fact]
    public async Task HasKeySetChangedAsync_triggers_rebuild_when_a_new_certificate_version_appears()
    {
        var ct = TestContext.Current.CancellationToken;
        var t0 = DateTimeOffset.Parse("2026-01-01T00:00:00Z");
        var reader = new FakeKeyVaultCertificateReader();
        reader.AddRsaVersion("v1", createdOn: t0);
        var timeProvider = new FakeTimeProvider(t0);

        await using var sut = BuildService(reader, timeProvider, refreshInterval: DefaultRefreshInterval);
        await sut.GetSigningKeysAsync(ct); // Bootstrap load.
        reader.PrivateKeyMaterialCalls.Clear();
        reader.PublicKeyMaterialCalls.Clear();

        reader.AddRsaVersion("v2", createdOn: t0 + DefaultRefreshInterval);
        timeProvider.SetUtcNow(t0 + DefaultRefreshInterval);
        var keys = await sut.GetSigningKeysAsync(ct);

        keys.Should().HaveCount(2, "v2 must be published as soon as it appears, per publish-then-activate");
        reader.PublicKeyMaterialCalls.Should().NotBeEmpty(
            "a new certificate version appearing must trigger a real reload, downloading key material again");
    }

    [Fact]
    public async Task HasKeySetChangedAsync_triggers_rebuild_when_a_non_active_versions_enabled_flag_flips()
    {
        // ADR 0011 Amendment 2's revocation case: disabling a version that is not the active
        // signer must still be reported as a change, even though the active version's identifier
        // is unchanged.
        var ct = TestContext.Current.CancellationToken;
        var t0 = DateTimeOffset.Parse("2026-01-01T00:00:00Z");
        var t1 = t0 + TimeSpan.FromDays(1);
        var retirementWindow = TimeSpan.FromHours(2);
        var reader = new FakeKeyVaultCertificateReader();
        reader.AddRsaVersion("v1", createdOn: t0);
        var timeProvider = new FakeTimeProvider(t0);

        await using var sut = BuildService(
            reader, timeProvider, refreshInterval: DefaultRefreshInterval, retirementWindow: retirementWindow);
        await sut.GetSigningKeysAsync(ct); // Bootstrap: v1 active.

        reader.AddRsaVersion("v2", createdOn: t1);
        timeProvider.SetUtcNow(t1 + DefaultRefreshInterval); // v2 activates; v1 retires but stays in-window.
        await sut.GetSigningKeysAsync(ct); // v1 + v2 both included.
        reader.PrivateKeyMaterialCalls.Clear();
        reader.PublicKeyMaterialCalls.Clear();

        // Disable v1 (the non-active, retired-but-in-window version). Only a small amount of time
        // passes (well inside the 2-hour retirement window if v1 were still enabled) so the change
        // is attributable solely to the Enabled flag flip, not to elapsed time.
        reader.SetEnabled("v1", enabled: false);
        timeProvider.SetUtcNow(t1 + DefaultRefreshInterval + DefaultRefreshInterval);
        var keys = await sut.GetSigningKeysAsync(ct);

        keys.Should().ContainSingle(
            "v1's disabled flag must exclude it immediately, even though the active version (v2) is unchanged");
        reader.PublicKeyMaterialCalls.Should().NotBeEmpty(
            "a non-active version's Enabled flag flipping must still trigger a rebuild");
    }

    [Fact]
    public async Task HasKeySetChangedAsync_triggers_rebuild_when_elapsed_time_alone_moves_a_version_out_of_its_retirement_window()
    {
        var ct = TestContext.Current.CancellationToken;
        var t0 = DateTimeOffset.Parse("2026-01-01T00:00:00Z");
        var t1 = t0 + TimeSpan.FromDays(1);
        var retirementWindow = TimeSpan.FromHours(1);
        var reader = new FakeKeyVaultCertificateReader();
        reader.AddRsaVersion("v1", createdOn: t0);
        var timeProvider = new FakeTimeProvider(t0);

        await using var sut = BuildService(
            reader, timeProvider, refreshInterval: DefaultRefreshInterval, retirementWindow: retirementWindow);
        await sut.GetSigningKeysAsync(ct); // Bootstrap: v1 active.

        reader.AddRsaVersion("v2", createdOn: t1);
        timeProvider.SetUtcNow(t1 + DefaultRefreshInterval); // v2 activates; v1 retired but still in-window.
        await sut.GetSigningKeysAsync(ct); // v1 + v2 both included.
        reader.PrivateKeyMaterialCalls.Clear();
        reader.PublicKeyMaterialCalls.Clear();

        // No Key Vault-side change at all — just elapsed time pushing v1 past its retirement window.
        timeProvider.SetUtcNow(t1 + DefaultRefreshInterval + retirementWindow + TimeSpan.FromMinutes(1));
        var keys = await sut.GetSigningKeysAsync(ct);

        keys.Should().ContainSingle("v1's retirement window has now fully elapsed");
        reader.PublicKeyMaterialCalls.Should().NotBeEmpty(
            "a version leaving its retirement window purely from elapsed time must still trigger a rebuild, " +
            "even with no Key Vault-side change");
    }

    [Fact]
    public async Task HasKeySetChangedAsync_triggers_rebuild_when_the_active_version_changes_with_membership_unchanged()
    {
        // Regression test for the security-review finding on this PR: ToVersionSet must compare
        // IsActive, not just version identifier and Enabled state. KeyRotationCheckInterval is both
        // the poll cadence and the publish-then-activate lead time, so a normal rotation spans two
        // polls. At poll N, v2 is published but not yet active — the included set becomes
        // {v1 active, v2 not-active}, a membership change from the single-version bootstrap state,
        // so this poll is correctly reported as a change regardless of the fix (see
        // GetSigningKeysAsync_rotated_in_version_is_published_but_not_yet_active). The poll under
        // test here is the *next* one (N+1): no Key Vault-side change at all happens between the two
        // polls — same two versions, same Enabled states — but v2 has now crossed into its
        // activation window and becomes the active signer while v1 (still within its retirement
        // window) remains included. Comparing only version identifier and Enabled state would see
        // {v1, v2} on both polls and report "no change," silently skipping the reload and leaving the
        // service signing with v1 past its intended rotation point.
        var ct = TestContext.Current.CancellationToken;
        var t0 = DateTimeOffset.Parse("2026-01-01T00:00:00Z");
        var t1 = t0 + TimeSpan.FromDays(1);
        var reader = new FakeKeyVaultCertificateReader();
        reader.AddRsaVersion("v1", createdOn: t0);
        var timeProvider = new FakeTimeProvider(t0);

        await using var sut = BuildService(
            reader, timeProvider, refreshInterval: DefaultRefreshInterval, retirementWindow: DefaultRetirementWindow);
        await sut.GetSigningKeysAsync(ct); // Bootstrap: v1 active.

        reader.AddRsaVersion("v2", createdOn: t1);
        timeProvider.SetUtcNow(t1); // Poll N: v2 published but not yet active (membership change).
        await sut.GetSigningKeysAsync(ct); // v1 active + v2 not-active; both now recorded as "previously included".
        reader.PrivateKeyMaterialCalls.Clear();
        reader.PublicKeyMaterialCalls.Clear();

        // Poll N+1: one KeyRotationCheckInterval later, with no Key Vault-side change whatsoever —
        // v2 now activates and v1 (still within its retirement window) stays included. Same version
        // identifiers, same Enabled states as poll N; only which entry is active differs.
        timeProvider.SetUtcNow(t1 + DefaultRefreshInterval);
        var keys = await sut.GetSigningKeysAsync(ct);

        keys.Should().HaveCount(2, "v1 is still within its retirement window and v2 is now active");
        keys[0].Kid.Should().Be(JwkThumbprint.Compute(reader.GetRsaMaterial("v2")),
            "the handoff must actually happen: v2 must become the active (index 0) signing key at this poll");
        reader.PublicKeyMaterialCalls.Should().NotBeEmpty(
            "the active-slot handoff alone must be enough to trigger a real reload, even with membership and " +
            "Enabled states unchanged since the previous poll");
        reader.PrivateKeyMaterialCalls.Should().Contain("v2",
            "v2 is now the active version and must have its real private key downloaded so it can actually sign");
        reader.PrivateKeyMaterialCalls.Should().NotContain("v1",
            "v1 is no longer active, so only its public key is needed even though it is still included");
    }

    [Fact]
    public async Task HasKeySetChangedAsync_only_enumerates_certificate_versions_and_never_downloads_key_material_when_reporting_no_change()
    {
        var ct = TestContext.Current.CancellationToken;
        var t0 = DateTimeOffset.Parse("2026-01-01T00:00:00Z");
        var reader = new FakeKeyVaultCertificateReader();
        reader.AddRsaVersion("v1", createdOn: t0);
        var timeProvider = new FakeTimeProvider(t0);

        await using var sut = BuildService(reader, timeProvider, refreshInterval: DefaultRefreshInterval);
        await sut.GetSigningKeysAsync(ct); // Bootstrap load.
        var enumerationCallsAfterBootstrap = reader.GetCertificateVersionsCallCount;
        reader.PrivateKeyMaterialCalls.Clear();
        reader.PublicKeyMaterialCalls.Clear();

        timeProvider.SetUtcNow(t0 + DefaultRefreshInterval); // Unchanged poll.
        await sut.GetSigningKeysAsync(ct);

        reader.GetCertificateVersionsCallCount.Should().Be(enumerationCallsAfterBootstrap + 1,
            "the ask step must enumerate certificate versions exactly once per cycle");
        reader.PrivateKeyMaterialCalls.Should().BeEmpty("the ask's metadata-only check must never download key material");
        reader.PublicKeyMaterialCalls.Should().BeEmpty();
    }

    [Fact]
    public async Task HasKeySetChangedAsync_only_enumerates_certificate_versions_before_a_real_reload_downloads_key_material()
    {
        // Proves the "ask" itself is metadata-only even on a cycle that ends up rebuilding: the
        // ask's own enumeration call never touches key material — only the subsequent, separate
        // LoadKeysAsync reload (which shares the same ComputeIncludedVersionsAsync helper and so
        // enumerates a second time) ever calls the key-material endpoints.
        var ct = TestContext.Current.CancellationToken;
        var t0 = DateTimeOffset.Parse("2026-01-01T00:00:00Z");
        var reader = new FakeKeyVaultCertificateReader();
        reader.AddRsaVersion("v1", createdOn: t0);
        var timeProvider = new FakeTimeProvider(t0);

        await using var sut = BuildService(reader, timeProvider, refreshInterval: DefaultRefreshInterval);
        await sut.GetSigningKeysAsync(ct); // Bootstrap load.
        var enumerationCallsAfterBootstrap = reader.GetCertificateVersionsCallCount;
        reader.PrivateKeyMaterialCalls.Clear();
        reader.PublicKeyMaterialCalls.Clear();

        reader.AddRsaVersion("v2", createdOn: t0 + DefaultRefreshInterval); // A genuine change.
        timeProvider.SetUtcNow(t0 + DefaultRefreshInterval);
        await sut.GetSigningKeysAsync(ct);

        reader.GetCertificateVersionsCallCount.Should().Be(enumerationCallsAfterBootstrap + 2,
            "one enumeration for the ask (HasKeySetChangedAsync) and a second, separate one for the real reload " +
            "(LoadKeysAsync) that the \"true\" answer then triggers");
        reader.PublicKeyMaterialCalls.Should().NotBeEmpty("the real reload — not the ask — is what downloads key material");
    }

    // ── WarnIfPreviouslyPublishedKidVanished (ADR 0011 §3.5 anomaly surfacing) ──────────────────────

    [Fact]
    public async Task GetSigningKeysAsync_does_not_warn_when_a_previously_published_kid_is_still_present_next_cycle()
    {
        var ct = TestContext.Current.CancellationToken;
        var t0 = DateTimeOffset.Parse("2026-01-01T00:00:00Z");
        var reader = new FakeKeyVaultCertificateReader();
        reader.AddRsaVersion("v1", createdOn: t0);
        var timeProvider = new FakeTimeProvider(t0);
        var logger = new CapturingLogger<AzureKeyVaultCachedSigningJwtSigningService>();

        await using var sut = BuildService(reader, timeProvider, refreshInterval: DefaultRefreshInterval, logger: logger);
        await sut.GetSigningKeysAsync(ct); // Bootstrap load: v1 published, kid recorded.

        timeProvider.SetUtcNow(t0 + DefaultRefreshInterval); // Cache expires -> forces a second LoadKeysAsync.
        await sut.GetSigningKeysAsync(ct); // v1 is still the only, still-active version.

        logger.Entries.Should().BeEmpty(
            "a kid that is still present in the next refresh cycle is not an anomaly and must not be warned about");
    }

    [Fact]
    public async Task GetSigningKeysAsync_does_not_warn_when_a_previously_published_kid_retires_normally_and_the_version_stays_in_key_vault()
    {
        var ct = TestContext.Current.CancellationToken;
        var t0 = DateTimeOffset.Parse("2026-01-01T00:00:00Z");
        var t1 = t0 + TimeSpan.FromDays(1);
        var retirementWindow = TimeSpan.FromHours(1);
        var reader = new FakeKeyVaultCertificateReader();
        reader.AddRsaVersion("v1", createdOn: t0);
        var timeProvider = new FakeTimeProvider(t0);
        var logger = new CapturingLogger<AzureKeyVaultCachedSigningJwtSigningService>();

        await using var sut = BuildService(
            reader, timeProvider, refreshInterval: DefaultRefreshInterval, retirementWindow: retirementWindow, logger: logger);
        await sut.GetSigningKeysAsync(ct); // Bootstrap: v1 active, kid recorded.

        reader.AddRsaVersion("v2", createdOn: t1);
        // Past v1's full retirement window: v1 is excluded from the included set, but its Key Vault
        // certificate version is never removed from Versions - a normal, expected retirement.
        timeProvider.SetUtcNow(t1 + DefaultRefreshInterval + retirementWindow + TimeSpan.FromMinutes(1));
        var keys = await sut.GetSigningKeysAsync(ct);

        keys.Should().ContainSingle("v1's retirement window has fully elapsed");
        logger.Entries.Should().BeEmpty(
            "v1's certificate version is still present in Key Vault (merely excluded for having aged past its " +
            "retirement window), so this is an expected exclusion, not the anomaly ADR 0011 §3.5 warns about");
    }

    [Fact]
    public async Task GetSigningKeysAsync_warns_when_a_previously_published_kid_s_certificate_version_disappears_from_key_vault_entirely()
    {
        var ct = TestContext.Current.CancellationToken;
        var t0 = DateTimeOffset.Parse("2026-01-01T00:00:00Z");
        var t1 = t0 + TimeSpan.FromDays(1);
        var retirementWindow = TimeSpan.FromHours(1);
        var reader = new FakeKeyVaultCertificateReader();
        var v1 = reader.AddRsaVersion("v1", createdOn: t0);
        var v1Kid = JwkThumbprint.Compute(reader.GetRsaMaterial("v1"));
        var timeProvider = new FakeTimeProvider(t0);
        var logger = new CapturingLogger<AzureKeyVaultCachedSigningJwtSigningService>();

        await using var sut = BuildService(
            reader, timeProvider, refreshInterval: DefaultRefreshInterval, retirementWindow: retirementWindow, logger: logger);
        await sut.GetSigningKeysAsync(ct); // Bootstrap: v1 active, kid recorded as previously published.

        reader.AddRsaVersion("v2", createdOn: t1);
        timeProvider.SetUtcNow(t1 + DefaultRefreshInterval); // v2 activates; v1 would normally still be in its retirement window.

        // Simulate an operator (or a misbehaving external rotation process) deleting v1's certificate
        // version from Key Vault outright, well before its retirement window (1 hour) has elapsed -
        // exactly the anomaly ADR 0011 §3.5 exists to surface.
        reader.Versions.RemoveAll(version => version.Version == v1.Version);

        var keys = await sut.GetSigningKeysAsync(ct);

        keys.Should().ContainSingle("v1 is gone from Key Vault entirely, so it cannot be included any more");
        var entry = logger.Entries.Should().ContainSingle(
            "a previously-published kid whose certificate version has vanished from Key Vault entirely, before " +
            "its retirement window elapsed, must be surfaced as a loud warning per ADR 0011 §3.5").Which;
        entry.Level.Should().Be(LogLevel.Warning);
        entry.Message.Should().Contain(v1Kid, "the vanished kid must be identifiable in the log line");
        entry.Message.Should().Contain("v1", "the vanished Key Vault certificate version must be identifiable in the log line");
    }

    [Fact]
    public async Task GetSigningKeysAsync_vanished_kid_warning_log_state_carries_only_the_kid_and_version_strings_never_key_material()
    {
        // Proves the warning cannot leak key material even in principle: the structured log state
        // passed to ILogger.Log (as opposed to just the rendered message) must contain only string
        // values (the kid and the Key Vault version identifier), never an AsymmetricAlgorithm handle
        // or any RSA/EC parameter material.
        var ct = TestContext.Current.CancellationToken;
        var t0 = DateTimeOffset.Parse("2026-01-01T00:00:00Z");
        var t1 = t0 + TimeSpan.FromDays(1);
        var reader = new FakeKeyVaultCertificateReader();
        var v1 = reader.AddRsaVersion("v1", createdOn: t0);
        var timeProvider = new FakeTimeProvider(t0);
        var logger = new CapturingLogger<AzureKeyVaultCachedSigningJwtSigningService>();

        await using var sut = BuildService(
            reader, timeProvider, refreshInterval: DefaultRefreshInterval, logger: logger);
        await sut.GetSigningKeysAsync(ct);

        reader.AddRsaVersion("v2", createdOn: t1);
        timeProvider.SetUtcNow(t1 + DefaultRefreshInterval);
        reader.Versions.RemoveAll(version => version.Version == v1.Version);
        await sut.GetSigningKeysAsync(ct);

        var entry = logger.Entries.Should().ContainSingle().Which;
        var state = entry.State.Should().BeAssignableTo<IReadOnlyList<KeyValuePair<string, object>>>().Subject;

        state.Should().NotBeEmpty();
        state.Should().OnlyContain(
            kv => kv.Value == null || kv.Value is string,
            "the only structured values ever logged for this warning are the public kid, the Key Vault version " +
            "string, and the format template itself - never a key handle or raw key parameter material");
        state.Should().NotContain(
            kv => kv.Value is AsymmetricAlgorithm || kv.Value is RSAParameters || kv.Value is ECParameters);
    }

    private static byte[] Base64UrlDecode(byte[] base64UrlBytes)
    {
        var text = System.Text.Encoding.ASCII.GetString(base64UrlBytes).Replace('-', '+').Replace('_', '/');
        return Convert.FromBase64String(text.PadRight(text.Length + ((4 - (text.Length % 4)) % 4), '='));
    }
}
