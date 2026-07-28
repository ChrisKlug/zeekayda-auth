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
    private static readonly TimeSpan DefaultPublicationLead = TimeSpan.FromMinutes(5);
    private static readonly TimeSpan DefaultRetirementWindow = TimeSpan.FromHours(1);

    // ── Fake infrastructure ───────────────────────────────────────────────────────────────────────

    private sealed class CapturingLogger<T> : ISanitizingLogger<T>
    {
        public List<(LogLevel Level, string Message)> Entries { get; } = [];

        public IDisposable? BeginScope<TState>(TState state) where TState : notnull => null;

        public bool IsEnabled(LogLevel logLevel) => true;

        public void Log<TState>(
            LogLevel logLevel, EventId eventId, TState state, Exception? exception, Func<TState, Exception?, string> formatter)
            => Entries.Add((logLevel, formatter(state, exception)));
    }

    private static AzureKeyVaultCachedSigningJwtSigningService BuildService(
        FakeKeyVaultCertificateReader reader,
        FakeTimeProvider timeProvider,
        TimeSpan? refreshInterval = null,
        TimeSpan? publicationLead = null,
        TimeSpan? retirementWindow = null,
        SigningAlgorithm algorithm = SigningAlgorithm.RS256,
        ISanitizingLogger<JwtSigningService<AzureKeyVaultCachedSigningOptions>>? logger = null)
    {
        var options = Options.Create(new AzureKeyVaultCachedSigningOptions
        {
            CertificateIdentifier = new KeyVaultCertificateIdentifier(CertificateIdentifierUri),
            Credential = new FakeTokenCredential(),
            Algorithm = algorithm,
            RefreshInterval = refreshInterval ?? DefaultRefreshInterval,
            PublicationLead = publicationLead ?? DefaultPublicationLead,
        });

        return new AzureKeyVaultCachedSigningJwtSigningService(
            options,
            timeProvider,
            reader,
            new FakeRetirementWindowProvider(retirementWindow ?? DefaultRetirementWindow),
            logger ?? NullSanitizingLogger<JwtSigningService<AzureKeyVaultCachedSigningOptions>>.Instance);
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

        await using var sut = BuildService(reader, timeProvider);

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

        await using var sut = BuildService(reader, timeProvider, refreshInterval: DefaultRefreshInterval, publicationLead: DefaultPublicationLead);
        await sut.GetSigningKeysAsync(ct); // Prime the initial (bootstrap) load.

        reader.AddRsaVersion("v2", createdOn: t1);
        timeProvider.SetUtcNow(t1); // Cache has expired (> RefreshInterval since the first load).

        var keys = await sut.GetSigningKeysAsync(ct);

        keys.Should().HaveCount(2, "v2 must be published even though it is not yet active");
        keys[0].Kid.Should().Be(JwkThumbprint.Compute(reader.GetRsaMaterial("v1")), "v1 is still the active signer");
    }

    [Fact]
    public async Task GetSigningKeysAsync_rotated_in_version_becomes_active_after_publication_lead_and_predecessor_overlaps()
    {
        var ct = TestContext.Current.CancellationToken;
        var t0 = DateTimeOffset.Parse("2026-01-01T00:00:00Z");
        var t1 = t0 + TimeSpan.FromDays(1);
        var reader = new FakeKeyVaultCertificateReader();
        reader.AddRsaVersion("v1", createdOn: t0);
        var timeProvider = new FakeTimeProvider(t0);

        await using var sut = BuildService(
            reader, timeProvider, refreshInterval: DefaultRefreshInterval, publicationLead: DefaultPublicationLead,
            retirementWindow: DefaultRetirementWindow);
        await sut.GetSigningKeysAsync(ct); // Bootstrap load.

        reader.AddRsaVersion("v2", createdOn: t1);
        timeProvider.SetUtcNow(t1 + DefaultPublicationLead); // v2's ActivateAt, exactly.

        var keys = await sut.GetSigningKeysAsync(ct);

        keys.Should().HaveCount(2, "both versions must appear in JWKS during the overlap window");
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
            reader, timeProvider, refreshInterval: DefaultRefreshInterval, publicationLead: DefaultPublicationLead,
            retirementWindow: retirementWindow);
        await sut.GetSigningKeysAsync(ct);

        reader.AddRsaVersion("v2", createdOn: t1);
        timeProvider.SetUtcNow(t1 + DefaultPublicationLead + retirementWindow + TimeSpan.FromMinutes(1));

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

        await using var sut = BuildService(reader, timeProvider, refreshInterval: DefaultRefreshInterval, publicationLead: DefaultPublicationLead);
        reader.AddRsaVersion("v2", createdOn: t1);
        timeProvider.SetUtcNow(t1 + DefaultPublicationLead);
        await sut.GetSigningKeysAsync(ct); // v1 and v2 now overlap.

        reader.SetEnabled("v1", enabled: false);
        timeProvider.SetUtcNow(t1 + DefaultPublicationLead + DefaultRefreshInterval + TimeSpan.FromSeconds(1));
        var keys = await sut.GetSigningKeysAsync(ct);

        keys.Should().ContainSingle();
        keys[0].Kid.Should().Be(JwkThumbprint.Compute(reader.GetRsaMaterial("v2")),
            "a disabled certificate version is excluded at once, bypassing the retirement window entirely");
    }

    // ── Kid derivation: thumbprint, never a Key Vault URI ────────────────────────────────────────

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
        keys[0].Kid.Should().Be(JwkThumbprint.Compute(reader.GetRsaMaterial("super-secret-version-guid-1234")));
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

    // ── No certificate versions / no enabled version ─────────────────────────────────────────────

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
    public async Task GetSigningKeysAsync_throws_clear_exception_when_no_version_is_enabled()
    {
        var ct = TestContext.Current.CancellationToken;
        var t0 = DateTimeOffset.Parse("2026-01-01T00:00:00Z");
        var reader = new FakeKeyVaultCertificateReader();
        reader.AddRsaVersion("v1", createdOn: t0, enabled: false);
        var timeProvider = new FakeTimeProvider(t0);

        await using var sut = BuildService(reader, timeProvider);

        var act = async () => await sut.GetSigningKeysAsync(ct);

        (await act.Should().ThrowAsync<ZeeKayDaConfigurationException>())
            .WithMessage("*no_active_key*");
    }

    [Fact]
    public async Task GetSigningKeysAsync_throws_clear_exception_when_no_version_has_activated_yet()
    {
        // The sole-ever-version bootstrap exemption (base SigningKeyRotation.SelectActiveKey) only
        // applies when exactly one version has ever existed — with two versions on the timeline, a
        // NotBefore-delayed second version is genuinely not yet eligible, and the first version's own
        // NotBefore (also in the future) means neither can be selected as active.
        var ct = TestContext.Current.CancellationToken;
        var t0 = DateTimeOffset.Parse("2026-01-01T00:00:00Z");
        var reader = new FakeKeyVaultCertificateReader();
        reader.AddRsaVersion("v1", createdOn: t0, notBefore: t0 + TimeSpan.FromDays(1));
        reader.AddRsaVersion("v2", createdOn: t0 + TimeSpan.FromHours(1), notBefore: t0 + TimeSpan.FromDays(2));
        var timeProvider = new FakeTimeProvider(t0);

        await using var sut = BuildService(reader, timeProvider);

        var act = async () => await sut.GetSigningKeysAsync(ct);

        (await act.Should().ThrowAsync<ZeeKayDaConfigurationException>())
            .WithMessage("*no_active_key*");
    }

    [Fact]
    public async Task SignAsync_releases_the_previously_cached_private_key_once_every_version_becomes_disabled()
    {
        // Regression test (issue #425 security review, finding F2): once Key Vault reports zero
        // enabled versions — e.g. an operator disabling every version as part of an emergency
        // revocation — the previously cached active signer's private key material must not be left
        // resident in process memory indefinitely. ListKeysAsync throwing "no_active_key" on the next
        // refresh must release it immediately rather than waiting for a later successful refresh or
        // process shutdown to clean it up.
        var ct = TestContext.Current.CancellationToken;
        var t0 = DateTimeOffset.Parse("2026-01-01T00:00:00Z");
        var reader = new FakeKeyVaultCertificateReader();
        reader.AddRsaVersion("v1", createdOn: t0);
        AsymmetricAlgorithm? capturedPrivateKey = null;
        reader.OnPrivateKeyExtracted = (_, key) => capturedPrivateKey = key;
        var timeProvider = new FakeTimeProvider(t0);

        await using var sut = BuildService(reader, timeProvider, refreshInterval: DefaultRefreshInterval, publicationLead: DefaultPublicationLead);
        await sut.SignAsync("payload"u8.ToArray(), ct); // Downloads and caches v1's private key.
        capturedPrivateKey.Should().NotBeNull();

        reader.SetEnabled("v1", enabled: false);
        timeProvider.SetUtcNow(t0 + DefaultRefreshInterval + TimeSpan.FromSeconds(1));

        var act = async () => await sut.SignAsync("payload"u8.ToArray(), ct);
        (await act.Should().ThrowAsync<ZeeKayDaConfigurationException>())
            .WithMessage("*no_active_key*");

        var useAfterRevocation = () => ((RSA)capturedPrivateKey!).ExportParameters(includePrivateParameters: true);
        useAfterRevocation.Should().Throw<ObjectDisposedException>(
            "the cached private key must be released as soon as Key Vault reports zero enabled versions, " +
            "not left resident in process memory until a later successful refresh or shutdown");
    }

    [Fact]
    public async Task SignAsync_does_not_promote_a_not_yet_active_successor_early_after_predecessor_is_revoked_on_a_live_refresh()
    {
        // Regression test (issue #425 security review, findings F1 and F1-2): the single-key
        // bootstrap exemption must never fire for this (Tier B) provider, on any refresh - including
        // a *live* refresh that merely happens to shrink the listing down to one key via operator
        // revocation, not a genuine cold start. Without the fix (gating the exemption on
        // "isBootstrapSnapshot" - true on every process's first-ever snapshot, restart included -
        // rather than on the provider's tier), disabling every key but a not-yet-due successor would
        // instantly promote that successor, bypassing PublicationLead - and, unlike the version of
        // this bug the original F1 fix closed, this replay would re-occur on every fresh instance
        // (a restart or a scaled-out replica) started while the revocation is still in effect.
        var ct = TestContext.Current.CancellationToken;
        var t0 = DateTimeOffset.Parse("2026-01-01T00:00:00Z");
        var refreshInterval = TimeSpan.FromMinutes(5);
        var publicationLead = TimeSpan.FromHours(1);
        var reader = new FakeKeyVaultCertificateReader();
        reader.AddRsaVersion("v1", createdOn: t0);
        var timeProvider = new FakeTimeProvider(t0);

        await using var sut = BuildService(reader, timeProvider, refreshInterval: refreshInterval, publicationLead: publicationLead);
        await sut.SignAsync("payload"u8.ToArray(), ct); // Bootstrap load: v1 active.

        reader.AddRsaVersion("v2", createdOn: t0); // v2's ActivateAt is t0 + publicationLead - still an hour away.
        timeProvider.SetUtcNow(t0 + refreshInterval + TimeSpan.FromSeconds(1)); // Cache expired: a live (non-bootstrap) refresh.
        await sut.SignAsync("payload"u8.ToArray(), ct); // v1 still active; v2 published but not yet active.

        reader.SetEnabled("v1", enabled: false);
        // Another live refresh; well before v2's ActivateAt (t0 + 1 hour). The listing now contains
        // only v2, so timeline.Count == 1 - exactly the shape the bootstrap exemption keys off.
        timeProvider.SetUtcNow(t0 + (2 * refreshInterval) + TimeSpan.FromSeconds(2));

        var act = async () => await sut.SignAsync("payload"u8.ToArray(), ct);

        (await act.Should().ThrowAsync<ZeeKayDaConfigurationException>())
            .WithMessage(
                "*no_active_key*",
                "v2 has not yet reached its own ActivateAt and must fail closed rather than being " +
                "promoted early just because a live revocation happened to leave it as the sole listed key");
    }

    [Fact]
    public async Task SignAsync_does_not_release_the_active_signer_when_the_callers_own_cancellation_token_fires_mid_refresh()
    {
        // Regression test (issue #425 security review, finding F2-1): a caller's own cancellation
        // (e.g. a client disconnect) firing mid-refresh is not a signal about the cached signer's
        // health, and must not release it. Without the fix, a client could repeatedly cancel requests
        // to force a perfectly healthy cached signer to be torn down and its private key
        // re-downloaded from Key Vault on every subsequent call - a remotely triggerable
        // amplification vector against Key Vault requiring no actual key compromise.
        var ct = TestContext.Current.CancellationToken;
        var t0 = DateTimeOffset.Parse("2026-01-01T00:00:00Z");
        var reader = new FakeKeyVaultCertificateReader();
        reader.AddRsaVersion("v1", createdOn: t0);
        AsymmetricAlgorithm? capturedPrivateKey = null;
        reader.OnPrivateKeyExtracted = (_, key) => capturedPrivateKey = key;
        var timeProvider = new FakeTimeProvider(t0);

        await using var sut = BuildService(reader, timeProvider, refreshInterval: DefaultRefreshInterval, publicationLead: DefaultPublicationLead);
        await sut.SignAsync("payload"u8.ToArray(), ct); // Downloads and caches v1's private key.
        capturedPrivateKey.Should().NotBeNull();
        reader.PrivateKeyMaterialCalls.Should().ContainSingle();

        timeProvider.SetUtcNow(t0 + DefaultRefreshInterval + TimeSpan.FromSeconds(1)); // Cache expired: next call refreshes.
        using var cts = new CancellationTokenSource();
        // Cancelled deterministically once the refresh has already acquired the base class's internal
        // snapshot lock and started enumerating versions - simulating the caller's own request being
        // cancelled mid-refresh (e.g. a client disconnect), not before the refresh even begins.
        reader.CancelDuringVersionEnumeration = cts;

        var act = async () => await sut.SignAsync("payload"u8.ToArray(), cts.Token);
        await act.Should().ThrowAsync<OperationCanceledException>();

        var stillUsable = () => ((RSA)capturedPrivateKey!).ExportParameters(includePrivateParameters: true);
        stillUsable.Should().NotThrow(
            "a caller-driven cancellation must not release the previously cached, still-healthy signer");

        var afterCancellation = await sut.SignAsync("payload"u8.ToArray(), ct);
        afterCancellation.Should().NotBeNull();
        reader.PrivateKeyMaterialCalls.Should().ContainSingle(
            "the signer must be reused, not re-created (and its private key re-downloaded), once the " +
            "caller's cancellation has passed and a normal call succeeds");
    }

    // ── Startup failure propagation ──────────────────────────────────────────────────────────────

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

        // The active version's private key is only requested by CreateSignerAsync (called lazily on
        // first sign, not by GetSigningKeysAsync/ListKeysAsync).
        var act = async () => await sut.SignAsync("payload"u8.ToArray(), ct);

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

    // ── Completeness contract: a failed read must throw, not return a partial list ───────────────

    [Fact]
    public async Task GetSigningKeysAsync_throws_rather_than_returning_a_partial_list_when_a_later_version_fails_to_load()
    {
        var ct = TestContext.Current.CancellationToken;
        var t0 = DateTimeOffset.Parse("2026-01-01T00:00:00Z");
        var reader = new FakeKeyVaultCertificateReader();
        reader.AddRsaVersion("v0", createdOn: t0 - TimeSpan.FromDays(1));
        reader.AddRsaVersion("v1", createdOn: t0, notBefore: t0 + TimeSpan.FromDays(2)); // Published, not yet active.
        reader.SetPublicKeyException("v1", new ZeeKayDaConfigurationException(
            new ZeeKayDaConfigurationFailure("signing.azure_key_vault.access_denied", "Simulated failure for v1.")));
        var timeProvider = new FakeTimeProvider(t0);

        await using var sut = BuildService(reader, timeProvider);

        var act = async () => await sut.GetSigningKeysAsync(ct);

        (await act.Should().ThrowAsync<ZeeKayDaConfigurationException>())
            .WithMessage("*access_denied*");
    }

    [Fact]
    public async Task GetSigningKeysAsync_disposes_active_public_only_handle_when_BuildDescriptor_throws_for_it()
    {
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
        var useAfterFailure = () => ((RSA)capturedKey!).ExportParameters(includePrivateParameters: false);
        useAfterFailure.Should().Throw<ObjectDisposedException>(
            "the public-only key handle extracted before BuildDescriptor's failure must not be leaked");
    }

    // ── Private key material: only downloaded (and only via CreateSignerAsync) for the active key ──

    [Fact]
    public async Task ListKeysAsync_never_downloads_real_private_key_material_only_public_key_material()
    {
        var ct = TestContext.Current.CancellationToken;
        var t0 = DateTimeOffset.Parse("2026-01-01T00:00:00Z");
        var reader = new FakeKeyVaultCertificateReader();
        reader.AddRsaVersion("v1", createdOn: t0);
        var timeProvider = new FakeTimeProvider(t0);

        await using var sut = BuildService(reader, timeProvider);
        await sut.GetSigningKeysAsync(ct);

        reader.PrivateKeyMaterialCalls.Should().BeEmpty(
            "ListKeysAsync must only ever build public-only listings; real private key material is only " +
            "fetched lazily by CreateSignerAsync for the active key");
        reader.PublicKeyMaterialCalls.Should().Contain("v1");
    }

    [Fact]
    public async Task CreateSignerAsync_downloads_real_private_key_material_only_for_the_active_version()
    {
        var ct = TestContext.Current.CancellationToken;
        var t0 = DateTimeOffset.Parse("2026-01-01T00:00:00Z");
        var t1 = t0 + TimeSpan.FromDays(1);
        var reader = new FakeKeyVaultCertificateReader();
        reader.AddRsaVersion("v1", createdOn: t0);
        var timeProvider = new FakeTimeProvider(t0);

        await using var sut = BuildService(reader, timeProvider, refreshInterval: DefaultRefreshInterval, publicationLead: DefaultPublicationLead);
        reader.AddRsaVersion("v2", createdOn: t1);
        timeProvider.SetUtcNow(t1); // v2 published but not yet active.

        var keys = await sut.GetSigningKeysAsync(ct);
        keys.Should().HaveCount(2);

        await sut.SignAsync("payload"u8.ToArray(), ct);

        reader.PrivateKeyMaterialCalls.Should().OnlyContain(v => v == "v1",
            "real private key material must only ever be downloaded for the active version");
    }

    [Fact]
    public async Task SignAsync_does_not_re_download_private_key_material_across_multiple_signs()
    {
        var ct = TestContext.Current.CancellationToken;
        var t0 = DateTimeOffset.Parse("2026-01-01T00:00:00Z");
        var reader = new FakeKeyVaultCertificateReader();
        reader.AddRsaVersion("v1", createdOn: t0);
        var timeProvider = new FakeTimeProvider(t0);

        await using var sut = BuildService(reader, timeProvider);
        await sut.SignAsync("payload-1"u8.ToArray(), ct); // First sign: creates and caches the signer.
        var callsAfterFirstSign = reader.PrivateKeyMaterialCalls.Count;

        await sut.SignAsync("payload-2"u8.ToArray(), ct);
        await sut.SignAsync("payload-3"u8.ToArray(), ct);

        reader.PrivateKeyMaterialCalls.Should().HaveCount(callsAfterFirstSign,
            "signing must reuse the already-created local signer — no Key Vault round trip per sign");
    }

    [Fact]
    public async Task SignAsync_produces_a_signature_verifiable_with_the_certificate_s_public_key()
    {
        var ct = TestContext.Current.CancellationToken;
        var t0 = DateTimeOffset.Parse("2026-01-01T00:00:00Z");
        var reader = new FakeKeyVaultCertificateReader();
        reader.AddRsaVersion("v1", createdOn: t0);
        var timeProvider = new FakeTimeProvider(t0);

        await using var sut = BuildService(reader, timeProvider, algorithm: SigningAlgorithm.RS256);
        await sut.GetSigningKeysAsync(ct);

        var payloadSegment = "payload"u8.ToArray();
        var result = await sut.SignAsync(payloadSegment, ct);

        using var rsa = RSA.Create();
        rsa.ImportParameters(reader.GetRsaMaterial("v1"));

        var actualSigningInput = new byte[result.HeaderSegment.Length + 1 + payloadSegment.Length];
        result.HeaderSegment.Span.CopyTo(actualSigningInput);
        actualSigningInput[result.HeaderSegment.Length] = (byte)'.';
        payloadSegment.CopyTo(actualSigningInput.AsSpan(result.HeaderSegment.Length + 1));
        var signatureBytes = Base64UrlDecode(result.SignatureSegment.ToArray());

        var isValid = rsa.VerifyData(
            actualSigningInput, signatureBytes, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);

        isValid.Should().BeTrue("the signature must be verifiable against the certificate's own public key");
    }

    // ── Refresh cadence (Tier B / ADR 0015) ──────────────────────────────────────────────────────

    [Fact]
    public async Task ListKeysAsync_is_called_once_per_RefreshInterval()
    {
        var ct = TestContext.Current.CancellationToken;
        var t0 = DateTimeOffset.Parse("2026-01-01T00:00:00Z");
        var reader = new FakeKeyVaultCertificateReader();
        reader.AddRsaVersion("v1", createdOn: t0);
        var timeProvider = new FakeTimeProvider(t0);

        await using var sut = BuildService(reader, timeProvider, refreshInterval: DefaultRefreshInterval);
        await sut.GetSigningKeysAsync(ct); // Bootstrap load.
        var enumerationCallsAfterBootstrap = reader.GetCertificateVersionsCallCount;

        await sut.GetSigningKeysAsync(ct); // Still within the refresh window — no re-enumeration.

        reader.GetCertificateVersionsCallCount.Should().Be(enumerationCallsAfterBootstrap);

        timeProvider.SetUtcNow(t0 + DefaultRefreshInterval);
        await sut.GetSigningKeysAsync(ct);

        reader.GetCertificateVersionsCallCount.Should().Be(enumerationCallsAfterBootstrap + 1,
            "once RefreshInterval has elapsed, ListKeysAsync must re-enumerate Key Vault's version list");
    }

    // ── Vanished-kid / within-window-vanish Warning (shared base, ADR 0015 §6) ──────────────────

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
        var logger = new CapturingLogger<JwtSigningService<AzureKeyVaultCachedSigningOptions>>();

        await using var sut = BuildService(
            reader, timeProvider, refreshInterval: DefaultRefreshInterval, publicationLead: DefaultPublicationLead,
            retirementWindow: retirementWindow, logger: logger);
        await sut.GetSigningKeysAsync(ct); // Bootstrap: v1 active.

        reader.AddRsaVersion("v2", createdOn: t1);
        timeProvider.SetUtcNow(t1 + DefaultPublicationLead + retirementWindow + TimeSpan.FromMinutes(1));
        var keys = await sut.GetSigningKeysAsync(ct);

        keys.Should().ContainSingle("v1's retirement window has fully elapsed");
        logger.Entries.Should().NotContain(e => e.Level == LogLevel.Warning,
            "v1's certificate version is still present in Key Vault, merely excluded for having aged past " +
            "its retirement window — an expected exclusion, not the anomaly ADR 0015 §6 warns about");
    }

    [Fact]
    public async Task GetSigningKeysAsync_warns_when_a_previously_published_kid_s_certificate_version_disappears_from_key_vault_entirely_within_the_retirement_window()
    {
        var ct = TestContext.Current.CancellationToken;
        var t0 = DateTimeOffset.Parse("2026-01-01T00:00:00Z");
        var t1 = t0 + TimeSpan.FromDays(1);
        var retirementWindow = TimeSpan.FromHours(1);
        var reader = new FakeKeyVaultCertificateReader();
        var v1 = reader.AddRsaVersion("v1", createdOn: t0);
        var timeProvider = new FakeTimeProvider(t0);
        var logger = new CapturingLogger<JwtSigningService<AzureKeyVaultCachedSigningOptions>>();

        await using var sut = BuildService(
            reader, timeProvider, refreshInterval: DefaultRefreshInterval, publicationLead: DefaultPublicationLead,
            retirementWindow: retirementWindow, logger: logger);
        await sut.GetSigningKeysAsync(ct); // Bootstrap: v1 active, published.

        reader.AddRsaVersion("v2", createdOn: t1);
        timeProvider.SetUtcNow(t1 + DefaultPublicationLead); // v2 activates; v1 would normally still be in its retirement window.

        // Simulate an operator (or a misbehaving external process) deleting v1's certificate version
        // from Key Vault outright, well before its retirement window has elapsed.
        reader.Versions.RemoveAll(version => version.Version == v1.Version);

        var keys = await sut.GetSigningKeysAsync(ct);

        keys.Should().ContainSingle("v1 is gone from Key Vault entirely, so it cannot be included any more");
        logger.Entries.Should().Contain(e => e.Level == LogLevel.Warning,
            "a previously-published key vanishing from Key Vault entirely, before its retirement window " +
            "elapsed, must be surfaced as a Warning per ADR 0015 §6");
    }

    [Fact]
    public async Task GetSigningKeysAsync_warns_when_a_previously_published_kid_s_certificate_version_is_disabled_within_the_retirement_window()
    {
        // Regression test (issue #425 security review, finding F9b): the actual emergency-revocation
        // path an operator uses is disabling a version in Key Vault, not deleting it outright. The
        // version stays present in the vault's version list, merely no longer enabled/returned by
        // ListKeysAsync — the same within-window-vanish Warning must fire for this path too, not only
        // for outright deletion.
        var ct = TestContext.Current.CancellationToken;
        var t0 = DateTimeOffset.Parse("2026-01-01T00:00:00Z");
        var t1 = t0 + TimeSpan.FromDays(1);
        var retirementWindow = TimeSpan.FromHours(1);
        var reader = new FakeKeyVaultCertificateReader();
        reader.AddRsaVersion("v1", createdOn: t0);
        var timeProvider = new FakeTimeProvider(t0);
        var logger = new CapturingLogger<JwtSigningService<AzureKeyVaultCachedSigningOptions>>();

        await using var sut = BuildService(
            reader, timeProvider, refreshInterval: DefaultRefreshInterval, publicationLead: DefaultPublicationLead,
            retirementWindow: retirementWindow, logger: logger);
        await sut.GetSigningKeysAsync(ct); // Bootstrap: v1 active, published.

        reader.AddRsaVersion("v2", createdOn: t1);
        timeProvider.SetUtcNow(t1 + DefaultPublicationLead); // v2 activates; v1 would normally still be in its retirement window.

        // Emergency revocation: disable v1 in Key Vault (still present in the version list) rather
        // than deleting it.
        reader.SetEnabled("v1", enabled: false);

        var keys = await sut.GetSigningKeysAsync(ct);

        keys.Should().ContainSingle("v1 is disabled, so the kill switch drops it immediately");
        logger.Entries.Should().Contain(e => e.Level == LogLevel.Warning,
            "disabling a previously-published key while still inside its retirement window is the real " +
            "emergency-revocation procedure, and must be surfaced as a Warning per ADR 0015 §6 exactly " +
            "like outright deletion");
    }

    // ── Private/public key cross-check (issue #425 security review, finding F3) ────────────────────

    [Fact]
    public async Task SignAsync_throws_AzureKeyVaultSigningException_when_the_downloaded_private_key_does_not_match_the_listed_public_key()
    {
        var ct = TestContext.Current.CancellationToken;
        var t0 = DateTimeOffset.Parse("2026-01-01T00:00:00Z");
        var reader = new FakeKeyVaultCertificateReader();
        reader.AddRsaVersion("v1", createdOn: t0);
        var timeProvider = new FakeTimeProvider(t0);

        // Simulate the certificate's linked secret (private key material) having diverged from its
        // Cer (public key material published in the JWKS) — two separate Key Vault reads that
        // should always agree, but which this cross-check exists to verify rather than assume.
        using var divergentRsa = RSA.Create(2048);
        reader.SetMismatchedPrivateKeyMaterial("v1", divergentRsa.ExportParameters(includePrivateParameters: true));

        await using var sut = BuildService(reader, timeProvider);
        await sut.GetSigningKeysAsync(ct); // Publishes v1's (unmodified) public key in the JWKS.

        var act = async () => await sut.SignAsync("payload"u8.ToArray(), ct);

        (await act.Should().ThrowAsync<AzureKeyVaultSigningException>())
            .WithMessage("*does not match*");
    }

    [Fact]
    public async Task SignAsync_disposes_the_mismatched_private_key_before_throwing()
    {
        var ct = TestContext.Current.CancellationToken;
        var t0 = DateTimeOffset.Parse("2026-01-01T00:00:00Z");
        var reader = new FakeKeyVaultCertificateReader();
        reader.AddRsaVersion("v1", createdOn: t0);
        using var divergentRsa = RSA.Create(2048);
        reader.SetMismatchedPrivateKeyMaterial("v1", divergentRsa.ExportParameters(includePrivateParameters: true));

        AsymmetricAlgorithm? capturedPrivateKey = null;
        reader.OnPrivateKeyExtracted = (_, key) => capturedPrivateKey = key;

        var timeProvider = new FakeTimeProvider(t0);
        await using var sut = BuildService(reader, timeProvider);
        await sut.GetSigningKeysAsync(ct);

        var act = async () => await sut.SignAsync("payload"u8.ToArray(), ct);
        await act.Should().ThrowAsync<AzureKeyVaultSigningException>();

        capturedPrivateKey.Should().NotBeNull();
        var useAfterFailure = () => ((RSA)capturedPrivateKey!).ExportParameters(includePrivateParameters: true);
        useAfterFailure.Should().Throw<ObjectDisposedException>(
            "the downloaded private key must not be leaked once the cross-check against the listed " +
            "public key fails");
    }

    [Fact]
    public async Task SignAsync_succeeds_when_the_downloaded_private_key_matches_the_listed_public_key()
    {
        var ct = TestContext.Current.CancellationToken;
        var t0 = DateTimeOffset.Parse("2026-01-01T00:00:00Z");
        var reader = new FakeKeyVaultCertificateReader();
        reader.AddRsaVersion("v1", createdOn: t0);
        var timeProvider = new FakeTimeProvider(t0);

        await using var sut = BuildService(reader, timeProvider);
        await sut.GetSigningKeysAsync(ct);

        var act = async () => await sut.SignAsync("payload"u8.ToArray(), ct);

        await act.Should().NotThrowAsync(
            "the private and public halves of the same version, read normally, must always match");
    }

    [Fact]
    public async Task SignAsync_succeeds_for_an_EC_version_when_the_downloaded_private_key_matches_the_listed_public_key()
    {
        var ct = TestContext.Current.CancellationToken;
        var t0 = DateTimeOffset.Parse("2026-01-01T00:00:00Z");
        var reader = new FakeKeyVaultCertificateReader();
        reader.AddEcVersion("v1", createdOn: t0);
        var timeProvider = new FakeTimeProvider(t0);

        await using var sut = BuildService(reader, timeProvider, algorithm: SigningAlgorithm.ES256);
        await sut.GetSigningKeysAsync(ct);

        var act = async () => await sut.SignAsync("payload"u8.ToArray(), ct);

        await act.Should().NotThrowAsync(
            "the private and public halves of the same EC version, read normally, must always match");
    }

    [Fact]
    public async Task SignAsync_throws_AzureKeyVaultSigningException_when_the_downloaded_EC_private_key_does_not_match_the_listed_public_key()
    {
        var ct = TestContext.Current.CancellationToken;
        var t0 = DateTimeOffset.Parse("2026-01-01T00:00:00Z");
        var reader = new FakeKeyVaultCertificateReader();
        reader.AddEcVersion("v1", createdOn: t0);
        var timeProvider = new FakeTimeProvider(t0);

        using var divergentEc = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        reader.SetMismatchedPrivateKeyMaterial("v1", divergentEc.ExportParameters(includePrivateParameters: true));

        await using var sut = BuildService(reader, timeProvider, algorithm: SigningAlgorithm.ES256);
        await sut.GetSigningKeysAsync(ct);

        var act = async () => await sut.SignAsync("payload"u8.ToArray(), ct);

        (await act.Should().ThrowAsync<AzureKeyVaultSigningException>())
            .WithMessage("*does not match*");
    }

    [Fact]
    public async Task SignAsync_throws_AzureKeyVaultSigningException_when_the_downloaded_private_key_type_disagrees_with_the_listed_public_key_type()
    {
        // A different flavor of divergence than a same-type key mismatch: here the certificate's
        // linked secret disagrees with its Cer not just on the key values but on the key *type*
        // itself (RSA vs EC) — neither switch arm in VerifyPrivateKeyMatchesListedPublicKey matches,
        // so it must still fail closed via the default (false) arm rather than silently accepting it.
        var ct = TestContext.Current.CancellationToken;
        var t0 = DateTimeOffset.Parse("2026-01-01T00:00:00Z");
        var reader = new FakeKeyVaultCertificateReader();
        reader.AddRsaVersion("v1", createdOn: t0); // Listed publicly as RSA.
        var timeProvider = new FakeTimeProvider(t0);

        using var ecKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        reader.SetMismatchedPrivateKeyMaterial("v1", ecKey.ExportParameters(includePrivateParameters: true)); // Downloads as EC.

        await using var sut = BuildService(reader, timeProvider);
        await sut.GetSigningKeysAsync(ct);

        var act = async () => await sut.SignAsync("payload"u8.ToArray(), ct);

        (await act.Should().ThrowAsync<AzureKeyVaultSigningException>())
            .WithMessage("*does not match*");
    }

    private static byte[] Base64UrlDecode(byte[] base64UrlBytes)
    {
        var text = System.Text.Encoding.ASCII.GetString(base64UrlBytes).Replace('-', '+').Replace('_', '/');
        return Convert.FromBase64String(text.PadRight(text.Length + ((4 - (text.Length % 4)) % 4), '='));
    }
}
