using System.Security.Cryptography;
using Azure.Security.KeyVault.Keys;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Microsoft.Extensions.Time.Testing;
using ZeeKayDa.Auth.AzureKeyVault.Tests.Fakes;
using ZeeKayDa.Auth.Logging;
using ZeeKayDa.Auth.Tokens;

namespace ZeeKayDa.Auth.AzureKeyVault.Tests;

public sealed class AzureKeyVaultRemoteSigningJwtSigningServiceTests
{
    private static readonly Uri KeyIdentifierUri = new("https://fake-vault.vault.azure.net/keys/fake-key");
    private static readonly TimeSpan DefaultRefreshInterval = TimeSpan.FromMinutes(5);
    private static readonly TimeSpan DefaultPublicationLead = TimeSpan.FromMinutes(5);
    private static readonly TimeSpan DefaultRetirementWindow = TimeSpan.FromHours(1);

    private sealed class CapturingLogger<T> : ISanitizingLogger<T>
    {
        public List<(LogLevel Level, string Message)> Entries { get; } = [];

        public IDisposable? BeginScope<TState>(TState state) where TState : notnull => null;

        public bool IsEnabled(LogLevel logLevel) => true;

        public void Log<TState>(
            LogLevel logLevel, EventId eventId, TState state, Exception? exception, Func<TState, Exception?, string> formatter)
            => Entries.Add((logLevel, formatter(state, exception)));
    }

    /// <summary>
    /// A <see cref="FakeKeyVaultSigner.SignFunc"/> that signs with the real private key material
    /// <paramref name="reader"/> retained for whichever key version <paramref name="uri"/> targets,
    /// so the ADR 0015 §11 self-test (issue #437) — which every active-key handoff now runs, not
    /// just real token signing — sees a genuinely verifiable signature. RS256 only, matching every
    /// test in this file that exercises <c>SignAsync</c>.
    /// </summary>
    private static Func<Uri, string, SigningAlgorithm, byte[], ReadOnlyMemory<byte>> RealRsaSignFunc(FakeKeyVaultKeyReader reader) =>
        (uri, _, _, signingInput) =>
        {
            var version = uri.Segments[^1];
            using var rsa = reader.CreateRsaPrivateKey(version);
            return rsa.SignData(signingInput, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        };

    private static AzureKeyVaultRemoteSigningJwtSigningService BuildService(
        FakeKeyVaultKeyReader reader,
        FakeTimeProvider timeProvider,
        TimeSpan? refreshInterval = null,
        TimeSpan? publicationLead = null,
        TimeSpan? retirementWindow = null,
        FakeKeyVaultSigner? signer = null,
        SigningAlgorithm algorithm = SigningAlgorithm.RS256,
        ISanitizingLogger<JwtSigningService<AzureKeyVaultRemoteSigningOptions>>? logger = null)
    {
        var options = Options.Create(new AzureKeyVaultRemoteSigningOptions
        {
            KeyIdentifier = new KeyVaultKeyIdentifier(KeyIdentifierUri),
            Credential = new FakeTokenCredential(),
            Algorithm = algorithm,
            RefreshInterval = refreshInterval ?? DefaultRefreshInterval,
            PublicationLead = publicationLead ?? DefaultPublicationLead,
        });

        return new AzureKeyVaultRemoteSigningJwtSigningService(
            options,
            timeProvider,
            reader,
            signer ?? new FakeKeyVaultSigner(),
            new FakeRetirementWindowProvider(retirementWindow ?? DefaultRetirementWindow),
            logger ?? NullSanitizingLogger<JwtSigningService<AzureKeyVaultRemoteSigningOptions>>.Instance);
    }

    // ── Bootstrap ────────────────────────────────────────────────────────────────────────────────

    [Fact]
    public async Task GetSigningKeysAsync_first_ever_version_is_active_immediately_no_bootstrap_wait()
    {
        var ct = TestContext.Current.CancellationToken;
        var t0 = DateTimeOffset.Parse("2026-01-01T00:00:00Z");
        var reader = new FakeKeyVaultKeyReader();
        var v1 = reader.AddRsaVersion("v1", createdOn: t0);
        var timeProvider = new FakeTimeProvider(t0);

        await using var sut = BuildService(reader, timeProvider);

        var keys = await sut.GetSigningKeysAsync(ct);

        keys.Should().HaveCount(1);
        keys[0].Kid.Should().Be(JwkThumbprint.Compute(reader.GetRsaMaterial(v1.Version)));
    }

    // ── Normal rotation: publish-then-activate, overlap, retirement ─────────────────────────────────

    [Fact]
    public async Task GetSigningKeysAsync_rotated_in_version_is_published_but_not_yet_active()
    {
        var ct = TestContext.Current.CancellationToken;
        var t0 = DateTimeOffset.Parse("2026-01-01T00:00:00Z");
        var t1 = t0 + TimeSpan.FromDays(1);
        var reader = new FakeKeyVaultKeyReader();
        reader.AddRsaVersion("v1", createdOn: t0);
        var timeProvider = new FakeTimeProvider(t0);

        await using var sut = BuildService(reader, timeProvider, refreshInterval: DefaultRefreshInterval, publicationLead: DefaultPublicationLead);
        await sut.GetSigningKeysAsync(ct); // Prime the initial (bootstrap) load.

        reader.AddRsaVersion("v2", createdOn: t1);
        timeProvider.SetUtcNow(t1); // Cache has expired -> re-list.

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
        var reader = new FakeKeyVaultKeyReader();
        reader.AddRsaVersion("v1", createdOn: t0);
        var timeProvider = new FakeTimeProvider(t0);

        await using var sut = BuildService(
            reader, timeProvider, refreshInterval: DefaultRefreshInterval, publicationLead: DefaultPublicationLead,
            retirementWindow: DefaultRetirementWindow);
        await sut.GetSigningKeysAsync(ct); // Bootstrap load.

        reader.AddRsaVersion("v2", createdOn: t1);
        timeProvider.SetUtcNow(t1 + DefaultPublicationLead); // v2's ActivateAt, exactly.

        var keys = await sut.GetSigningKeysAsync(ct);

        keys.Should().HaveCount(2, "v1 must still overlap with v2 (relying parties may hold tokens signed by either)");
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
        var reader = new FakeKeyVaultKeyReader();
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
        var reader = new FakeKeyVaultKeyReader();
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
            "a disabled key is excluded at once, not gradually faded out over its retirement window");
    }

    // ── NotBefore-delayed successor: predecessor still gets its full, correct retirement window ─────

    [Fact]
    public async Task GetSigningKeysAsync_notbefore_delayed_successor_still_grants_predecessor_correct_retirement()
    {
        var ct = TestContext.Current.CancellationToken;
        var t0 = DateTimeOffset.Parse("2026-01-01T00:00:00Z");
        var t1 = t0 + TimeSpan.FromDays(1);
        var notBefore = t1 + TimeSpan.FromDays(5); // Deliberately scheduled well past t1 + PublicationLead.
        var retirementWindow = TimeSpan.FromHours(2);
        var reader = new FakeKeyVaultKeyReader();
        reader.AddRsaVersion("v1", createdOn: t0);
        var timeProvider = new FakeTimeProvider(t0);

        await using var sut = BuildService(
            reader, timeProvider, refreshInterval: DefaultRefreshInterval, publicationLead: DefaultPublicationLead,
            retirementWindow: retirementWindow);
        await sut.GetSigningKeysAsync(ct);

        reader.AddRsaVersion("v2", createdOn: t1, notBefore: notBefore);

        timeProvider.SetUtcNow(t1 + DefaultPublicationLead);
        var beforeNotBefore = await sut.GetSigningKeysAsync(ct);
        beforeNotBefore[0].Kid.Should().Be(JwkThumbprint.Compute(reader.GetRsaMaterial("v1")));
        beforeNotBefore.Should().HaveCount(2);

        timeProvider.SetUtcNow(notBefore + TimeSpan.FromMinutes(1));
        var justAfterHandover = await sut.GetSigningKeysAsync(ct);
        justAfterHandover[0].Kid.Should().Be(JwkThumbprint.Compute(reader.GetRsaMaterial("v2")));
        justAfterHandover.Should().Contain(k => k.Kid == JwkThumbprint.Compute(reader.GetRsaMaterial("v1")),
            "v1 must still be within its retirement window measured from v2's real (NotBefore-gated) activation");

        timeProvider.SetUtcNow(notBefore + retirementWindow + TimeSpan.FromHours(1));
        var wellAfterHandover = await sut.GetSigningKeysAsync(ct);
        wellAfterHandover.Should().ContainSingle();
        wellAfterHandover[0].Kid.Should().Be(JwkThumbprint.Compute(reader.GetRsaMaterial("v2")));
    }

    // ── Kid derivation ───────────────────────────────────────────────────────────────────────────

    [Fact]
    public async Task GetSigningKeysAsync_kid_is_thumbprint_and_never_contains_vault_or_key_identifiers()
    {
        var ct = TestContext.Current.CancellationToken;
        var t0 = DateTimeOffset.Parse("2026-01-01T00:00:00Z");
        var reader = new FakeKeyVaultKeyReader();
        reader.AddRsaVersion("super-secret-version-guid-1234", createdOn: t0);
        var timeProvider = new FakeTimeProvider(t0);

        await using var sut = BuildService(reader, timeProvider);
        var keys = await sut.GetSigningKeysAsync(ct);

        keys[0].Kid.Should().NotContain("fake-vault");
        keys[0].Kid.Should().NotContain("fake-key");
        keys[0].Kid.Should().NotContain("super-secret-version-guid-1234");
    }

    [Fact]
    public async Task GetSigningKeysAsync_two_simultaneously_live_versions_with_identical_material_fail_closed_on_duplicate_kid()
    {
        var ct = TestContext.Current.CancellationToken;
        var t0 = DateTimeOffset.Parse("2026-01-01T00:00:00Z");
        var reader = new FakeKeyVaultKeyReader();
        reader.AddRsaVersion("v1", createdOn: t0);
        reader.AddRsaVersionWithSameMaterialAs("v1-copy", sourceVersion: "v1", createdOn: t0);
        var timeProvider = new FakeTimeProvider(t0);

        await using var sut = BuildService(reader, timeProvider);

        var act = async () => await sut.GetSigningKeysAsync(ct);

        (await act.Should().ThrowAsync<ZeeKayDaConfigurationException>())
            .WithMessage("*duplicate_kid*");
    }

    // ── Key types: RSA / EC / RSA-HSM / EC-HSM ───────────────────────────────────────────────────

    [Fact]
    public async Task GetSigningKeysAsync_builds_correct_descriptor_for_rsa_key()
    {
        var ct = TestContext.Current.CancellationToken;
        var t0 = DateTimeOffset.Parse("2026-01-01T00:00:00Z");
        var reader = new FakeKeyVaultKeyReader();
        reader.AddRsaVersion("v1", createdOn: t0);
        var timeProvider = new FakeTimeProvider(t0);

        await using var sut = BuildService(reader, timeProvider, algorithm: SigningAlgorithm.RS256);
        var keys = await sut.GetSigningKeysAsync(ct);

        keys[0].KeyType.Should().Be(SigningKeyType.Rsa);
        keys[0].RsaPublicParameters.Should().NotBeNull();
    }

    [Fact]
    public async Task GetSigningKeysAsync_builds_correct_descriptor_for_ec_key()
    {
        var ct = TestContext.Current.CancellationToken;
        var t0 = DateTimeOffset.Parse("2026-01-01T00:00:00Z");
        var reader = new FakeKeyVaultKeyReader();
        reader.AddEcVersion("v1", createdOn: t0);
        var timeProvider = new FakeTimeProvider(t0);

        await using var sut = BuildService(reader, timeProvider, algorithm: SigningAlgorithm.ES256);
        var keys = await sut.GetSigningKeysAsync(ct);

        keys[0].KeyType.Should().Be(SigningKeyType.Ec);
        keys[0].EcPublicParameters.Should().NotBeNull();
    }

    // ── Algorithm / key-type mismatch ────────────────────────────────────────────────────────────

    [Fact]
    public async Task GetSigningKeysAsync_throws_clear_exception_when_ec_algorithm_configured_against_rsa_key()
    {
        var ct = TestContext.Current.CancellationToken;
        var t0 = DateTimeOffset.Parse("2026-01-01T00:00:00Z");
        var reader = new FakeKeyVaultKeyReader();
        reader.AddRsaVersion("v1", createdOn: t0);
        var timeProvider = new FakeTimeProvider(t0);

        await using var sut = BuildService(reader, timeProvider, algorithm: SigningAlgorithm.ES256);

        var act = async () => await sut.GetSigningKeysAsync(ct);

        (await act.Should().ThrowAsync<ZeeKayDaConfigurationException>())
            .WithMessage("*algorithm_key_type_mismatch*");
    }

    [Fact]
    public async Task GetSigningKeysAsync_throws_clear_exception_when_rsa_algorithm_configured_against_ec_key()
    {
        var ct = TestContext.Current.CancellationToken;
        var t0 = DateTimeOffset.Parse("2026-01-01T00:00:00Z");
        var reader = new FakeKeyVaultKeyReader();
        reader.AddEcVersion("v1", createdOn: t0);
        var timeProvider = new FakeTimeProvider(t0);

        await using var sut = BuildService(reader, timeProvider, algorithm: SigningAlgorithm.RS256);

        var act = async () => await sut.GetSigningKeysAsync(ct);

        (await act.Should().ThrowAsync<ZeeKayDaConfigurationException>())
            .WithMessage("*algorithm_key_type_mismatch*");
    }

    // ── No key versions / no enabled key / no active key ─────────────────────────────────────────

    [Fact]
    public async Task GetSigningKeysAsync_throws_clear_exception_when_key_has_no_versions()
    {
        var ct = TestContext.Current.CancellationToken;
        var reader = new FakeKeyVaultKeyReader();
        var timeProvider = new FakeTimeProvider(DateTimeOffset.Parse("2026-01-01T00:00:00Z"));

        await using var sut = BuildService(reader, timeProvider);

        var act = async () => await sut.GetSigningKeysAsync(ct);

        (await act.Should().ThrowAsync<ZeeKayDaConfigurationException>())
            .WithMessage("*no_key_versions*");
    }

    [Fact]
    public async Task GetSigningKeysAsync_throws_clear_exception_when_no_version_is_enabled()
    {
        var ct = TestContext.Current.CancellationToken;
        var t0 = DateTimeOffset.Parse("2026-01-01T00:00:00Z");
        var reader = new FakeKeyVaultKeyReader();
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
        var reader = new FakeKeyVaultKeyReader();
        reader.AddRsaVersion("v1", createdOn: t0, notBefore: t0 + TimeSpan.FromDays(1));
        reader.AddRsaVersion("v2", createdOn: t0 + TimeSpan.FromHours(1), notBefore: t0 + TimeSpan.FromDays(2));
        var timeProvider = new FakeTimeProvider(t0);

        await using var sut = BuildService(reader, timeProvider);

        var act = async () => await sut.GetSigningKeysAsync(ct);

        (await act.Should().ThrowAsync<ZeeKayDaConfigurationException>())
            .WithMessage("*no_active_key*");
    }

    // ── Completeness contract: a failed read must throw, not return a partial list ───────────────

    [Fact]
    public async Task GetSigningKeysAsync_throws_rather_than_returning_a_partial_list_when_a_later_version_fails_to_load()
    {
        var ct = TestContext.Current.CancellationToken;
        var t0 = DateTimeOffset.Parse("2026-01-01T00:00:00Z");
        var reader = new FakeKeyVaultKeyReader();
        reader.AddRsaVersion("v1", createdOn: t0, notBefore: t0 + TimeSpan.FromDays(2)); // Not yet active -> published alongside v0.
        reader.AddRsaVersion("v0", createdOn: t0 - TimeSpan.FromDays(1));
        reader.SetKeyMaterialException("v1", new ZeeKayDaConfigurationException(
            new ZeeKayDaConfigurationFailure("signing.azure_key_vault.access_denied", "Simulated failure for v1.")));
        var timeProvider = new FakeTimeProvider(t0);

        await using var sut = BuildService(reader, timeProvider);

        var act = async () => await sut.GetSigningKeysAsync(ct);

        (await act.Should().ThrowAsync<ZeeKayDaConfigurationException>())
            .WithMessage("*access_denied*");
    }

    [Fact]
    public async Task GetSigningKeysAsync_disposes_key_handle_when_BuildDescriptor_throws_for_it()
    {
        var ct = TestContext.Current.CancellationToken;
        var t0 = DateTimeOffset.Parse("2026-01-01T00:00:00Z");
        var reader = new FakeKeyVaultKeyReader();
        reader.AddRsaVersion("v1", createdOn: t0);
        AsymmetricAlgorithm? capturedKey = null;
        reader.OnKeyExtracted = (_, key) => capturedKey = key;
        var timeProvider = new FakeTimeProvider(t0);

        await using var sut = BuildService(reader, timeProvider, algorithm: SigningAlgorithm.ES256);

        var act = async () => await sut.GetSigningKeysAsync(ct);
        (await act.Should().ThrowAsync<ZeeKayDaConfigurationException>())
            .WithMessage("*algorithm_key_type_mismatch*");

        capturedKey.Should().NotBeNull();
        var useAfterFailure = () => ((RSA)capturedKey!).ExportParameters(includePrivateParameters: false);
        useAfterFailure.Should().Throw<ObjectDisposedException>(
            "the key handle obtained before BuildDescriptor's failure must not be leaked");
    }

    // ── Remote signing: the sign-time round trip ─────────────────────────────────────────────────

    [Fact]
    public async Task SignAsync_delegates_to_key_vault_signer_not_local_crypto()
    {
        var ct = TestContext.Current.CancellationToken;
        var t0 = DateTimeOffset.Parse("2026-01-01T00:00:00Z");
        var reader = new FakeKeyVaultKeyReader();
        var v1 = reader.AddRsaVersion("v1", createdOn: t0);
        var timeProvider = new FakeTimeProvider(t0);
        var signer = new FakeKeyVaultSigner { SignFunc = RealRsaSignFunc(reader) };

        await using var sut = BuildService(reader, timeProvider, signer: signer, algorithm: SigningAlgorithm.RS256);

        var payload = "payload"u8.ToArray();
        var result = await sut.SignAsync(payload, ct);

        signer.Calls.Should().HaveCount(2, "one call is the ADR 0015 §11 self-test (issue #437) and one is the real signature");
        signer.Calls[0].Algorithm.Should().Be(SigningAlgorithm.RS256);
        signer.Calls[0].KeyVersionUri.Should().Be(v1.Id, "signing must target the exact key version that produced the active descriptor");
        signer.Calls[0].Kid.Should().Be(JwkThumbprint.Compute(reader.GetRsaMaterial("v1")),
            "the sign-time exception path must be able to identify the key by its non-leaking kid, not just the URI");
        result.SignatureSegment.ToArray().Should().NotBeEmpty();
    }

    [Fact]
    public async Task SignAsync_result_kid_matches_the_active_descriptor_kid()
    {
        var ct = TestContext.Current.CancellationToken;
        var t0 = DateTimeOffset.Parse("2026-01-01T00:00:00Z");
        var reader = new FakeKeyVaultKeyReader();
        reader.AddRsaVersion("v1", createdOn: t0);
        var timeProvider = new FakeTimeProvider(t0);
        var signer = new FakeKeyVaultSigner { SignFunc = RealRsaSignFunc(reader) };

        await using var sut = BuildService(reader, timeProvider, signer: signer);
        var keys = await sut.GetSigningKeysAsync(ct);

        var result = await sut.SignAsync("payload"u8.ToArray(), ct);

        result.Kid.Should().Be(keys[0].Kid);
        result.Algorithm.Should().Be(keys[0].Algorithm);
    }

    [Fact]
    public async Task SignAsync_after_active_key_handoff_targets_the_new_active_versions_uri_and_kid()
    {
        var ct = TestContext.Current.CancellationToken;
        var t0 = DateTimeOffset.Parse("2026-01-01T00:00:00Z");
        var t1 = t0 + TimeSpan.FromDays(1);
        var reader = new FakeKeyVaultKeyReader();
        reader.AddRsaVersion("v1", createdOn: t0);
        var timeProvider = new FakeTimeProvider(t0);
        var signer = new FakeKeyVaultSigner { SignFunc = RealRsaSignFunc(reader) };

        await using var sut = BuildService(
            reader, timeProvider, refreshInterval: DefaultRefreshInterval, publicationLead: DefaultPublicationLead,
            retirementWindow: DefaultRetirementWindow, signer: signer);
        await sut.GetSigningKeysAsync(ct); // Bootstrap: v1 active.

        var v2 = reader.AddRsaVersion("v2", createdOn: t1);
        timeProvider.SetUtcNow(t1 + DefaultPublicationLead); // v2 activates; v1 still within its retirement window.
        var keys = await sut.GetSigningKeysAsync(ct);
        keys.Should().HaveCount(2);
        keys[0].Kid.Should().Be(JwkThumbprint.Compute(reader.GetRsaMaterial("v2")));

        await sut.SignAsync("payload"u8.ToArray(), ct);

        signer.Calls.Should().HaveCount(2, "one call is the ADR 0015 §11 self-test (issue #437) and one is the real signature");
        signer.Calls[0].KeyVersionUri.Should().Be(v2.Id, "signing after the handoff must target v2's Key Vault key version, not v1's");
        signer.Calls[0].Kid.Should().Be(JwkThumbprint.Compute(reader.GetRsaMaterial("v2")));
    }

    [Fact]
    public async Task Dispose_never_tears_down_the_shared_IKeyVaultSigner_across_an_active_key_handoff()
    {
        // Regression test (issue #425 security review, finding F9a): KeyVaultRemoteSigner.Dispose is
        // documented as a deliberate no-op because IKeyVaultSigner is a shared, DI-owned seam every
        // activation depends on (ADR 0015 §2/Security Considerations item 5). This proves it: v1's
        // signer wrapper is retired by the v1->v2 handoff, and the service itself is later disposed,
        // yet the shared FakeKeyVaultSigner is never told to dispose either time.
        var ct = TestContext.Current.CancellationToken;
        var t0 = DateTimeOffset.Parse("2026-01-01T00:00:00Z");
        var t1 = t0 + TimeSpan.FromDays(1);
        var reader = new FakeKeyVaultKeyReader();
        reader.AddRsaVersion("v1", createdOn: t0);
        var timeProvider = new FakeTimeProvider(t0);
        var signer = new FakeKeyVaultSigner { SignFunc = RealRsaSignFunc(reader) };

        var sut = BuildService(
            reader, timeProvider, refreshInterval: DefaultRefreshInterval, publicationLead: DefaultPublicationLead,
            retirementWindow: DefaultRetirementWindow, signer: signer);
        await sut.GetSigningKeysAsync(ct); // Bootstrap: v1 active.
        await sut.SignAsync("payload"u8.ToArray(), ct);

        reader.AddRsaVersion("v2", createdOn: t1);
        timeProvider.SetUtcNow(t1 + DefaultPublicationLead); // v2 activates; v1's wrapper is retired by the handoff.
        await sut.GetSigningKeysAsync(ct);
        await sut.SignAsync("payload"u8.ToArray(), ct);

        signer.DisposeCallCount.Should().Be(0, "the handoff must retire v1's ISigner wrapper without disposing the shared IKeyVaultSigner seam");

        await sut.DisposeAsync();

        signer.DisposeCallCount.Should().Be(0, "disposing the service itself must not tear down the shared IKeyVaultSigner seam either");
    }

    // ── Refresh cadence (KeySourceOptions / ADR 0015) ────────────────────────────────────────────

    [Fact]
    public async Task ListKeysAsync_is_called_once_per_RefreshInterval()
    {
        var ct = TestContext.Current.CancellationToken;
        var t0 = DateTimeOffset.Parse("2026-01-01T00:00:00Z");
        var reader = new FakeKeyVaultKeyReader();
        reader.AddRsaVersion("v1", createdOn: t0);
        var timeProvider = new FakeTimeProvider(t0);

        await using var sut = BuildService(reader, timeProvider, refreshInterval: DefaultRefreshInterval);
        await sut.GetSigningKeysAsync(ct); // Bootstrap load.
        var enumerationCallsAfterBootstrap = reader.GetKeyVersionsCallCount;

        await sut.GetSigningKeysAsync(ct); // Still within the refresh window — no re-enumeration.

        reader.GetKeyVersionsCallCount.Should().Be(enumerationCallsAfterBootstrap);

        timeProvider.SetUtcNow(t0 + DefaultRefreshInterval);
        await sut.GetSigningKeysAsync(ct);

        reader.GetKeyVersionsCallCount.Should().Be(enumerationCallsAfterBootstrap + 1,
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
        var reader = new FakeKeyVaultKeyReader();
        reader.AddRsaVersion("v1", createdOn: t0);
        var timeProvider = new FakeTimeProvider(t0);
        var logger = new CapturingLogger<JwtSigningService<AzureKeyVaultRemoteSigningOptions>>();

        await using var sut = BuildService(
            reader, timeProvider, refreshInterval: DefaultRefreshInterval, publicationLead: DefaultPublicationLead,
            retirementWindow: retirementWindow, logger: logger);
        await sut.GetSigningKeysAsync(ct); // Bootstrap: v1 active.

        reader.AddRsaVersion("v2", createdOn: t1);
        timeProvider.SetUtcNow(t1 + DefaultPublicationLead + retirementWindow + TimeSpan.FromMinutes(1));
        var keys = await sut.GetSigningKeysAsync(ct);

        keys.Should().ContainSingle("v1's retirement window has fully elapsed");
        logger.Entries.Should().NotContain(e => e.Level == LogLevel.Warning,
            "v1's key version is still present in Key Vault, merely excluded for having aged past its " +
            "retirement window — an expected exclusion, not the anomaly ADR 0015 §6 warns about");
    }

    [Fact]
    public async Task GetSigningKeysAsync_warns_when_a_previously_published_kid_s_key_version_disappears_from_key_vault_entirely_within_the_retirement_window()
    {
        var ct = TestContext.Current.CancellationToken;
        var t0 = DateTimeOffset.Parse("2026-01-01T00:00:00Z");
        var t1 = t0 + TimeSpan.FromDays(1);
        var retirementWindow = TimeSpan.FromHours(1);
        var reader = new FakeKeyVaultKeyReader();
        var v1 = reader.AddRsaVersion("v1", createdOn: t0);
        var timeProvider = new FakeTimeProvider(t0);
        var logger = new CapturingLogger<JwtSigningService<AzureKeyVaultRemoteSigningOptions>>();

        await using var sut = BuildService(
            reader, timeProvider, refreshInterval: DefaultRefreshInterval, publicationLead: DefaultPublicationLead,
            retirementWindow: retirementWindow, logger: logger);
        await sut.GetSigningKeysAsync(ct); // Bootstrap: v1 active, published.

        reader.AddRsaVersion("v2", createdOn: t1);
        timeProvider.SetUtcNow(t1 + DefaultPublicationLead);

        reader.Versions.RemoveAll(version => version.Version == v1.Version);

        var keys = await sut.GetSigningKeysAsync(ct);

        keys.Should().ContainSingle("v1 is gone from Key Vault entirely, so it cannot be included any more");
        logger.Entries.Should().Contain(e => e.Level == LogLevel.Warning,
            "a previously-published key vanishing from Key Vault entirely, before its retirement window " +
            "elapsed, must be surfaced as a Warning per ADR 0015 §6");
    }

    [Fact]
    public async Task GetSigningKeysAsync_warns_when_a_previously_published_kid_s_key_version_is_disabled_within_the_retirement_window()
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
        var reader = new FakeKeyVaultKeyReader();
        reader.AddRsaVersion("v1", createdOn: t0);
        var timeProvider = new FakeTimeProvider(t0);
        var logger = new CapturingLogger<JwtSigningService<AzureKeyVaultRemoteSigningOptions>>();

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
}
