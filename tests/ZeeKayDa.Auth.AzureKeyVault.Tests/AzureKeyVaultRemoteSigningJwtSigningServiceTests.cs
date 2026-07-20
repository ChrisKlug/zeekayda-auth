using System.Security.Cryptography;
using Azure.Security.KeyVault.Keys;
using Microsoft.Extensions.Options;
using Microsoft.Extensions.Time.Testing;
using ZeeKayDa.Auth.AzureKeyVault.Tests.Fakes;
using ZeeKayDa.Auth.Tokens;

namespace ZeeKayDa.Auth.AzureKeyVault.Tests;

public sealed class AzureKeyVaultRemoteSigningJwtSigningServiceTests
{
    private static readonly Uri KeyIdentifierUri = new("https://fake-vault.vault.azure.net/keys/fake-key");
    private static readonly TimeSpan DefaultRefreshInterval = TimeSpan.FromMinutes(5);
    private static readonly TimeSpan DefaultRetirementWindow = TimeSpan.FromHours(1);

    private static AzureKeyVaultRemoteSigningJwtSigningService BuildService(
        FakeKeyVaultKeyReader reader,
        FakeTimeProvider timeProvider,
        TimeSpan? refreshInterval = null,
        TimeSpan? retirementWindow = null,
        FakeKeyVaultSigner? signer = null,
        SigningAlgorithm algorithm = SigningAlgorithm.RS256)
    {
        var options = Options.Create(new AzureKeyVaultRemoteSigningOptions
        {
            KeyIdentifier = new KeyVaultKeyIdentifier(KeyIdentifierUri),
            Credential = new FakeTokenCredential(),
            Algorithm = algorithm,
            KeyRotationCheckInterval = refreshInterval ?? DefaultRefreshInterval,
        });

        return new AzureKeyVaultRemoteSigningJwtSigningService(
            options,
            timeProvider,
            reader,
            signer ?? new FakeKeyVaultSigner(),
            new FakeRetirementWindowProvider(retirementWindow ?? DefaultRetirementWindow),
            NullSanitizingLogger<AzureKeyVaultRemoteSigningJwtSigningService>.Instance);
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

        await using var sut = BuildService(reader, timeProvider, refreshInterval: DefaultRefreshInterval);

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

        await using var sut = BuildService(reader, timeProvider, refreshInterval: DefaultRefreshInterval);
        await sut.GetSigningKeysAsync(ct); // Prime the initial (bootstrap) load.

        reader.AddRsaVersion("v2", createdOn: t1);
        timeProvider.SetUtcNow(t1); // Cache has expired (> KeyRotationCheckInterval since the first load).

        var keys = await sut.GetSigningKeysAsync(ct);

        keys.Should().HaveCount(2, "v2 must be published even though it is not yet active (ADR 0011 §3.5)");
        keys[0].Kid.Should().Be(JwkThumbprint.Compute(reader.GetRsaMaterial("v1")), "v1 is still the active signer");
    }

    [Fact]
    public async Task GetSigningKeysAsync_rotated_in_version_becomes_active_after_refresh_interval_and_predecessor_overlaps()
    {
        var ct = TestContext.Current.CancellationToken;
        var t0 = DateTimeOffset.Parse("2026-01-01T00:00:00Z");
        var t1 = t0 + TimeSpan.FromDays(1);
        var reader = new FakeKeyVaultKeyReader();
        reader.AddRsaVersion("v1", createdOn: t0);
        var timeProvider = new FakeTimeProvider(t0);

        await using var sut = BuildService(
            reader, timeProvider, refreshInterval: DefaultRefreshInterval, retirementWindow: DefaultRetirementWindow);
        await sut.GetSigningKeysAsync(ct); // Bootstrap load.

        reader.AddRsaVersion("v2", createdOn: t1);
        timeProvider.SetUtcNow(t1 + DefaultRefreshInterval); // v2's ActivatesAt, exactly.

        var keys = await sut.GetSigningKeysAsync(ct);

        keys.Should().HaveCount(2, "v1 must still overlap with v2 for AC #3 (relying parties may hold tokens signed by either)");
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
            reader, timeProvider, refreshInterval: DefaultRefreshInterval, retirementWindow: retirementWindow);
        await sut.GetSigningKeysAsync(ct);

        reader.AddRsaVersion("v2", createdOn: t1);
        timeProvider.SetUtcNow(t1 + DefaultRefreshInterval + retirementWindow + TimeSpan.FromMinutes(1));

        var keys = await sut.GetSigningKeysAsync(ct);

        keys.Should().HaveCount(1, "v1's retirement window has fully elapsed since v2 took over");
        keys[0].Kid.Should().Be(JwkThumbprint.Compute(reader.GetRsaMaterial("v2")));
    }

    // ── Regression test: a disabled key must never gate a real predecessor's retirement ─────────────

    [Fact]
    public async Task GetSigningKeysAsync_disabled_intervening_version_does_not_gate_predecessor_retirement()
    {
        var ct = TestContext.Current.CancellationToken;
        // Regression test for a real bug: RetiredAt(v1) was originally computed as the positionally
        // next entry's ActivatesAt regardless of whether that entry was ever actually eligible to
        // become the active signer. v2 here is disabled and never becomes active — v1 stays the true
        // active signer straight through until v3 takes over. If the bug regressed, v1 would be
        // dropped from GetSigningKeysAsync() around v2's phantom would-be-activation time
        // (t0 + 1 day + KeyRotationCheckInterval + retirementWindow), long before v3 (the real successor) at
        // t0 + 10 days even exists.
        var t0 = DateTimeOffset.Parse("2026-01-01T00:00:00Z");
        var t1 = t0 + TimeSpan.FromDays(1); // v2: created shortly after v1, but disabled.
        var t2 = t0 + TimeSpan.FromDays(10); // v3: the real successor, much later.
        var retirementWindow = TimeSpan.FromHours(1);
        var reader = new FakeKeyVaultKeyReader();
        reader.AddRsaVersion("v1", createdOn: t0);
        var timeProvider = new FakeTimeProvider(t0);

        await using var sut = BuildService(
            reader, timeProvider, refreshInterval: DefaultRefreshInterval, retirementWindow: retirementWindow);
        await sut.GetSigningKeysAsync(ct);

        reader.AddRsaVersion("v2", createdOn: t1, enabled: false);
        timeProvider.SetUtcNow(t1);
        await sut.GetSigningKeysAsync(ct);

        // Time now passes well beyond what would have been v2's phantom retirement cutoff
        // (t1 + KeyRotationCheckInterval + retirementWindow), while v1 is still the only real active signer.
        var stillMidway = t1 + DefaultRefreshInterval + retirementWindow + TimeSpan.FromHours(1);
        timeProvider.SetUtcNow(stillMidway);
        var midwayKeys = await sut.GetSigningKeysAsync(ct);

        midwayKeys.Should().ContainSingle(k => k.Kid == JwkThumbprint.Compute(reader.GetRsaMaterial("v1")),
            "v1 is still the real active signer — a disabled version must never cause it to retire early");

        // v3 now genuinely takes over.
        reader.AddRsaVersion("v3", createdOn: t2);
        timeProvider.SetUtcNow(t2 + DefaultRefreshInterval);
        var afterHandoverKeys = await sut.GetSigningKeysAsync(ct);

        afterHandoverKeys.Should().Contain(k => k.Kid == JwkThumbprint.Compute(reader.GetRsaMaterial("v1")),
            "v1 must still be within its (correctly computed) retirement window relative to v3's real takeover");
        afterHandoverKeys[0].Kid.Should().Be(JwkThumbprint.Compute(reader.GetRsaMaterial("v3")));
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

        await using var sut = BuildService(reader, timeProvider, refreshInterval: DefaultRefreshInterval);
        reader.AddRsaVersion("v2", createdOn: t1);
        timeProvider.SetUtcNow(t1 + DefaultRefreshInterval);
        await sut.GetSigningKeysAsync(ct); // v1 and v2 now overlap.

        reader.SetEnabled("v1", enabled: false);
        // Advance past a full KeyRotationCheckInterval so the base class's own cache (also gated by
        // KeyRotationCheckInterval) actually expires and re-invokes LoadKeysAsync — a shorter advance would
        // just replay the stale cached set from before v1 was disabled.
        timeProvider.SetUtcNow(t1 + DefaultRefreshInterval + DefaultRefreshInterval + TimeSpan.FromSeconds(1));
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
        // v2's NotBefore opens well after its own CreatedOn + KeyRotationCheckInterval — the fix folds
        // NotBefore into ActivatesAt itself, so v1's RetiredAt correctly reflects v2's REAL
        // activation instant (NotBefore), not the raw CreatedOn + KeyRotationCheckInterval value, and not an
        // undefined/zero-grace result either.
        var t0 = DateTimeOffset.Parse("2026-01-01T00:00:00Z");
        var t1 = t0 + TimeSpan.FromDays(1);
        var notBefore = t1 + TimeSpan.FromDays(5); // Deliberately scheduled well past t1 + KeyRotationCheckInterval.
        var retirementWindow = TimeSpan.FromHours(2);
        var reader = new FakeKeyVaultKeyReader();
        reader.AddRsaVersion("v1", createdOn: t0);
        var timeProvider = new FakeTimeProvider(t0);

        await using var sut = BuildService(
            reader, timeProvider, refreshInterval: DefaultRefreshInterval, retirementWindow: retirementWindow);
        await sut.GetSigningKeysAsync(ct);

        reader.AddRsaVersion("v2", createdOn: t1, notBefore: notBefore);

        // Just after v1 + KeyRotationCheckInterval, but well before v2's NotBefore: v1 must still be active,
        // and v2 must still be published (not yet active).
        timeProvider.SetUtcNow(t1 + DefaultRefreshInterval);
        var beforeNotBefore = await sut.GetSigningKeysAsync(ct);
        beforeNotBefore[0].Kid.Should().Be(JwkThumbprint.Compute(reader.GetRsaMaterial("v1")));
        beforeNotBefore.Should().HaveCount(2);

        // Exactly at v2's NotBefore: v2 takes over, and v1 gets its full retirementWindow of grace
        // from THIS instant — not zero, and not from the earlier (incorrect) CreatedOn + KeyRotationCheckInterval.
        timeProvider.SetUtcNow(notBefore + TimeSpan.FromMinutes(1));
        var justAfterHandover = await sut.GetSigningKeysAsync(ct);
        justAfterHandover[0].Kid.Should().Be(JwkThumbprint.Compute(reader.GetRsaMaterial("v2")));
        justAfterHandover.Should().Contain(k => k.Kid == JwkThumbprint.Compute(reader.GetRsaMaterial("v1")),
            "v1 must still be within its retirement window measured from v2's real (NotBefore-gated) activation");

        // Well past retirementWindow since the real handover: v1 is now correctly excluded.
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
        // Since kid = thumbprint(public key material), two Key Vault VERSIONS that happen to share
        // identical key material (e.g. imported/BYOK material reused across versions) produce the
        // same kid. If both are simultaneously part of the trusted set, the base class's existing
        // duplicate-kid guard (JwtSigningService<TOptions>.ValidateKeySet) must fail closed rather
        // than publish an ambiguous JWKS with two entries under one kid — exactly the behavior this
        // asserts. Kid determinism/uniqueness itself (same material -> same kid, different material
        // -> different kid) is covered directly and more precisely in JwkThumbprintTests.
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

    // ── No key versions / no active key ──────────────────────────────────────────────────────────

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
    public async Task GetSigningKeysAsync_throws_clear_exception_when_no_version_has_activated_yet()
    {
        var ct = TestContext.Current.CancellationToken;
        var t0 = DateTimeOffset.Parse("2026-01-01T00:00:00Z");
        var reader = new FakeKeyVaultKeyReader();
        // Every version is not-yet-eligible at "now" — NotBefore in the future.
        reader.AddRsaVersion("v1", createdOn: t0, notBefore: t0 + TimeSpan.FromDays(1));
        var timeProvider = new FakeTimeProvider(t0);

        await using var sut = BuildService(reader, timeProvider);

        var act = async () => await sut.GetSigningKeysAsync(ct);

        (await act.Should().ThrowAsync<ZeeKayDaConfigurationException>())
            .WithMessage("*no_active_key*");
    }

    // ── Regression test for #315: mid-load key-handle leak on a partial LoadKeysAsync failure ───

    [Fact]
    public async Task GetSigningKeysAsync_disposes_already_obtained_key_handle_when_a_later_version_fails_to_load()
    {
        // v0 is the active version, so its public-only key handle has already been obtained and
        // added to keyPairs by the time v1's key material download (v1 is published but not yet
        // active) fails. The base class must not leak v0's live handle.
        var ct = TestContext.Current.CancellationToken;
        var t0 = DateTimeOffset.Parse("2026-01-01T00:00:00Z");
        var reader = new FakeKeyVaultKeyReader();
        reader.AddRsaVersion("v1", createdOn: t0, notBefore: t0 + TimeSpan.FromDays(2)); // Not yet active -> published alongside the active v0.
        reader.AddRsaVersion("v0", createdOn: t0 - TimeSpan.FromDays(1));
        reader.SetKeyMaterialException("v1", new ZeeKayDaConfigurationException(
            new ZeeKayDaConfigurationFailure("signing.azure_key_vault.access_denied", "Simulated failure for v1.")));
        AsymmetricAlgorithm? capturedKey = null;
        reader.OnKeyExtracted = (version, key) =>
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
            "v0's already-obtained key handle must not be leaked when v1's later load fails");
    }

    [Fact]
    public async Task GetSigningKeysAsync_disposes_key_handle_when_BuildDescriptor_throws_for_it()
    {
        // Regression test for the mid-load key-handle leak: ValidateAlgorithmFamilyMatchesKeyType
        // throws inside BuildDescriptor for an ES256/RSA mismatch. The key handle already obtained
        // from the reader for that same version was never added to keyPairs, so it must be disposed
        // directly at the point of failure rather than leaked.
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

    // ── SignInputAsync override ──────────────────────────────────────────────────────────────────

    [Fact]
    public async Task SignAsync_delegates_to_key_vault_signer_not_local_crypto()
    {
        var ct = TestContext.Current.CancellationToken;
        var t0 = DateTimeOffset.Parse("2026-01-01T00:00:00Z");
        var reader = new FakeKeyVaultKeyReader();
        var v1 = reader.AddRsaVersion("v1", createdOn: t0);
        var timeProvider = new FakeTimeProvider(t0);
        var signer = new FakeKeyVaultSigner { SignFunc = (_, _, _, _) => new byte[] { 9, 9, 9 } };

        await using var sut = BuildService(reader, timeProvider, signer: signer, algorithm: SigningAlgorithm.RS256);

        var payload = "payload"u8.ToArray();
        var result = await sut.SignAsync(payload, ct);

        signer.Calls.Should().ContainSingle();
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

        await using var sut = BuildService(reader, timeProvider);
        var keys = await sut.GetSigningKeysAsync(ct);

        var result = await sut.SignAsync("payload"u8.ToArray(), ct);

        result.Kid.Should().Be(keys[0].Kid);
        result.Algorithm.Should().Be(keys[0].Algorithm);
    }

    // ── HasKeySetChangedAsync: metadata-only change detection (ADR 0011 §3.5) ───────────────────────

    [Fact]
    public async Task GetSigningKeysAsync_skips_key_material_download_when_versions_are_unchanged_between_polls()
    {
        var ct = TestContext.Current.CancellationToken;
        var t0 = DateTimeOffset.Parse("2026-01-01T00:00:00Z");
        var reader = new FakeKeyVaultKeyReader();
        reader.AddRsaVersion("v1", createdOn: t0);
        var timeProvider = new FakeTimeProvider(t0);

        await using var sut = BuildService(reader, timeProvider, refreshInterval: DefaultRefreshInterval);
        await sut.GetSigningKeysAsync(ct); // Bootstrap load.
        reader.KeyMaterialCalls.Clear();

        timeProvider.SetUtcNow(t0 + DefaultRefreshInterval); // Cache expires -> triggers the "ask" step.
        var keys = await sut.GetSigningKeysAsync(ct);

        keys.Should().HaveCount(1);
        reader.KeyMaterialCalls.Should().BeEmpty(
            "no version changed since the last load, so HasKeySetChangedAsync must report no change and LoadKeysAsync must not run");
    }

    [Fact]
    public async Task SignAsync_still_succeeds_after_an_unchanged_poll_skips_the_reload()
    {
        var ct = TestContext.Current.CancellationToken;
        var t0 = DateTimeOffset.Parse("2026-01-01T00:00:00Z");
        var reader = new FakeKeyVaultKeyReader();
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
    public async Task HasKeySetChangedAsync_triggers_rebuild_when_a_new_key_version_appears()
    {
        var ct = TestContext.Current.CancellationToken;
        var t0 = DateTimeOffset.Parse("2026-01-01T00:00:00Z");
        var reader = new FakeKeyVaultKeyReader();
        reader.AddRsaVersion("v1", createdOn: t0);
        var timeProvider = new FakeTimeProvider(t0);

        await using var sut = BuildService(reader, timeProvider, refreshInterval: DefaultRefreshInterval);
        await sut.GetSigningKeysAsync(ct); // Bootstrap load.
        reader.KeyMaterialCalls.Clear();

        reader.AddRsaVersion("v2", createdOn: t0 + DefaultRefreshInterval);
        timeProvider.SetUtcNow(t0 + DefaultRefreshInterval);
        var keys = await sut.GetSigningKeysAsync(ct);

        keys.Should().HaveCount(2, "v2 must be published as soon as it appears, per publish-then-activate");
        reader.KeyMaterialCalls.Should().NotBeEmpty(
            "a new key version appearing must trigger a real reload, downloading key material again");
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
        var reader = new FakeKeyVaultKeyReader();
        reader.AddRsaVersion("v1", createdOn: t0);
        var timeProvider = new FakeTimeProvider(t0);

        await using var sut = BuildService(
            reader, timeProvider, refreshInterval: DefaultRefreshInterval, retirementWindow: retirementWindow);
        await sut.GetSigningKeysAsync(ct); // Bootstrap: v1 active.

        reader.AddRsaVersion("v2", createdOn: t1);
        timeProvider.SetUtcNow(t1 + DefaultRefreshInterval); // v2 activates; v1 retires but stays in-window.
        await sut.GetSigningKeysAsync(ct); // v1 + v2 both included.
        reader.KeyMaterialCalls.Clear();

        // Disable v1 (the non-active, retired-but-in-window version). Only a small amount of time
        // passes (well inside the 2-hour retirement window if v1 were still enabled) so the change
        // is attributable solely to the Enabled flag flip, not to elapsed time.
        reader.SetEnabled("v1", enabled: false);
        timeProvider.SetUtcNow(t1 + DefaultRefreshInterval + DefaultRefreshInterval);
        var keys = await sut.GetSigningKeysAsync(ct);

        keys.Should().ContainSingle(
            "v1's disabled flag must exclude it immediately, even though the active version (v2) is unchanged");
        reader.KeyMaterialCalls.Should().NotBeEmpty(
            "a non-active version's Enabled flag flipping must still trigger a rebuild");
    }

    [Fact]
    public async Task HasKeySetChangedAsync_triggers_rebuild_when_elapsed_time_alone_moves_a_version_out_of_its_retirement_window()
    {
        var ct = TestContext.Current.CancellationToken;
        var t0 = DateTimeOffset.Parse("2026-01-01T00:00:00Z");
        var t1 = t0 + TimeSpan.FromDays(1);
        var retirementWindow = TimeSpan.FromHours(1);
        var reader = new FakeKeyVaultKeyReader();
        reader.AddRsaVersion("v1", createdOn: t0);
        var timeProvider = new FakeTimeProvider(t0);

        await using var sut = BuildService(
            reader, timeProvider, refreshInterval: DefaultRefreshInterval, retirementWindow: retirementWindow);
        await sut.GetSigningKeysAsync(ct); // Bootstrap: v1 active.

        reader.AddRsaVersion("v2", createdOn: t1);
        timeProvider.SetUtcNow(t1 + DefaultRefreshInterval); // v2 activates; v1 retired but still in-window.
        await sut.GetSigningKeysAsync(ct); // v1 + v2 both included.
        reader.KeyMaterialCalls.Clear();

        // No Key Vault-side change at all — just elapsed time pushing v1 past its retirement window.
        timeProvider.SetUtcNow(t1 + DefaultRefreshInterval + retirementWindow + TimeSpan.FromMinutes(1));
        var keys = await sut.GetSigningKeysAsync(ct);

        keys.Should().ContainSingle("v1's retirement window has now fully elapsed");
        reader.KeyMaterialCalls.Should().NotBeEmpty(
            "a version leaving its retirement window purely from elapsed time must still trigger a rebuild, " +
            "even with no Key Vault-side change");
    }

    [Fact]
    public async Task HasKeySetChangedAsync_triggers_rebuild_when_the_active_version_changes_with_membership_unchanged()
    {
        // Regression test for the same class of bug already found and fixed for the sibling
        // cached-signing provider: ToVersionSet must compare IsActive, not just version identifier
        // and Enabled state. KeyRotationCheckInterval is both the poll cadence and the
        // publish-then-activate lead time, so a normal rotation spans two polls. At poll N, v2 is
        // published but not yet active — the included set becomes {v1 active, v2 not-active}, a
        // membership change from the single-version bootstrap state, so this poll is correctly
        // reported as a change regardless of the fix (see
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
        var reader = new FakeKeyVaultKeyReader();
        reader.AddRsaVersion("v1", createdOn: t0);
        var timeProvider = new FakeTimeProvider(t0);
        var signer = new FakeKeyVaultSigner();

        await using var sut = BuildService(
            reader, timeProvider, refreshInterval: DefaultRefreshInterval, retirementWindow: DefaultRetirementWindow,
            signer: signer);
        await sut.GetSigningKeysAsync(ct); // Bootstrap: v1 active.

        var v2 = reader.AddRsaVersion("v2", createdOn: t1);
        timeProvider.SetUtcNow(t1); // Poll N: v2 published but not yet active (membership change).
        await sut.GetSigningKeysAsync(ct); // v1 active + v2 not-active; both now recorded as "previously included".
        reader.KeyMaterialCalls.Clear();

        // Poll N+1: one KeyRotationCheckInterval later, with no Key Vault-side change whatsoever —
        // v2 now activates and v1 (still within its retirement window) stays included. Same version
        // identifiers, same Enabled states as poll N; only which entry is active differs.
        timeProvider.SetUtcNow(t1 + DefaultRefreshInterval);
        var keys = await sut.GetSigningKeysAsync(ct);

        keys.Should().HaveCount(2, "v1 is still within its retirement window and v2 is now active");
        keys[0].Kid.Should().Be(JwkThumbprint.Compute(reader.GetRsaMaterial("v2")),
            "the handoff must actually happen: v2 must become the active (index 0) signing key at this poll");
        reader.KeyMaterialCalls.Should().NotBeEmpty(
            "the active-slot handoff alone must be enough to trigger a real reload, even with membership and " +
            "Enabled states unchanged since the previous poll");

        // Prove the reload is not merely cosmetic: the service must actually sign with v2 going
        // forward, dispatching to the Key Vault signer with v2's own versioned key URI and kid.
        await sut.SignAsync("payload"u8.ToArray(), ct);

        signer.Calls.Should().ContainSingle();
        signer.Calls[0].KeyVersionUri.Should().Be(v2.Id, "signing after the handoff must target v2's Key Vault key version, not v1's");
        signer.Calls[0].Kid.Should().Be(JwkThumbprint.Compute(reader.GetRsaMaterial("v2")),
            "signing after the handoff must use v2's kid");
    }

    [Fact]
    public async Task HasKeySetChangedAsync_only_enumerates_key_versions_and_never_downloads_key_material_when_reporting_no_change()
    {
        var ct = TestContext.Current.CancellationToken;
        var t0 = DateTimeOffset.Parse("2026-01-01T00:00:00Z");
        var reader = new FakeKeyVaultKeyReader();
        reader.AddRsaVersion("v1", createdOn: t0);
        var timeProvider = new FakeTimeProvider(t0);

        await using var sut = BuildService(reader, timeProvider, refreshInterval: DefaultRefreshInterval);
        await sut.GetSigningKeysAsync(ct); // Bootstrap load.
        var enumerationCallsAfterBootstrap = reader.GetKeyVersionsCallCount;
        reader.KeyMaterialCalls.Clear();

        timeProvider.SetUtcNow(t0 + DefaultRefreshInterval); // Unchanged poll.
        await sut.GetSigningKeysAsync(ct);

        reader.GetKeyVersionsCallCount.Should().Be(enumerationCallsAfterBootstrap + 1,
            "the ask step must enumerate key versions exactly once per cycle");
        reader.KeyMaterialCalls.Should().BeEmpty("the ask's metadata-only check must never download key material");
    }

    [Fact]
    public async Task HasKeySetChangedAsync_only_enumerates_key_versions_before_a_real_reload_downloads_key_material()
    {
        // Proves the "ask" itself is metadata-only even on a cycle that ends up rebuilding: the
        // ask's own enumeration call never touches key material — only the subsequent, separate
        // LoadKeysAsync reload (which shares the same ComputeIncludedVersionsAsync helper and so
        // enumerates a second time) ever calls GetKeyMaterialAsync.
        var ct = TestContext.Current.CancellationToken;
        var t0 = DateTimeOffset.Parse("2026-01-01T00:00:00Z");
        var reader = new FakeKeyVaultKeyReader();
        reader.AddRsaVersion("v1", createdOn: t0);
        var timeProvider = new FakeTimeProvider(t0);

        await using var sut = BuildService(reader, timeProvider, refreshInterval: DefaultRefreshInterval);
        await sut.GetSigningKeysAsync(ct); // Bootstrap load.
        var enumerationCallsAfterBootstrap = reader.GetKeyVersionsCallCount;
        reader.KeyMaterialCalls.Clear();

        reader.AddRsaVersion("v2", createdOn: t0 + DefaultRefreshInterval); // A genuine change.
        timeProvider.SetUtcNow(t0 + DefaultRefreshInterval);
        await sut.GetSigningKeysAsync(ct);

        reader.GetKeyVersionsCallCount.Should().Be(enumerationCallsAfterBootstrap + 2,
            "one enumeration for the ask (HasKeySetChangedAsync) and a second, separate one for the real reload " +
            "(LoadKeysAsync) that the \"true\" answer then triggers");
        reader.KeyMaterialCalls.Should().NotBeEmpty("the real reload — not the ask — is what downloads key material");
    }
}
