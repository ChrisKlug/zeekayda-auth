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
            RefreshInterval = refreshInterval ?? DefaultRefreshInterval,
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
        timeProvider.SetUtcNow(t1); // Cache has expired (> RefreshInterval since the first load).

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
        // (t0 + 1 day + RefreshInterval + retirementWindow), long before v3 (the real successor) at
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
        // (t1 + RefreshInterval + retirementWindow), while v1 is still the only real active signer.
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
        // Advance past a full RefreshInterval so the base class's own cache (also gated by
        // RefreshInterval) actually expires and re-invokes LoadKeysAsync — a shorter advance would
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
        // v2's NotBefore opens well after its own CreatedOn + RefreshInterval — the fix folds
        // NotBefore into ActivatesAt itself, so v1's RetiredAt correctly reflects v2's REAL
        // activation instant (NotBefore), not the raw CreatedOn + RefreshInterval value, and not an
        // undefined/zero-grace result either.
        var t0 = DateTimeOffset.Parse("2026-01-01T00:00:00Z");
        var t1 = t0 + TimeSpan.FromDays(1);
        var notBefore = t1 + TimeSpan.FromDays(5); // Deliberately scheduled well past t1 + RefreshInterval.
        var retirementWindow = TimeSpan.FromHours(2);
        var reader = new FakeKeyVaultKeyReader();
        reader.AddRsaVersion("v1", createdOn: t0);
        var timeProvider = new FakeTimeProvider(t0);

        await using var sut = BuildService(
            reader, timeProvider, refreshInterval: DefaultRefreshInterval, retirementWindow: retirementWindow);
        await sut.GetSigningKeysAsync(ct);

        reader.AddRsaVersion("v2", createdOn: t1, notBefore: notBefore);

        // Just after v1 + RefreshInterval, but well before v2's NotBefore: v1 must still be active,
        // and v2 must still be published (not yet active).
        timeProvider.SetUtcNow(t1 + DefaultRefreshInterval);
        var beforeNotBefore = await sut.GetSigningKeysAsync(ct);
        beforeNotBefore[0].Kid.Should().Be(JwkThumbprint.Compute(reader.GetRsaMaterial("v1")));
        beforeNotBefore.Should().HaveCount(2);

        // Exactly at v2's NotBefore: v2 takes over, and v1 gets its full retirementWindow of grace
        // from THIS instant — not zero, and not from the earlier (incorrect) CreatedOn + RefreshInterval.
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
}
