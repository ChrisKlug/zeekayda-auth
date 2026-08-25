using System.Security.Cryptography;
using Azure.Security.KeyVault.Keys;
using Microsoft.Extensions.Options;
using Microsoft.Extensions.Time.Testing;
using ZeeKayDa.Auth.AzureKeyVault.Tests.Fakes;
using ZeeKayDa.Auth.Tokens;

namespace ZeeKayDa.Auth.AzureKeyVault.Tests;

/// <summary>
/// Direct-construction tests for <see cref="AzureKeyVaultRemoteSigningKeySource"/>, bypassing DI and
/// the <c>AddAzureKeyVaultRemoteSigning</c> extension entirely, and mirroring
/// <c>WindowsCertificateStoreSigningKeySourceTests</c>'s shape. The Key Vault-specific concern they
/// add is the version-to-slot mapping: unlike every slot-configured sibling source, this one derives
/// which version signs, which is staged, and which stay published from the vault's own per-version
/// metadata, so that derivation — the age gate, the first-ever exemption, the enabled/validity
/// filters, and the previous-version count — is what most of this file pins down.
/// </summary>
public sealed class AzureKeyVaultRemoteSigningKeySourceTests
{
    private static readonly Uri KeyIdentifierUri = new("https://fake-vault.vault.azure.net/keys/fake-key");
    private static readonly DateTimeOffset T0 = DateTimeOffset.Parse("2026-01-01T00:00:00Z");
    private static readonly TimeSpan DefaultPreActivationDelay = TimeSpan.FromDays(1);

    private static AzureKeyVaultRemoteSigningKeySource BuildSource(
        FakeKeyVaultKeyReader reader,
        FakeTimeProvider timeProvider,
        FakeKeyVaultSigner? signer = null,
        SigningAlgorithm algorithm = SigningAlgorithm.RS256,
        int previousVersionsToPublish = 1,
        TimeSpan? preActivationDelay = null)
    {
        var options = Options.Create(new AzureKeyVaultRemoteSigningOptions
        {
            KeyIdentifier = new KeyVaultKeyIdentifier(KeyIdentifierUri),
            Credential = new FakeTokenCredential(),
            Algorithm = algorithm,
            PreviousVersionsToPublish = previousVersionsToPublish,
            PreActivationDelay = preActivationDelay ?? DefaultPreActivationDelay,
        });

        return new AzureKeyVaultRemoteSigningKeySource(
            options, reader, signer ?? new FakeKeyVaultSigner(), timeProvider);
    }

    /// <summary>
    /// A <see cref="FakeKeyVaultSigner.SignFunc"/> that signs with the real private key material
    /// <paramref name="reader"/> retained for whichever key version the URI targets, so a test can
    /// verify the produced signature against the public key the source reported. RS256 only,
    /// matching every test in this file that verifies a signature.
    /// </summary>
    private static Func<Uri, string, SigningAlgorithm, byte[], ReadOnlyMemory<byte>> RealRsaSignFunc(FakeKeyVaultKeyReader reader) =>
        (uri, _, _, signingInput) =>
        {
            var version = uri.Segments[^1];
            using var rsa = reader.CreateRsaPrivateKey(version);
            return rsa.SignData(signingInput, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        };

    private static string[] PublishedIds(SourceKeySet keySet) => [.. keySet.Keys.Select(k => k.Id.Value)];

    // ── Bootstrap ────────────────────────────────────────────────────────────────────────────────

    [Fact]
    public async Task ReadAsync_first_ever_version_signs_immediately_despite_the_pre_activation_delay()
    {
        var ct = TestContext.Current.CancellationToken;
        var reader = new FakeKeyVaultKeyReader();
        reader.AddRsaVersion("v1", createdOn: T0);
        var sut = BuildSource(reader, new FakeTimeProvider(T0));

        var keySet = await sut.ReadAsync(ct);

        keySet.Keys.Should().ContainSingle("a brand-new deployment must be able to start on its only version");
        keySet.SigningKey.Id.Should().Be(new SourceKeyId("v1"));
        keySet.SigningKey.Algorithm.Should().Be(SigningAlgorithm.RS256);
        keySet.SigningKey.PublicKey.RsaPublicParameters.Should().NotBeNull(
            "only public material may ever leave this source's read path");
    }

    [Fact]
    public async Task ReadAsync_first_ever_exemption_applies_only_to_the_chronologically_first_version()
    {
        var ct = TestContext.Current.CancellationToken;
        var reader = new FakeKeyVaultKeyReader();
        reader.AddRsaVersion("v1", createdOn: T0 - TimeSpan.FromHours(2));
        reader.AddRsaVersion("v2", createdOn: T0 - TimeSpan.FromHours(1));
        var sut = BuildSource(reader, new FakeTimeProvider(T0));

        var keySet = await sut.ReadAsync(ct);

        keySet.SigningKey.Id.Should().Be(new SourceKeyId("v1"),
            "v2 is younger than the delay and is not the first-ever version, so it may not sign");
        PublishedIds(keySet).Should().BeEquivalentTo(["v1", "v2"], "v2 is still published as staged");
    }

    // ── Version-to-slot mapping ──────────────────────────────────────────────────────────────────

    [Fact]
    public async Task ReadAsync_newest_ripened_version_signs_and_its_predecessor_stays_published()
    {
        var ct = TestContext.Current.CancellationToken;
        var reader = new FakeKeyVaultKeyReader();
        reader.AddRsaVersion("v1", createdOn: T0);
        reader.AddRsaVersion("v2", createdOn: T0 + TimeSpan.FromDays(10));
        var sut = BuildSource(reader, new FakeTimeProvider(T0 + TimeSpan.FromDays(11)));

        var keySet = await sut.ReadAsync(ct);

        keySet.SigningKey.Id.Should().Be(new SourceKeyId("v2"));
        PublishedIds(keySet).Should().Equal(["v2", "v1"],
            "relying parties may still hold tokens v1 signed, so it must remain published");
    }

    [Fact]
    public async Task ReadAsync_version_younger_than_the_delay_is_published_as_staged_but_does_not_sign()
    {
        var ct = TestContext.Current.CancellationToken;
        var reader = new FakeKeyVaultKeyReader();
        reader.AddRsaVersion("v1", createdOn: T0);
        reader.AddRsaVersion("v2", createdOn: T0 + TimeSpan.FromDays(10));
        var sut = BuildSource(reader, new FakeTimeProvider(T0 + TimeSpan.FromDays(10) + TimeSpan.FromHours(1)));

        var keySet = await sut.ReadAsync(ct);

        keySet.SigningKey.Id.Should().Be(new SourceKeyId("v1"), "v2 has not existed for the pre-activation delay yet");
        PublishedIds(keySet).Should().BeEquivalentTo(["v1", "v2"],
            "the staged version's public half must be published so relying parties cache it before it ever signs");
    }

    [Fact]
    public async Task ReadAsync_version_with_a_future_NotBefore_is_published_as_staged_but_does_not_sign()
    {
        var ct = TestContext.Current.CancellationToken;
        var now = T0 + TimeSpan.FromDays(10);
        var reader = new FakeKeyVaultKeyReader();
        reader.AddRsaVersion("v1", createdOn: T0);
        reader.AddRsaVersion("v2", createdOn: T0 + TimeSpan.FromDays(5), notBefore: now + TimeSpan.FromDays(2));
        var sut = BuildSource(reader, new FakeTimeProvider(now));

        var keySet = await sut.ReadAsync(ct);

        keySet.SigningKey.Id.Should().Be(new SourceKeyId("v1"),
            "v2 is old enough but its own NotBefore has not passed, so it may not sign");
        PublishedIds(keySet).Should().BeEquivalentTo(["v1", "v2"]);
    }

    [Fact]
    public async Task ReadAsync_publishes_up_to_the_configured_number_of_previous_versions_newest_first()
    {
        var ct = TestContext.Current.CancellationToken;
        var reader = new FakeKeyVaultKeyReader();
        reader.AddRsaVersion("v1", createdOn: T0);
        reader.AddRsaVersion("v2", createdOn: T0 + TimeSpan.FromDays(1));
        reader.AddRsaVersion("v3", createdOn: T0 + TimeSpan.FromDays(2));
        reader.AddRsaVersion("v4", createdOn: T0 + TimeSpan.FromDays(3));
        var sut = BuildSource(reader, new FakeTimeProvider(T0 + TimeSpan.FromDays(30)), previousVersionsToPublish: 2);

        var keySet = await sut.ReadAsync(ct);

        keySet.SigningKey.Id.Should().Be(new SourceKeyId("v4"));
        PublishedIds(keySet).Should().Equal(["v4", "v3", "v2"],
            "only the two newest versions older than the signing one are published, and v1 falls off the end");
    }

    [Fact]
    public async Task ReadAsync_publishes_no_previous_versions_when_the_count_is_zero()
    {
        var ct = TestContext.Current.CancellationToken;
        var reader = new FakeKeyVaultKeyReader();
        reader.AddRsaVersion("v1", createdOn: T0);
        reader.AddRsaVersion("v2", createdOn: T0 + TimeSpan.FromDays(1));
        var sut = BuildSource(reader, new FakeTimeProvider(T0 + TimeSpan.FromDays(30)), previousVersionsToPublish: 0);

        var keySet = await sut.ReadAsync(ct);

        PublishedIds(keySet).Should().Equal(["v2"]);
    }

    [Fact]
    public async Task ReadAsync_publishes_every_staged_version_when_several_exist()
    {
        // Every enabled version newer than the signing one is published — not only the next in
        // line — so two replicas whose restarts straddle a version ripening still publish each
        // other's signing key.
        var ct = TestContext.Current.CancellationToken;
        var now = T0 + TimeSpan.FromDays(10);
        var reader = new FakeKeyVaultKeyReader();
        reader.AddRsaVersion("v1", createdOn: T0);
        reader.AddRsaVersion("v2", createdOn: now - TimeSpan.FromHours(3));
        reader.AddRsaVersion("v3", createdOn: now - TimeSpan.FromHours(1));
        var sut = BuildSource(reader, new FakeTimeProvider(now));

        var keySet = await sut.ReadAsync(ct);

        keySet.SigningKey.Id.Should().Be(new SourceKeyId("v1"));
        PublishedIds(keySet).Should().Equal(["v1", "v2", "v3"],
            "a replica restarting after v3 ripens will sign with it, so this replica's JWKS must already carry it");
    }

    [Fact]
    public async Task ReadAsync_excludes_disabled_versions_from_every_slot()
    {
        var ct = TestContext.Current.CancellationToken;
        var reader = new FakeKeyVaultKeyReader();
        reader.AddRsaVersion("v1", createdOn: T0);
        reader.AddRsaVersion("v2", createdOn: T0 + TimeSpan.FromDays(1), enabled: false);
        reader.AddRsaVersion("v3", createdOn: T0 + TimeSpan.FromDays(2));
        var sut = BuildSource(reader, new FakeTimeProvider(T0 + TimeSpan.FromDays(30)), previousVersionsToPublish: 5);

        var keySet = await sut.ReadAsync(ct);

        keySet.SigningKey.Id.Should().Be(new SourceKeyId("v3"));
        PublishedIds(keySet).Should().Equal(["v3", "v1"],
            "disabling a version in the vault is the operator's revocation lever and removes it from publication unconditionally");
    }

    [Fact]
    public async Task ReadAsync_expired_newer_version_does_not_sign_but_is_still_published_as_staged()
    {
        var ct = TestContext.Current.CancellationToken;
        var now = T0 + TimeSpan.FromDays(30);
        var reader = new FakeKeyVaultKeyReader();
        reader.AddRsaVersion("v1", createdOn: T0);
        reader.AddRsaVersion("v2", createdOn: T0 + TimeSpan.FromDays(1), expiresOn: T0 + TimeSpan.FromDays(10));
        var sut = BuildSource(reader, new FakeTimeProvider(now));

        var keySet = await sut.ReadAsync(ct);

        keySet.SigningKey.Id.Should().Be(new SourceKeyId("v1"), "an expired version may never sign");
        PublishedIds(keySet).Should().BeEquivalentTo(["v1", "v2"],
            "v2 is still enabled, so tokens it signed before expiry must remain verifiable until the operator disables it");
    }

    [Fact]
    public async Task ReadAsync_expired_but_enabled_previous_version_is_still_published_within_the_count()
    {
        var ct = TestContext.Current.CancellationToken;
        var now = T0 + TimeSpan.FromDays(30);
        var reader = new FakeKeyVaultKeyReader();
        reader.AddRsaVersion("v1", createdOn: T0, expiresOn: T0 + TimeSpan.FromDays(10));
        reader.AddRsaVersion("v2", createdOn: T0 + TimeSpan.FromDays(1));
        var sut = BuildSource(reader, new FakeTimeProvider(now));

        var keySet = await sut.ReadAsync(ct);

        keySet.SigningKey.Id.Should().Be(new SourceKeyId("v2"));
        PublishedIds(keySet).Should().Equal(["v2", "v1"],
            "tokens v1 signed before its expiry are still within their own lifetime");
    }

    [Fact]
    public async Task ReadAsync_zero_delay_lets_a_newly_created_version_sign_immediately()
    {
        var ct = TestContext.Current.CancellationToken;
        var reader = new FakeKeyVaultKeyReader();
        reader.AddRsaVersion("v1", createdOn: T0);
        reader.AddRsaVersion("v2", createdOn: T0 + TimeSpan.FromDays(10));
        var sut = BuildSource(reader, new FakeTimeProvider(T0 + TimeSpan.FromDays(10)), preActivationDelay: TimeSpan.Zero);

        var keySet = await sut.ReadAsync(ct);

        keySet.SigningKey.Id.Should().Be(new SourceKeyId("v2"));
    }

    [Fact]
    public async Task ReadAsync_orders_versions_created_at_the_same_instant_deterministically()
    {
        var ct = TestContext.Current.CancellationToken;
        var reader = new FakeKeyVaultKeyReader();
        reader.AddRsaVersion("a", createdOn: T0);
        reader.AddRsaVersion("b", createdOn: T0);
        var sut = BuildSource(reader, new FakeTimeProvider(T0 + TimeSpan.FromDays(30)));

        var keySet = await sut.ReadAsync(ct);

        keySet.SigningKey.Id.Should().Be(new SourceKeyId("b"),
            "a CreatedOn tie is broken by the version string, ordinal descending, so every replica derives the same answer");
    }

    [Fact]
    public async Task ReadAsync_reports_each_versions_own_validity_window()
    {
        var ct = TestContext.Current.CancellationToken;
        var notBefore = T0 - TimeSpan.FromDays(1);
        var expiresOn = T0 + TimeSpan.FromDays(365);
        var reader = new FakeKeyVaultKeyReader();
        reader.AddRsaVersion("v1", createdOn: T0, notBefore: notBefore, expiresOn: expiresOn);
        var sut = BuildSource(reader, new FakeTimeProvider(T0));

        var keySet = await sut.ReadAsync(ct);

        keySet.SigningKey.NotBefore.Should().Be(notBefore);
        keySet.SigningKey.ExpiresAt.Should().Be(expiresOn);
    }

    [Fact]
    public async Task ReadAsync_maps_ec_key_material()
    {
        var ct = TestContext.Current.CancellationToken;
        var reader = new FakeKeyVaultKeyReader();
        reader.AddEcVersion("v1", createdOn: T0);
        var sut = BuildSource(reader, new FakeTimeProvider(T0), algorithm: SigningAlgorithm.ES256);

        var keySet = await sut.ReadAsync(ct);

        keySet.SigningKey.PublicKey.KeyType.Should().Be(SigningKeyType.Ec);
        keySet.SigningKey.PublicKey.EcPublicParameters.Should().NotBeNull();
    }

    // ── Failure paths: always throw, never a partial set ─────────────────────────────────────────

    [Fact]
    public async Task ReadAsync_throws_when_the_key_has_no_versions()
    {
        var ct = TestContext.Current.CancellationToken;
        var sut = BuildSource(new FakeKeyVaultKeyReader(), new FakeTimeProvider(T0));

        var act = async () => await sut.ReadAsync(ct);

        (await act.Should().ThrowAsync<ZeeKayDaConfigurationException>())
            .WithMessage("*no_key_versions*");
    }

    [Fact]
    public async Task ReadAsync_throws_when_no_version_is_enabled()
    {
        var ct = TestContext.Current.CancellationToken;
        var reader = new FakeKeyVaultKeyReader();
        reader.AddRsaVersion("v1", createdOn: T0, enabled: false);
        var sut = BuildSource(reader, new FakeTimeProvider(T0));

        var act = async () => await sut.ReadAsync(ct);

        (await act.Should().ThrowAsync<ZeeKayDaConfigurationException>())
            .WithMessage("*no_active_key*");
    }

    [Fact]
    public async Task ReadAsync_throws_when_enabled_versions_exist_but_none_is_eligible_to_sign()
    {
        // The first-ever version is disabled, so its exemption is gone; the only enabled version is
        // younger than the delay. Fail closed — the error must name the escape hatch rather than
        // letting a young key sign early.
        var ct = TestContext.Current.CancellationToken;
        var reader = new FakeKeyVaultKeyReader();
        reader.AddRsaVersion("v1", createdOn: T0, enabled: false);
        reader.AddRsaVersion("v2", createdOn: T0 + TimeSpan.FromDays(10));
        var sut = BuildSource(reader, new FakeTimeProvider(T0 + TimeSpan.FromDays(10) + TimeSpan.FromHours(1)));

        var act = async () => await sut.ReadAsync(ct);

        (await act.Should().ThrowAsync<ZeeKayDaConfigurationException>())
            .WithMessage("*no_eligible_version*PreActivationDelay*");
    }

    [Fact]
    public async Task ReadAsync_throws_rather_than_returning_a_partial_set_when_a_published_versions_material_fails_to_load()
    {
        // The completeness contract: a vault error must never be indistinguishable from revocation,
        // so a failure loading ANY selected version's public half fails the whole read.
        var ct = TestContext.Current.CancellationToken;
        var reader = new FakeKeyVaultKeyReader();
        reader.AddRsaVersion("v1", createdOn: T0);
        reader.AddRsaVersion("v2", createdOn: T0 + TimeSpan.FromDays(10));
        reader.SetKeyMaterialException("v1", new ZeeKayDaConfigurationException(
            new ZeeKayDaConfigurationFailure("signing.azure_key_vault.access_denied", "Simulated failure for v1.")));
        var sut = BuildSource(reader, new FakeTimeProvider(T0 + TimeSpan.FromDays(30)));

        var act = async () => await sut.ReadAsync(ct);

        (await act.Should().ThrowAsync<ZeeKayDaConfigurationException>())
            .WithMessage("*access_denied*");
    }

    [Fact]
    public async Task ReadAsync_throws_when_the_signing_versions_identifier_uri_is_not_version_pinned()
    {
        // Defence-in-depth behind the ring's self-test: an unpinned URI would make the SDK's
        // CryptographyClient sign with whatever version is newest at sign time, not the version
        // whose public half was published.
        var ct = TestContext.Current.CancellationToken;
        var reader = new FakeKeyVaultKeyReader();
        reader.AddRsaVersion("v1", createdOn: T0, id: new Uri("https://fake-vault.vault.azure.net/keys/fake-key"));
        var sut = BuildSource(reader, new FakeTimeProvider(T0));

        var act = async () => await sut.ReadAsync(ct);

        (await act.Should().ThrowAsync<ZeeKayDaConfigurationException>())
            .WithMessage("*unversioned_key_uri*");
    }

    [Fact]
    public async Task ReadAsync_throws_and_does_not_memoize_when_the_listing_fails_mid_enumeration()
    {
        // The sharpest edge of the never-a-partial-set contract: versions already received before
        // the failure must not be served as if they were the whole history.
        var ct = TestContext.Current.CancellationToken;
        var reader = new FakeKeyVaultKeyReader();
        reader.AddRsaVersion("v1", createdOn: T0);
        reader.AddRsaVersion("v2", createdOn: T0 + TimeSpan.FromDays(10));
        reader.AddRsaVersion("v3", createdOn: T0 + TimeSpan.FromDays(20));
        reader.MidEnumerationFailure = (2, new ZeeKayDaConfigurationException(
            new ZeeKayDaConfigurationFailure("signing.azure_key_vault.startup_failure", "Simulated paging failure.")));
        var sut = BuildSource(reader, new FakeTimeProvider(T0 + TimeSpan.FromDays(30)));

        var act = async () => await sut.ReadAsync(ct);
        (await act.Should().ThrowAsync<ZeeKayDaConfigurationException>())
            .WithMessage("*startup_failure*");

        reader.MidEnumerationFailure = null;
        var keySet = await sut.ReadAsync(ct);

        keySet.SigningKey.Id.Should().Be(new SourceKeyId("v3"),
            "the partial two-version read must not have been memoized — the retry sees the full history");
    }

    [Fact]
    public async Task ReadAsync_no_eligible_version_error_does_not_name_a_ripening_time_past_that_versions_own_expiry()
    {
        // v1 (first ever) is disabled; v2 is too young to sign and expires before it would ripen,
        // so there is no instant at which any version becomes eligible — the error must say to
        // create a new version rather than promise a wait that can never succeed.
        var ct = TestContext.Current.CancellationToken;
        var now = T0 + TimeSpan.FromDays(10);
        var reader = new FakeKeyVaultKeyReader();
        reader.AddRsaVersion("v1", createdOn: T0, enabled: false);
        reader.AddRsaVersion("v2", createdOn: now - TimeSpan.FromHours(1), expiresOn: now + TimeSpan.FromHours(1));
        var sut = BuildSource(reader, new FakeTimeProvider(now));

        var act = async () => await sut.ReadAsync(ct);

        (await act.Should().ThrowAsync<ZeeKayDaConfigurationException>())
            .WithMessage("*no_eligible_version*Create a new key version*");
    }

    [Fact]
    public async Task ReadAsync_no_eligible_version_error_names_the_NotBefore_instant_when_it_is_later_than_the_age_gate()
    {
        // A staged version can be blocked by its own nbf even after the age gate is satisfied — the
        // error must name the LATER of the two instants, since waiting out only the age gate would
        // still not let it sign.
        var ct = TestContext.Current.CancellationToken;
        var now = T0 + TimeSpan.FromDays(10);
        var notBefore = now + TimeSpan.FromDays(3);
        var reader = new FakeKeyVaultKeyReader();
        reader.AddRsaVersion("v1", createdOn: T0, enabled: false);
        reader.AddRsaVersion("v2", createdOn: now - TimeSpan.FromHours(1), notBefore: notBefore);
        var sut = BuildSource(reader, new FakeTimeProvider(now));

        var act = async () => await sut.ReadAsync(ct);

        (await act.Should().ThrowAsync<ZeeKayDaConfigurationException>())
            .WithMessage($"*no_eligible_version*{notBefore:O}*");
    }

    [Fact]
    public async Task ReadAsync_no_eligible_version_error_names_the_ripening_instant_of_a_version_expiring_after_it()
    {
        var ct = TestContext.Current.CancellationToken;
        var now = T0 + TimeSpan.FromDays(10);
        var reader = new FakeKeyVaultKeyReader();
        reader.AddRsaVersion("v1", createdOn: T0, enabled: false);
        reader.AddRsaVersion("v2", createdOn: now - TimeSpan.FromHours(1), expiresOn: now + TimeSpan.FromDays(30));
        var sut = BuildSource(reader, new FakeTimeProvider(now));

        var act = async () => await sut.ReadAsync(ct);

        var ripensAt = now - TimeSpan.FromHours(1) + DefaultPreActivationDelay;
        (await act.Should().ThrowAsync<ZeeKayDaConfigurationException>())
            .WithMessage($"*no_eligible_version*{ripensAt:O}*");
    }

    [Fact]
    public async Task ReadAsync_no_eligible_version_error_says_create_a_new_version_when_every_enabled_version_has_expired()
    {
        // An already-expired version's PAST eligibility instant must not be presented as a wait
        // target — waiting can never succeed, so the only remedy is a new version.
        var ct = TestContext.Current.CancellationToken;
        var now = T0 + TimeSpan.FromDays(10);
        var reader = new FakeKeyVaultKeyReader();
        reader.AddRsaVersion("v1", createdOn: T0, enabled: false);
        reader.AddRsaVersion("v2", createdOn: T0 + TimeSpan.FromDays(1), expiresOn: T0 + TimeSpan.FromDays(5));
        var sut = BuildSource(reader, new FakeTimeProvider(now));

        var act = async () => await sut.ReadAsync(ct);

        (await act.Should().ThrowAsync<ZeeKayDaConfigurationException>())
            .WithMessage("*no_eligible_version*Create a new key version*");
    }

    [Fact]
    public async Task ReadAsync_propagates_a_version_listing_failure()
    {
        var ct = TestContext.Current.CancellationToken;
        var reader = new FakeKeyVaultKeyReader
        {
            VersionsException = new ZeeKayDaConfigurationException(
                new ZeeKayDaConfigurationFailure(
                    "signing.azure_key_vault.access_denied", "Simulated bad-credentials failure.")),
        };
        var sut = BuildSource(reader, new FakeTimeProvider(T0));

        var act = async () => await sut.ReadAsync(ct);

        (await act.Should().ThrowAsync<ZeeKayDaConfigurationException>())
            .WithMessage("*access_denied*");
    }

    [Fact]
    public async Task ReadAsync_does_not_memoize_a_failed_read()
    {
        var ct = TestContext.Current.CancellationToken;
        var reader = new FakeKeyVaultKeyReader();
        reader.AddRsaVersion("v1", createdOn: T0);
        reader.VersionsException = new ZeeKayDaConfigurationException(
            new ZeeKayDaConfigurationFailure("signing.azure_key_vault.startup_failure", "Transient outage."));
        var sut = BuildSource(reader, new FakeTimeProvider(T0));

        var firstAttempt = async () => await sut.ReadAsync(ct);
        await firstAttempt.Should().ThrowAsync<ZeeKayDaConfigurationException>();

        reader.VersionsException = null;
        var keySet = await sut.ReadAsync(ct);

        keySet.SigningKey.Id.Should().Be(new SourceKeyId("v1"),
            "a failed read is never cached, so a retry re-reads the vault");
    }

    // ── Read-once ────────────────────────────────────────────────────────────────────────────────

    [Fact]
    public async Task ReadAsync_reads_the_vault_exactly_once_and_ignores_versions_rotated_in_afterwards()
    {
        var ct = TestContext.Current.CancellationToken;
        var reader = new FakeKeyVaultKeyReader();
        reader.AddRsaVersion("v1", createdOn: T0);
        var timeProvider = new FakeTimeProvider(T0);
        var sut = BuildSource(reader, timeProvider);

        var first = await sut.ReadAsync(ct);

        reader.AddRsaVersion("v2", createdOn: T0 + TimeSpan.FromMinutes(1));
        timeProvider.SetUtcNow(T0 + TimeSpan.FromDays(30));
        var second = await sut.ReadAsync(ct);

        second.Should().BeSameAs(first, "read-once is a property of this source, not only of the ring");
        reader.GetKeyVersionsCallCount.Should().Be(1);
        PublishedIds(second).Should().Equal(["v1"],
            "a version rotated in after startup has no effect until the host restarts");
    }

    [Fact]
    public async Task ReadAsync_reads_the_vault_exactly_once_under_concurrent_readers()
    {
        var ct = TestContext.Current.CancellationToken;
        var reader = new FakeKeyVaultKeyReader();
        reader.AddRsaVersion("v1", createdOn: T0);
        var sut = BuildSource(reader, new FakeTimeProvider(T0));

        var first = sut.ReadAsync(ct).AsTask();
        var second = sut.ReadAsync(ct).AsTask();
        var results = await Task.WhenAll(first, second);

        results[1].Should().BeSameAs(results[0],
            "the read gate serialises concurrent readers onto the one memoized key set");
        reader.GetKeyVersionsCallCount.Should().Be(1);
    }

    // ── CreateSignerAsync ────────────────────────────────────────────────────────────────────────

    [Fact]
    public async Task CreateSignerAsync_returns_a_signer_whose_signature_verifies_against_the_reported_public_key()
    {
        var ct = TestContext.Current.CancellationToken;
        var reader = new FakeKeyVaultKeyReader();
        var v1 = reader.AddRsaVersion("v1", createdOn: T0);
        var signerSeam = new FakeKeyVaultSigner { SignFunc = RealRsaSignFunc(reader) };
        var sut = BuildSource(reader, new FakeTimeProvider(T0), signer: signerSeam);
        var keySet = await sut.ReadAsync(ct);

        using var signer = await sut.CreateSignerAsync(keySet.SigningKey.Id, ct);
        var signingInput = "header.payload"u8.ToArray();
        var signature = await signer.SignAsync(signingInput, ct);

        signer.Algorithm.Should().Be(SigningAlgorithm.RS256);
        signerSeam.Calls.Should().ContainSingle();
        signerSeam.Calls[0].KeyVersionUri.Should().Be(v1.Id,
            "signing must target the exact versioned key URI the read selected as the signing version");
        using var rsa = RSA.Create(keySet.SigningKey.PublicKey.RsaPublicParameters!.Value);
        rsa.VerifyData(signingInput, signature.Span, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1)
            .Should().BeTrue("the remote signer must sign with the same key pair whose public half the read reported");
    }

    [Fact]
    public async Task CreateSignerAsync_rejects_an_id_that_is_not_the_signing_version()
    {
        var ct = TestContext.Current.CancellationToken;
        var reader = new FakeKeyVaultKeyReader();
        reader.AddRsaVersion("v1", createdOn: T0);
        reader.AddRsaVersion("v2", createdOn: T0 + TimeSpan.FromDays(10));
        var sut = BuildSource(reader, new FakeTimeProvider(T0 + TimeSpan.FromDays(30)));
        var keySet = await sut.ReadAsync(ct);
        keySet.SigningKey.Id.Value.Should().Be("v2");

        var act = async () => await sut.CreateSignerAsync(new SourceKeyId("v1"), ct);

        await act.Should().ThrowAsync<InvalidOperationException>(
            "published-only versions never sign, so asking for one is a defect in the caller");
    }

    [Fact]
    public async Task CreateSignerAsync_rejects_any_id_before_a_successful_read()
    {
        var ct = TestContext.Current.CancellationToken;
        var reader = new FakeKeyVaultKeyReader();
        reader.AddRsaVersion("v1", createdOn: T0);
        var sut = BuildSource(reader, new FakeTimeProvider(T0));

        var act = async () => await sut.CreateSignerAsync(new SourceKeyId("v1"), ct);

        await act.Should().ThrowAsync<InvalidOperationException>();
    }

    [Fact]
    public async Task Disposing_a_signer_never_tears_down_the_shared_seam_and_a_later_signer_still_signs()
    {
        // The shared IKeyVaultSigner is a DI-owned seam pooling CryptographyClient instances; an
        // ISigner handed out by this source is one activation over it. Disposing the activation —
        // as the ring does on every handoff — must leave the seam fully usable for the next one.
        var ct = TestContext.Current.CancellationToken;
        var reader = new FakeKeyVaultKeyReader();
        reader.AddRsaVersion("v1", createdOn: T0);
        var signerSeam = new FakeKeyVaultSigner { SignFunc = RealRsaSignFunc(reader) };
        var sut = BuildSource(reader, new FakeTimeProvider(T0), signer: signerSeam);
        var keySet = await sut.ReadAsync(ct);

        var firstSigner = await sut.CreateSignerAsync(keySet.SigningKey.Id, ct);
        await firstSigner.SignAsync("payload"u8.ToArray(), ct);
        firstSigner.Dispose();

        signerSeam.DisposeCallCount.Should().Be(0,
            "disposing an activation must never dispose the shared, DI-owned seam");

        using var secondSigner = await sut.CreateSignerAsync(keySet.SigningKey.Id, ct);
        var signature = await secondSigner.SignAsync("payload"u8.ToArray(), ct);

        signature.ToArray().Should().NotBeEmpty("the seam must still sign after an earlier activation was disposed");
        signerSeam.DisposeCallCount.Should().Be(0);
    }
}
