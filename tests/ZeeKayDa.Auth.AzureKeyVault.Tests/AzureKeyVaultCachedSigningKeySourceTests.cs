using System.Security.Cryptography;
using Azure.Security.KeyVault.Certificates;
using Microsoft.Extensions.Options;
using ZeeKayDa.Auth.AzureKeyVault.Tests.Fakes;
using ZeeKayDa.Auth.Tokens;

namespace ZeeKayDa.Auth.AzureKeyVault.Tests;

/// <summary>
/// Direct-construction tests for <see cref="AzureKeyVaultCachedSigningKeySource"/>, bypassing DI
/// and the <c>AddAzureKeyVaultCachedSigning</c> extension entirely. The listing itself is
/// <see cref="KeyVaultVersions"/>, shared with the remote source; what this file adds is the cached
/// provider's own concerns — above all the least-privilege obligation that <b>private material is
/// downloaded only for the version asked to sign, and only in
/// <see cref="AzureKeyVaultCachedSigningKeySource.CreateSignerAsync"/></b> — plus the local-signing
/// round trip. The source holds no cache and no lock: every read re-reads the vault. It does not
/// pair the downloaded private key with the published public key; the ring's startup self-test does
/// (see <c>AzureKeyVaultCachedSigningIntegrationTests</c>).
/// </summary>
public sealed class AzureKeyVaultCachedSigningKeySourceTests
{
    private static readonly Uri CertificateIdentifierUri = new("https://fake-vault.vault.azure.net/certificates/fake-cert");
    private static readonly DateTimeOffset T0 = DateTimeOffset.Parse("2026-01-01T00:00:00Z");

    private static AzureKeyVaultCachedSigningKeySource BuildSource(
        FakeKeyVaultCertificateReader reader,
        SigningAlgorithm algorithm = SigningAlgorithm.RS256,
        int? maxVersions = null)
    {
        var options = Options.Create(new AzureKeyVaultCachedSigningOptions
        {
            CertificateIdentifier = new KeyVaultCertificateIdentifier(CertificateIdentifierUri),
            Credential = new FakeTokenCredential(),
            Algorithm = algorithm,
            MaxVersions = maxVersions,
        });

        return new AzureKeyVaultCachedSigningKeySource(options, reader);
    }

    private static string[] PublishedIds(IReadOnlyList<SourceKey> keySet) => [.. keySet.Select(k => k.Id.Value)];

    // ── Happy path ───────────────────────────────────────────────────────────────────────────────

    [Fact]
    public async Task ReadAsync_reports_a_versions_public_key_and_validity_window()
    {
        var ct = TestContext.Current.CancellationToken;
        var notBefore = T0 + TimeSpan.FromDays(1);
        var expiresOn = T0 + TimeSpan.FromDays(365);
        var reader = new FakeKeyVaultCertificateReader();
        reader.AddRsaVersion("v1", createdOn: T0, notBefore: notBefore, expiresOn: expiresOn);
        var sut = BuildSource(reader);

        var keySet = await sut.ReadAsync(ct);

        keySet.Should().ContainSingle();
        keySet.Single().Id.Should().Be(new SourceKeyId("v1"));
        keySet.Single().Algorithm.Should().Be(SigningAlgorithm.RS256);
        keySet.Single().PublicKey.RsaPublicParameters.Should().NotBeNull(
            "only public material may ever leave this source's read path");
        keySet.Single().NotBefore.Should().Be(notBefore);
        keySet.Single().ExpiresAt.Should().Be(expiresOn);
    }

    [Fact]
    public async Task ReadAsync_maps_ec_key_material()
    {
        var ct = TestContext.Current.CancellationToken;
        var reader = new FakeKeyVaultCertificateReader();
        reader.AddEcVersion("v1", createdOn: T0);
        var sut = BuildSource(reader, algorithm: SigningAlgorithm.ES256);

        var keySet = await sut.ReadAsync(ct);

        keySet.Single().PublicKey.KeyType.Should().Be(SigningKeyType.Ec);
        keySet.Single().PublicKey.EcPublicParameters.Should().NotBeNull();
    }

    // ── Least privilege: private material only for the version asked to sign ──────────────────────

    [Fact]
    public async Task ReadAsync_never_downloads_private_material_for_any_version()
    {
        var ct = TestContext.Current.CancellationToken;
        var now = T0 + TimeSpan.FromDays(30);
        var reader = new FakeKeyVaultCertificateReader();
        reader.AddRsaVersion("v1", createdOn: T0);
        reader.AddRsaVersion("v2", createdOn: T0 + TimeSpan.FromDays(1));
        reader.AddRsaVersion("v3", createdOn: now - TimeSpan.FromHours(1));
        var sut = BuildSource(reader);

        await sut.ReadAsync(ct);

        reader.PrivateKeyMaterialCalls.Should().BeEmpty(
            "a read publishes public halves only — no version's private key has any reason to exist " +
            "in process memory until a signer is created");
        reader.PublicKeyMaterialCalls.Should().BeEquivalentTo(["v1", "v2", "v3"]);
    }

    [Fact]
    public async Task CreateSignerAsync_downloads_private_material_for_exactly_the_version_asked_for()
    {
        var ct = TestContext.Current.CancellationToken;
        var now = T0 + TimeSpan.FromDays(30);
        var reader = new FakeKeyVaultCertificateReader();
        reader.AddRsaVersion("v1", createdOn: T0);
        reader.AddRsaVersion("v2", createdOn: T0 + TimeSpan.FromDays(1));
        var sut = BuildSource(reader);
        await sut.ReadAsync(ct);

        using var signer = await sut.CreateSignerAsync(new SourceKeyId("v1"), ct);

        reader.PrivateKeyMaterialCalls.Should().Equal(["v1"],
            "the requested version's private key is the only one ever downloaded");
    }

    [Fact]
    public async Task CreateSignerAsync_rejects_an_id_that_was_not_listed_without_downloading_anything()
    {
        var ct = TestContext.Current.CancellationToken;
        var reader = new FakeKeyVaultCertificateReader();
        reader.AddRsaVersion("v1", createdOn: T0);
        reader.AddRsaVersion("v2", createdOn: T0 + TimeSpan.FromDays(1), enabled: false);
        var sut = BuildSource(reader);
        await sut.ReadAsync(ct);

        var act = async () => await sut.CreateSignerAsync(new SourceKeyId("v2"), ct);

        await act.Should().ThrowAsync<InvalidOperationException>(
            "a disabled version was never listed, so asking for it is a defect in the caller");
        reader.PrivateKeyMaterialCalls.Should().BeEmpty(
            "the rejection must happen before any private key is downloaded");
    }

    [Fact]
    public async Task CreateSignerAsync_rejects_any_id_before_a_successful_read()
    {
        var ct = TestContext.Current.CancellationToken;
        var reader = new FakeKeyVaultCertificateReader();
        reader.AddRsaVersion("v1", createdOn: T0);
        var sut = BuildSource(reader);

        var act = async () => await sut.CreateSignerAsync(new SourceKeyId("v1"), ct);

        await act.Should().ThrowAsync<InvalidOperationException>();
        reader.PrivateKeyMaterialCalls.Should().BeEmpty();
    }

    // ── Local signing ────────────────────────────────────────────────────────────────────────────

    [Fact]
    public async Task CreateSignerAsync_returns_a_signer_whose_signature_verifies_against_the_reported_public_key()
    {
        var ct = TestContext.Current.CancellationToken;
        var reader = new FakeKeyVaultCertificateReader();
        reader.AddRsaVersion("v1", createdOn: T0);
        var sut = BuildSource(reader);
        var keySet = await sut.ReadAsync(ct);

        using var signer = await sut.CreateSignerAsync(keySet.Single().Id, ct);
        var signingInput = "header.payload"u8.ToArray();
        var signature = await signer.SignAsync(signingInput, ct);

        using var rsa = RSA.Create(keySet.Single().PublicKey.RsaPublicParameters!.Value);
        rsa.VerifyData(signingInput, signature.Span, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1)
            .Should().BeTrue("the local signer must sign with the same key pair whose public half the read reported");
    }

    // ── Failure paths: always throw, never a partial set ─────────────────────────────────────────

    [Fact]
    public async Task ReadAsync_throws_when_the_certificate_has_no_versions()
    {
        var ct = TestContext.Current.CancellationToken;
        var sut = BuildSource(new FakeKeyVaultCertificateReader());

        var act = async () => await sut.ReadAsync(ct);

        (await act.Should().ThrowAsync<ZeeKayDaConfigurationException>())
            .WithMessage("*no_certificate_versions*");
    }

    [Fact]
    public async Task ReadAsync_throws_when_no_version_is_enabled()
    {
        var ct = TestContext.Current.CancellationToken;
        var reader = new FakeKeyVaultCertificateReader();
        reader.AddRsaVersion("v1", createdOn: T0, enabled: false);
        var sut = BuildSource(reader);

        var act = async () => await sut.ReadAsync(ct);

        (await act.Should().ThrowAsync<ZeeKayDaConfigurationException>())
            .WithMessage("*no_enabled_version*");
    }

    [Fact]
    public async Task ReadAsync_throws_rather_than_returning_a_partial_set_when_a_published_versions_material_fails_to_load()
    {
        var ct = TestContext.Current.CancellationToken;
        var reader = new FakeKeyVaultCertificateReader();
        reader.AddRsaVersion("v1", createdOn: T0);
        reader.AddRsaVersion("v2", createdOn: T0 + TimeSpan.FromDays(10));
        reader.SetPublicKeyException("v1", new ZeeKayDaConfigurationException(
            new ZeeKayDaConfigurationFailure("signing.azure_key_vault.access_denied", "Simulated failure for v1.")));
        var sut = BuildSource(reader);

        var act = async () => await sut.ReadAsync(ct);

        (await act.Should().ThrowAsync<ZeeKayDaConfigurationException>())
            .WithMessage("*access_denied*");
    }

    [Fact]
    public async Task ReadAsync_throws_rather_than_returning_a_partial_set_when_the_listing_fails_mid_enumeration()
    {
        var ct = TestContext.Current.CancellationToken;
        var reader = new FakeKeyVaultCertificateReader();
        reader.AddRsaVersion("v1", createdOn: T0);
        reader.AddRsaVersion("v2", createdOn: T0 + TimeSpan.FromDays(10));
        reader.AddRsaVersion("v3", createdOn: T0 + TimeSpan.FromDays(20));
        reader.MidEnumerationFailure = (2, new ZeeKayDaConfigurationException(
            new ZeeKayDaConfigurationFailure("signing.azure_key_vault.startup_failure", "Simulated paging failure.")));
        var sut = BuildSource(reader);

        var act = async () => await sut.ReadAsync(ct);
        (await act.Should().ThrowAsync<ZeeKayDaConfigurationException>())
            .WithMessage("*startup_failure*");

        reader.MidEnumerationFailure = null;
        var keySet = await sut.ReadAsync(ct);

        PublishedIds(keySet).Should().BeEquivalentTo(["v1", "v2", "v3"],
            "the partial two-version read must not have been kept — the retry sees the full history");
    }

    [Fact]
    public async Task CreateSignerAsync_propagates_a_non_exportable_certificate_failure()
    {
        // A non-exportable key policy is only detectable at private-key-download time — Key Vault
        // returns HTTP 200 with a PFX that simply omits the key bag. The reader's mapped failure
        // must reach the caller unmodified.
        var ct = TestContext.Current.CancellationToken;
        var reader = new FakeKeyVaultCertificateReader();
        reader.AddRsaVersion("v1", createdOn: T0);
        reader.SetPrivateKeyException("v1", new ZeeKayDaConfigurationException(
            new ZeeKayDaConfigurationFailure(
                "signing.azure_key_vault.certificate_not_exportable", "Simulated non-exportable policy.")));
        var sut = BuildSource(reader);
        var keySet = await sut.ReadAsync(ct);

        var act = async () => await sut.CreateSignerAsync(keySet.Single().Id, ct);

        (await act.Should().ThrowAsync<ZeeKayDaConfigurationException>())
            .WithMessage("*certificate_not_exportable*");
    }

    // ── Every read hits the vault ────────────────────────────────────────────────────────────────

    [Fact]
    public async Task ReadAsync_re_reads_the_vault_and_lists_a_version_rotated_in_afterwards()
    {
        var ct = TestContext.Current.CancellationToken;
        var reader = new FakeKeyVaultCertificateReader();
        reader.AddRsaVersion("v1", createdOn: T0);
        var sut = BuildSource(reader);

        var first = await sut.ReadAsync(ct);
        reader.AddRsaVersion("v2", createdOn: T0 + TimeSpan.FromMinutes(1));
        var second = await sut.ReadAsync(ct);

        reader.GetCertificateVersionsCallCount.Should().Be(2);
        PublishedIds(first).Should().Equal(["v1"]);
        PublishedIds(second).Should().BeEquivalentTo(["v1", "v2"],
            "a version rotated in after the first read is observed by the next one");
    }

    [Fact]
    public async Task ReadAsync_stops_listing_a_version_that_is_disabled_after_the_first_read()
    {
        var ct = TestContext.Current.CancellationToken;
        var reader = new FakeKeyVaultCertificateReader();
        reader.AddRsaVersion("v1", createdOn: T0);
        reader.AddRsaVersion("v2", createdOn: T0 + TimeSpan.FromDays(10));
        var sut = BuildSource(reader);
        await sut.ReadAsync(ct);

        reader.SetEnabled("v1", false);
        var second = await sut.ReadAsync(ct);

        PublishedIds(second).Should().Equal(["v2"]);
    }

    [Fact]
    public async Task ReadAsync_reads_the_vault_on_every_call_under_concurrent_readers()
    {
        var ct = TestContext.Current.CancellationToken;
        var reader = new FakeKeyVaultCertificateReader();
        reader.AddRsaVersion("v1", createdOn: T0);
        var sut = BuildSource(reader);

        var results = await Task.WhenAll(sut.ReadAsync(ct), sut.ReadAsync(ct));

        reader.GetCertificateVersionsCallCount.Should().Be(2, "there is no read gate and no cached set to share");
        results.Should().AllSatisfy(keySet => PublishedIds(keySet).Should().Equal(["v1"]));
    }

    [Fact]
    public async Task CreateSignerAsync_rejects_a_version_the_latest_read_no_longer_lists()
    {
        // The listed-version set is replaced by each read, so a version that fell out of the listing
        // (here: disabled in the vault) can no longer have its private key downloaded.
        var ct = TestContext.Current.CancellationToken;
        var reader = new FakeKeyVaultCertificateReader();
        reader.AddRsaVersion("v1", createdOn: T0);
        reader.AddRsaVersion("v2", createdOn: T0 + TimeSpan.FromDays(10));
        var sut = BuildSource(reader);
        await sut.ReadAsync(ct);
        reader.SetEnabled("v1", false);
        await sut.ReadAsync(ct);

        var act = async () => await sut.CreateSignerAsync(new SourceKeyId("v1"), ct);

        await act.Should().ThrowAsync<InvalidOperationException>();
        reader.PrivateKeyMaterialCalls.Should().BeEmpty();
    }

    [Fact]
    public async Task CreateSignerAsync_still_opens_a_previously_listed_version_after_a_later_read_fails()
    {
        // The listed-version set is committed only once a read has fully succeeded, so a failed read
        // neither clears it nor leaves a half-built one.
        var ct = TestContext.Current.CancellationToken;
        var reader = new FakeKeyVaultCertificateReader();
        reader.AddRsaVersion("v1", createdOn: T0);
        var sut = BuildSource(reader);
        await sut.ReadAsync(ct);
        reader.AddRsaVersion("v2", createdOn: T0 + TimeSpan.FromDays(10));
        reader.SetPublicKeyException("v2", new ZeeKayDaConfigurationException(
            new ZeeKayDaConfigurationFailure("signing.azure_key_vault.access_denied", "Simulated failure for v2.")));
        var failing = async () => await sut.ReadAsync(ct);
        await failing.Should().ThrowAsync<ZeeKayDaConfigurationException>();

        using var signer = await sut.CreateSignerAsync(new SourceKeyId("v1"), ct);
        var unlisted = async () => await sut.CreateSignerAsync(new SourceKeyId("v2"), ct);

        signer.Should().NotBeNull();
        await unlisted.Should().ThrowAsync<InvalidOperationException>("v2 was never part of a successful read");
    }

    // ── MaxVersions ──────────────────────────────────────────────────────────────────────────────

    [Fact]
    public async Task ReadAsync_with_MaxVersions_lists_only_the_N_newest_enabled_versions()
    {
        var ct = TestContext.Current.CancellationToken;
        var reader = new FakeKeyVaultCertificateReader();
        reader.AddRsaVersion("v1", createdOn: T0);
        reader.AddRsaVersion("v4", createdOn: T0 + TimeSpan.FromDays(30));
        reader.AddRsaVersion("v2", createdOn: T0 + TimeSpan.FromDays(10));
        reader.AddRsaVersion("v3", createdOn: T0 + TimeSpan.FromDays(20));
        var sut = BuildSource(reader, maxVersions: 3);

        var keySet = await sut.ReadAsync(ct);

        PublishedIds(keySet).Should().BeEquivalentTo(["v2", "v3", "v4"],
            "the oldest version falls outside the three newest, whatever order the vault enumerates them in");
    }

    [Fact]
    public async Task ReadAsync_with_MaxVersions_fetches_public_material_only_for_the_listed_versions()
    {
        var ct = TestContext.Current.CancellationToken;
        var reader = new FakeKeyVaultCertificateReader();
        for (var i = 1; i <= 5; i++)
            reader.AddRsaVersion($"v{i}", createdOn: T0 + TimeSpan.FromDays(i));
        var sut = BuildSource(reader, maxVersions: 3);

        await sut.ReadAsync(ct);

        reader.PublicKeyMaterialCalls.Should().BeEquivalentTo(["v3", "v4", "v5"],
            "a version outside MaxVersions costs no per-version fetch");
        reader.PrivateKeyMaterialCalls.Should().BeEmpty();
    }

    [Fact]
    public async Task ReadAsync_with_MaxVersions_does_not_count_a_disabled_version_toward_N()
    {
        var ct = TestContext.Current.CancellationToken;
        var reader = new FakeKeyVaultCertificateReader();
        reader.AddRsaVersion("v1", createdOn: T0);
        reader.AddRsaVersion("v2", createdOn: T0 + TimeSpan.FromDays(10));
        reader.AddRsaVersion("v3", createdOn: T0 + TimeSpan.FromDays(20));
        reader.AddRsaVersion("v4", createdOn: T0 + TimeSpan.FromDays(30), enabled: false);
        reader.AddRsaVersion("v5", createdOn: T0 + TimeSpan.FromDays(40), enabled: false);
        var sut = BuildSource(reader, maxVersions: 3);

        var keySet = await sut.ReadAsync(ct);

        PublishedIds(keySet).Should().BeEquivalentTo(["v1", "v2", "v3"],
            "the two newest versions are disabled, so the three newest ENABLED ones are listed");
    }

    [Fact]
    public async Task ReadAsync_with_MaxVersions_breaks_a_tie_on_NotBefore_by_the_ordinally_greater_version_whatever_the_listing_order()
    {
        // Two versions created in the same second straddle the cut. Every replica must keep the same
        // one, so the vault's listing order cannot decide.
        var ct = TestContext.Current.CancellationToken;
        var listedFirst = new FakeKeyVaultCertificateReader();
        listedFirst.AddRsaVersion("v1", createdOn: T0);
        listedFirst.AddRsaVersion("va", createdOn: T0 + TimeSpan.FromDays(1));
        listedFirst.AddRsaVersion("vb", createdOn: T0 + TimeSpan.FromDays(1));
        listedFirst.AddRsaVersion("v3", createdOn: T0 + TimeSpan.FromDays(2));
        listedFirst.AddRsaVersion("v4", createdOn: T0 + TimeSpan.FromDays(3));
        var listedSecond = new FakeKeyVaultCertificateReader();
        listedSecond.AddRsaVersion("v4", createdOn: T0 + TimeSpan.FromDays(3));
        listedSecond.AddRsaVersion("v3", createdOn: T0 + TimeSpan.FromDays(2));
        listedSecond.AddRsaVersion("vb", createdOn: T0 + TimeSpan.FromDays(1));
        listedSecond.AddRsaVersion("va", createdOn: T0 + TimeSpan.FromDays(1));
        listedSecond.AddRsaVersion("v1", createdOn: T0);

        var first = await BuildSource(listedFirst, maxVersions: 3).ReadAsync(ct);
        var second = await BuildSource(listedSecond, maxVersions: 3).ReadAsync(ct);

        PublishedIds(first).Should().BeEquivalentTo(["v4", "v3", "vb"]);
        PublishedIds(second).Should().BeEquivalentTo(["v4", "v3", "vb"]);
    }

    [Fact]
    public async Task ReadAsync_with_MaxVersions_orders_by_NotBefore_not_by_creation()
    {
        var ct = TestContext.Current.CancellationToken;
        var reader = new FakeKeyVaultCertificateReader();
        // v1 is the oldest by creation, so ordering by creation would drop it; by NotBefore it is the newest.
        reader.AddRsaVersion("v1", createdOn: T0, notBefore: T0 + TimeSpan.FromDays(100));
        reader.AddRsaVersion("v2", createdOn: T0 + TimeSpan.FromDays(1));
        reader.AddRsaVersion("v3", createdOn: T0 + TimeSpan.FromDays(2));
        reader.AddRsaVersion("v4", createdOn: T0 + TimeSpan.FromDays(3));
        var sut = BuildSource(reader, maxVersions: 3);

        var keySet = await sut.ReadAsync(ct);

        PublishedIds(keySet).Should().BeEquivalentTo(["v1", "v3", "v4"]);
    }

    [Fact]
    public async Task ReadAsync_without_MaxVersions_fetches_public_material_for_every_enabled_version()
    {
        var ct = TestContext.Current.CancellationToken;
        var reader = new FakeKeyVaultCertificateReader();
        for (var i = 1; i <= 5; i++)
            reader.AddRsaVersion($"v{i}", createdOn: T0 + TimeSpan.FromDays(i));
        var sut = BuildSource(reader);

        await sut.ReadAsync(ct);

        reader.PublicKeyMaterialCalls.Should().BeEquivalentTo(["v1", "v2", "v3", "v4", "v5"]);
    }

    [Fact]
    public async Task CreateSignerAsync_rejects_an_enabled_version_that_MaxVersions_left_out_of_the_listing()
    {
        var ct = TestContext.Current.CancellationToken;
        var reader = new FakeKeyVaultCertificateReader();
        for (var i = 1; i <= 4; i++)
            reader.AddRsaVersion($"v{i}", createdOn: T0 + TimeSpan.FromDays(i));
        var sut = BuildSource(reader, maxVersions: 3);
        await sut.ReadAsync(ct);

        var act = async () => await sut.CreateSignerAsync(new SourceKeyId("v1"), ct);

        await act.Should().ThrowAsync<InvalidOperationException>(
            "a version outside the listing was never published, so downloading its private key is a caller defect");
        reader.PrivateKeyMaterialCalls.Should().BeEmpty();
    }
}
