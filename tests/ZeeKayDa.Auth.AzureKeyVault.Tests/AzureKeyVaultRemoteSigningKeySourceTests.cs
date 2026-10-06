using System.Security.Cryptography;
using Azure.Security.KeyVault.Keys;
using Microsoft.Extensions.Options;
using ZeeKayDa.Auth.AzureKeyVault.Tests.Fakes;
using ZeeKayDa.Auth.Tokens;

namespace ZeeKayDa.Auth.AzureKeyVault.Tests;

/// <summary>
/// Direct-construction tests for <see cref="AzureKeyVaultRemoteSigningKeySource"/>, bypassing DI and
/// the <c>AddAzureKeyVaultRemoteSigning</c> extension entirely, and mirroring
/// <c>WindowsCertificateStoreSigningKeySourceTests</c>'s shape. The Key Vault-specific concern they
/// add is the listing: every enabled version, dated from the vault's own per-version metadata.
/// </summary>
public sealed class AzureKeyVaultRemoteSigningKeySourceTests
{
    private static readonly Uri KeyIdentifierUri = new("https://fake-vault.vault.azure.net/keys/fake-key");
    private static readonly DateTimeOffset T0 = DateTimeOffset.Parse("2026-01-01T00:00:00Z");

    private static AzureKeyVaultRemoteSigningKeySource BuildSource(
        FakeKeyVaultKeyReader reader,
        FakeKeyVaultSigner? signer = null,
        SigningAlgorithm algorithm = SigningAlgorithm.RS256,
        int? maxVersions = null)
    {
        var options = Options.Create(new AzureKeyVaultRemoteSigningOptions
        {
            KeyIdentifier = new KeyVaultKeyIdentifier(KeyIdentifierUri),
            Credential = new FakeTokenCredential(),
            Algorithm = algorithm,
            MaxVersions = maxVersions,
        });

        return new AzureKeyVaultRemoteSigningKeySource(options, reader, signer ?? new FakeKeyVaultSigner());
    }

    private static IOptions<AzureKeyVaultRemoteSigningOptions> ValidOptions() =>
        Options.Create(new AzureKeyVaultRemoteSigningOptions
        {
            KeyIdentifier = new KeyVaultKeyIdentifier(KeyIdentifierUri),
            Credential = new FakeTokenCredential(),
            Algorithm = SigningAlgorithm.RS256,
        });

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

    private static string[] PublishedIds(IReadOnlyList<SourceKey> keySet) => [.. keySet.Select(k => k.Id.Value)];

    // ── Listing ──────────────────────────────────────────────────────────────────────────────────

    [Fact]
    public async Task ReadAsync_lists_every_enabled_version_with_its_public_key_only()
    {
        var ct = TestContext.Current.CancellationToken;
        var reader = new FakeKeyVaultKeyReader();
        reader.AddRsaVersion("v1", createdOn: T0);
        reader.AddRsaVersion("v2", createdOn: T0 + TimeSpan.FromDays(10));
        var sut = BuildSource(reader);

        var keySet = await sut.ReadAsync(ct);

        PublishedIds(keySet).Should().BeEquivalentTo(["v1", "v2"]);
        keySet.Should().AllSatisfy(key =>
        {
            key.Algorithm.Should().Be(SigningAlgorithm.RS256);
            key.PublicKey.RsaPublicParameters!.Value.D.Should().BeNull("only public material may leave the read path");
        });
    }

    [Fact]
    public async Task ReadAsync_does_not_list_a_disabled_version()
    {
        var ct = TestContext.Current.CancellationToken;
        var reader = new FakeKeyVaultKeyReader();
        reader.AddRsaVersion("v1", createdOn: T0);
        reader.AddRsaVersion("v2", createdOn: T0 + TimeSpan.FromDays(10), enabled: false);
        var sut = BuildSource(reader);

        var keySet = await sut.ReadAsync(ct);

        PublishedIds(keySet).Should().Equal("v1");
    }

    [Fact]
    public async Task ReadAsync_dates_a_version_from_its_creation_when_its_NotBefore_is_earlier()
    {
        var ct = TestContext.Current.CancellationToken;
        var expiresOn = T0 + TimeSpan.FromDays(365);
        var reader = new FakeKeyVaultKeyReader();
        reader.AddRsaVersion("v1", createdOn: T0, notBefore: T0 - TimeSpan.FromDays(1), expiresOn: expiresOn);
        var sut = BuildSource(reader);

        var key = (await sut.ReadAsync(ct)).Single();

        key.NotBefore.Should().Be(T0, "a version is published from its creation, never before");
        key.ExpiresAt.Should().Be(expiresOn);
    }

    [Fact]
    public async Task ReadAsync_dates_a_version_from_its_NotBefore_when_later_than_its_creation()
    {
        var ct = TestContext.Current.CancellationToken;
        var notBefore = T0 + TimeSpan.FromDays(3);
        var reader = new FakeKeyVaultKeyReader();
        reader.AddRsaVersion("v1", createdOn: T0, notBefore: notBefore);
        var sut = BuildSource(reader);

        var key = (await sut.ReadAsync(ct)).Single();

        key.NotBefore.Should().Be(notBefore, "a version may not sign before its own nbf");
        key.ExpiresAt.Should().Be(DateTimeOffset.MaxValue);
    }

    [Fact]
    public async Task ReadAsync_maps_ec_key_material()
    {
        var ct = TestContext.Current.CancellationToken;
        var reader = new FakeKeyVaultKeyReader();
        reader.AddEcVersion("v1", createdOn: T0);
        var sut = BuildSource(reader, algorithm: SigningAlgorithm.ES256);

        var keySet = await sut.ReadAsync(ct);

        keySet.Single().PublicKey.KeyType.Should().Be(SigningKeyType.Ec);
        keySet.Single().PublicKey.EcPublicParameters.Should().NotBeNull();
    }

    // ── Failure paths: always throw, never a partial set ─────────────────────────────────────────

    [Fact]
    public async Task ReadAsync_throws_when_the_key_has_no_versions()
    {
        var ct = TestContext.Current.CancellationToken;
        var sut = BuildSource(new FakeKeyVaultKeyReader());

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
        var sut = BuildSource(reader);

        var act = async () => await sut.ReadAsync(ct);

        (await act.Should().ThrowAsync<ZeeKayDaConfigurationException>())
            .WithMessage("*no_enabled_version*");
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
        var sut = BuildSource(reader);

        var act = async () => await sut.ReadAsync(ct);

        (await act.Should().ThrowAsync<ZeeKayDaConfigurationException>())
            .WithMessage("*access_denied*");
    }

    [Fact]
    public async Task ReadAsync_throws_when_a_listed_versions_identifier_uri_is_not_version_pinned()
    {
        // Defence-in-depth behind the ring's self-test: an unpinned URI would make the SDK's
        // CryptographyClient sign with whatever version is newest at sign time, not the version
        // whose public half was published.
        var ct = TestContext.Current.CancellationToken;
        var reader = new FakeKeyVaultKeyReader();
        reader.AddRsaVersion("v1", createdOn: T0, id: new Uri("https://fake-vault.vault.azure.net/keys/fake-key"));
        var sut = BuildSource(reader);

        var act = async () => await sut.ReadAsync(ct);

        (await act.Should().ThrowAsync<ZeeKayDaConfigurationException>())
            .WithMessage("*unversioned_key_uri*");
    }

    [Fact]
    public async Task ReadAsync_throws_rather_than_returning_a_partial_set_when_the_listing_fails_mid_enumeration()
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
    public async Task CreateSignerAsync_honours_a_cancelled_token_before_opening_a_signer()
    {
        var ct = TestContext.Current.CancellationToken;
        var reader = new FakeKeyVaultKeyReader();
        reader.AddRsaVersion("v1", createdOn: T0);
        var sut = BuildSource(reader);
        var keySet = await sut.ReadAsync(ct);

        var act = () => sut.CreateSignerAsync(keySet.Single().Id, new CancellationToken(canceled: true));

        await act.Should().ThrowAsync<OperationCanceledException>();
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
        var sut = BuildSource(reader);

        var act = async () => await sut.ReadAsync(ct);

        (await act.Should().ThrowAsync<ZeeKayDaConfigurationException>())
            .WithMessage("*access_denied*");
    }

    [Fact]
    public async Task ReadAsync_recovers_on_retry_after_a_failed_read()
    {
        var ct = TestContext.Current.CancellationToken;
        var reader = new FakeKeyVaultKeyReader();
        reader.AddRsaVersion("v1", createdOn: T0);
        reader.VersionsException = new ZeeKayDaConfigurationException(
            new ZeeKayDaConfigurationFailure("signing.azure_key_vault.startup_failure", "Transient outage."));
        var sut = BuildSource(reader);

        var firstAttempt = async () => await sut.ReadAsync(ct);
        await firstAttempt.Should().ThrowAsync<ZeeKayDaConfigurationException>();

        reader.VersionsException = null;
        var keySet = await sut.ReadAsync(ct);

        keySet.Single().Id.Should().Be(new SourceKeyId("v1"),
            "nothing is remembered between reads, so a retry re-reads the vault");
    }

    // ── Every read hits the vault ────────────────────────────────────────────────────────────────

    [Fact]
    public async Task ReadAsync_re_reads_the_vault_and_lists_a_version_rotated_in_afterwards()
    {
        var ct = TestContext.Current.CancellationToken;
        var reader = new FakeKeyVaultKeyReader();
        reader.AddRsaVersion("v1", createdOn: T0);
        var sut = BuildSource(reader);

        var first = await sut.ReadAsync(ct);
        reader.AddRsaVersion("v2", createdOn: T0 + TimeSpan.FromMinutes(1));
        var second = await sut.ReadAsync(ct);

        reader.GetKeyVersionsCallCount.Should().Be(2);
        PublishedIds(first).Should().Equal(["v1"]);
        PublishedIds(second).Should().BeEquivalentTo(["v1", "v2"],
            "a version rotated in after the first read is observed by the next one");
    }

    [Fact]
    public async Task ReadAsync_stops_listing_a_version_that_is_disabled_after_the_first_read()
    {
        var ct = TestContext.Current.CancellationToken;
        var reader = new FakeKeyVaultKeyReader();
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
        var reader = new FakeKeyVaultKeyReader();
        reader.AddRsaVersion("v1", createdOn: T0);
        var sut = BuildSource(reader);

        var results = await Task.WhenAll(sut.ReadAsync(ct), sut.ReadAsync(ct));

        reader.GetKeyVersionsCallCount.Should().Be(2, "there is no read gate and no cached set to share");
        results.Should().AllSatisfy(keySet => PublishedIds(keySet).Should().Equal(["v1"]));
    }

    [Fact]
    public async Task CreateSignerAsync_rejects_a_version_the_latest_read_no_longer_lists()
    {
        // The listed-version map is replaced by each read, so a version that fell out of the listing
        // (here: disabled in the vault) can no longer be signed with.
        var ct = TestContext.Current.CancellationToken;
        var reader = new FakeKeyVaultKeyReader();
        reader.AddRsaVersion("v1", createdOn: T0);
        reader.AddRsaVersion("v2", createdOn: T0 + TimeSpan.FromDays(10));
        var sut = BuildSource(reader);
        await sut.ReadAsync(ct);
        reader.SetEnabled("v1", false);
        await sut.ReadAsync(ct);

        var act = async () => await sut.CreateSignerAsync(new SourceKeyId("v1"), ct);

        await act.Should().ThrowAsync<InvalidOperationException>();
    }

    [Fact]
    public async Task CreateSignerAsync_still_opens_a_previously_listed_version_after_a_later_read_fails()
    {
        // The listed-version map is committed only once a read has fully succeeded, so a failed read
        // neither clears it nor leaves a half-built one.
        var ct = TestContext.Current.CancellationToken;
        var reader = new FakeKeyVaultKeyReader();
        reader.AddRsaVersion("v1", createdOn: T0);
        var sut = BuildSource(reader);
        await sut.ReadAsync(ct);
        reader.AddRsaVersion("v2", createdOn: T0 + TimeSpan.FromDays(10));
        reader.SetKeyMaterialException("v2", new ZeeKayDaConfigurationException(
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
        var reader = new FakeKeyVaultKeyReader();
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
        var reader = new FakeKeyVaultKeyReader();
        reader.AddRsaVersion("v1", createdOn: T0);
        reader.AddRsaVersion("v2", createdOn: T0 + TimeSpan.FromDays(10));
        reader.AddRsaVersion("v3", createdOn: T0 + TimeSpan.FromDays(20));
        reader.AddRsaVersion("v4", createdOn: T0 + TimeSpan.FromDays(30));
        reader.AddRsaVersion("v5", createdOn: T0 + TimeSpan.FromDays(40));
        var sut = BuildSource(reader, maxVersions: 3);

        await sut.ReadAsync(ct);

        reader.KeyMaterialCalls.Should().BeEquivalentTo(["v3", "v4", "v5"],
            "a version outside MaxVersions costs no per-version fetch");
    }

    [Fact]
    public async Task ReadAsync_with_MaxVersions_does_not_count_a_disabled_version_toward_N()
    {
        var ct = TestContext.Current.CancellationToken;
        var reader = new FakeKeyVaultKeyReader();
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
        var listedFirst = new FakeKeyVaultKeyReader();
        listedFirst.AddRsaVersion("v1", createdOn: T0);
        listedFirst.AddRsaVersion("va", createdOn: T0 + TimeSpan.FromDays(1));
        listedFirst.AddRsaVersion("vb", createdOn: T0 + TimeSpan.FromDays(1));
        listedFirst.AddRsaVersion("v3", createdOn: T0 + TimeSpan.FromDays(2));
        listedFirst.AddRsaVersion("v4", createdOn: T0 + TimeSpan.FromDays(3));
        var listedSecond = new FakeKeyVaultKeyReader();
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
        // A version created early but not valid until later is newer in the sense that matters: the
        // core picks the signer by NotBefore, so that is the order MaxVersions must trim by.
        var ct = TestContext.Current.CancellationToken;
        var reader = new FakeKeyVaultKeyReader();
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
    public async Task ReadAsync_with_MaxVersions_larger_than_the_version_count_lists_every_enabled_version()
    {
        var ct = TestContext.Current.CancellationToken;
        var reader = new FakeKeyVaultKeyReader();
        reader.AddRsaVersion("v1", createdOn: T0);
        reader.AddRsaVersion("v2", createdOn: T0 + TimeSpan.FromDays(10));
        var sut = BuildSource(reader, maxVersions: 5);

        var keySet = await sut.ReadAsync(ct);

        PublishedIds(keySet).Should().BeEquivalentTo(["v1", "v2"]);
    }

    [Fact]
    public async Task ReadAsync_without_MaxVersions_fetches_public_material_for_every_enabled_version()
    {
        var ct = TestContext.Current.CancellationToken;
        var reader = new FakeKeyVaultKeyReader();
        for (var i = 1; i <= 5; i++)
            reader.AddRsaVersion($"v{i}", createdOn: T0 + TimeSpan.FromDays(i));
        var sut = BuildSource(reader);

        await sut.ReadAsync(ct);

        reader.KeyMaterialCalls.Should().BeEquivalentTo(["v1", "v2", "v3", "v4", "v5"]);
    }

    [Fact]
    public async Task CreateSignerAsync_rejects_an_enabled_version_that_MaxVersions_left_out_of_the_listing()
    {
        var ct = TestContext.Current.CancellationToken;
        var reader = new FakeKeyVaultKeyReader();
        for (var i = 1; i <= 4; i++)
            reader.AddRsaVersion($"v{i}", createdOn: T0 + TimeSpan.FromDays(i));
        var sut = BuildSource(reader, maxVersions: 3);
        await sut.ReadAsync(ct);

        var act = async () => await sut.CreateSignerAsync(new SourceKeyId("v1"), ct);

        await act.Should().ThrowAsync<InvalidOperationException>(
            "a version outside the listing was never published, so signing with it is a caller defect");
    }

    // ── CreateSignerAsync ────────────────────────────────────────────────────────────────────────

    [Fact]
    public async Task CreateSignerAsync_returns_a_signer_whose_signature_verifies_against_the_reported_public_key()
    {
        var ct = TestContext.Current.CancellationToken;
        var reader = new FakeKeyVaultKeyReader();
        var v1 = reader.AddRsaVersion("v1", createdOn: T0);
        var signerSeam = new FakeKeyVaultSigner { SignFunc = RealRsaSignFunc(reader) };
        var sut = BuildSource(reader, signer: signerSeam);
        var keySet = await sut.ReadAsync(ct);

        using var signer = await sut.CreateSignerAsync(keySet.Single().Id, ct);
        var signingInput = "header.payload"u8.ToArray();
        var signature = await signer.SignAsync(signingInput, ct);

        signerSeam.Calls.Should().ContainSingle();
        signerSeam.Calls[0].KeyVersionUri.Should().Be(v1.Id,
            "signing must target the exact versioned key URI the read selected as the signing version");
        using var rsa = RSA.Create(keySet.Single().PublicKey.RsaPublicParameters!.Value);
        rsa.VerifyData(signingInput, signature.Span, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1)
            .Should().BeTrue("the remote signer must sign with the same key pair whose public half the read reported");
    }

    [Fact]
    public async Task CreateSignerAsync_opens_a_signer_for_any_listed_version_pinned_to_that_version()
    {
        var ct = TestContext.Current.CancellationToken;
        var reader = new FakeKeyVaultKeyReader();
        reader.AddRsaVersion("v1", createdOn: T0);
        reader.AddRsaVersion("v2", createdOn: T0 + TimeSpan.FromDays(10));
        var signerSeam = new FakeKeyVaultSigner { SignFunc = RealRsaSignFunc(reader) };
        var sut = BuildSource(reader, signer: signerSeam);
        await sut.ReadAsync(ct);

        using var signer = await sut.CreateSignerAsync(new SourceKeyId("v1"), ct);
        await signer.SignAsync("header.payload"u8.ToArray(), ct);

        signerSeam.Calls.Should().ContainSingle().Which.KeyVersionUri.Segments[^1].Should().Be("v1");
    }

    [Fact]
    public async Task CreateSignerAsync_rejects_an_id_that_was_not_listed()
    {
        var ct = TestContext.Current.CancellationToken;
        var reader = new FakeKeyVaultKeyReader();
        reader.AddRsaVersion("v1", createdOn: T0);
        reader.AddRsaVersion("v2", createdOn: T0 + TimeSpan.FromDays(10), enabled: false);
        var sut = BuildSource(reader);
        await sut.ReadAsync(ct);

        var act = async () => await sut.CreateSignerAsync(new SourceKeyId("v2"), ct);

        await act.Should().ThrowAsync<InvalidOperationException>(
            "a disabled version was never listed, so asking for it is a defect in the caller");
    }

    [Fact]
    public async Task CreateSignerAsync_rejects_any_id_before_a_successful_read()
    {
        var ct = TestContext.Current.CancellationToken;
        var reader = new FakeKeyVaultKeyReader();
        reader.AddRsaVersion("v1", createdOn: T0);
        var sut = BuildSource(reader);

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
        var sut = BuildSource(reader, signer: signerSeam);
        var keySet = await sut.ReadAsync(ct);

        var firstSigner = await sut.CreateSignerAsync(keySet.Single().Id, ct);
        await firstSigner.SignAsync("payload"u8.ToArray(), ct);
        firstSigner.Dispose();

        signerSeam.DisposeCallCount.Should().Be(0,
            "disposing an activation must never dispose the shared, DI-owned seam");

        using var secondSigner = await sut.CreateSignerAsync(keySet.Single().Id, ct);
        var signature = await secondSigner.SignAsync("payload"u8.ToArray(), ct);

        signature.ToArray().Should().NotBeEmpty("the seam must still sign after an earlier activation was disposed");
        signerSeam.DisposeCallCount.Should().Be(0);
    }
}
