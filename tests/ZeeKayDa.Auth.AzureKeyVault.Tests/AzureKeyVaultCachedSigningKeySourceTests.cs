using System.Security.Cryptography;
using Azure.Security.KeyVault.Certificates;
using Microsoft.Extensions.Options;
using Microsoft.Extensions.Time.Testing;
using ZeeKayDa.Auth.AzureKeyVault.Tests.Fakes;
using ZeeKayDa.Auth.Tokens;

namespace ZeeKayDa.Auth.AzureKeyVault.Tests;

/// <summary>
/// Direct-construction tests for <see cref="AzureKeyVaultCachedSigningKeySource"/>, bypassing DI
/// and the <c>AddAzureKeyVaultCachedSigning</c> extension entirely. The listing itself is
/// <see cref="KeyVaultVersions"/>, shared with the remote source; what this file adds is the cached
/// provider's own concerns — above all the least-privilege obligation that <b>private material is
/// downloaded only for the version asked to sign, and only in
/// <see cref="AzureKeyVaultCachedSigningKeySource.CreateSignerAsync"/></b> — plus the secret-vs-Cer
/// cross-check and the local-signing round trip.
/// </summary>
public sealed class AzureKeyVaultCachedSigningKeySourceTests
{
    private static readonly Uri CertificateIdentifierUri = new("https://fake-vault.vault.azure.net/certificates/fake-cert");
    private static readonly DateTimeOffset T0 = DateTimeOffset.Parse("2026-01-01T00:00:00Z");

    private static AzureKeyVaultCachedSigningKeySource BuildSource(
        FakeKeyVaultCertificateReader reader,
        SigningAlgorithm algorithm = SigningAlgorithm.RS256)
    {
        var options = Options.Create(new AzureKeyVaultCachedSigningOptions
        {
            CertificateIdentifier = new KeyVaultCertificateIdentifier(CertificateIdentifierUri),
            Credential = new FakeTokenCredential(),
            Algorithm = algorithm,
        });

        return new AzureKeyVaultCachedSigningKeySource(options, reader);
    }

    private static IOptions<AzureKeyVaultCachedSigningOptions> ValidOptions() =>
        Options.Create(new AzureKeyVaultCachedSigningOptions
        {
            CertificateIdentifier = new KeyVaultCertificateIdentifier(CertificateIdentifierUri),
            Credential = new FakeTokenCredential(),
            Algorithm = SigningAlgorithm.RS256,
        });

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

    // ── Secret-vs-Cer cross-check ────────────────────────────────────────────────────────────────

    [Fact]
    public async Task CreateSignerAsync_rejects_a_downloaded_private_key_that_does_not_match_the_published_public_key()
    {
        var ct = TestContext.Current.CancellationToken;
        var reader = new FakeKeyVaultCertificateReader();
        reader.AddRsaVersion("v1", createdOn: T0);
        using var divergedKey = RSA.Create(2048);
        reader.SetMismatchedPrivateKeyMaterial("v1", divergedKey.ExportParameters(includePrivateParameters: true));
        AsymmetricAlgorithm? capturedPrivateKey = null;
        reader.OnPrivateKeyExtracted = (_, key) => capturedPrivateKey = key;
        var sut = BuildSource(reader);
        var keySet = await sut.ReadAsync(ct);

        var act = async () => await sut.CreateSignerAsync(keySet.Single().Id, ct);

        (await act.Should().ThrowAsync<ZeeKayDaConfigurationException>())
            .WithMessage("*secret_cer_mismatch*does not match*",
                "a configuration failure is absorbed verbatim by the ring, so the divergence reaches the operator named");
        capturedPrivateKey.Should().NotBeNull();
        var useAfterFailure = () => ((RSA)capturedPrivateKey!).ExportParameters(includePrivateParameters: false);
        useAfterFailure.Should().Throw<ObjectDisposedException>(
            "the diverged private key must be disposed, not left reachable, when the cross-check rejects it");
    }

    [Fact]
    public async Task CreateSignerAsync_rejects_a_downloaded_ec_private_key_that_does_not_match_the_published_public_key()
    {
        var ct = TestContext.Current.CancellationToken;
        var reader = new FakeKeyVaultCertificateReader();
        reader.AddEcVersion("v1", createdOn: T0);
        using var divergedKey = System.Security.Cryptography.ECDsa.Create(System.Security.Cryptography.ECCurve.NamedCurves.nistP256);
        reader.SetMismatchedPrivateKeyMaterial("v1", divergedKey.ExportParameters(includePrivateParameters: true));
        AsymmetricAlgorithm? capturedPrivateKey = null;
        reader.OnPrivateKeyExtracted = (_, key) => capturedPrivateKey = key;
        var sut = BuildSource(reader, algorithm: SigningAlgorithm.ES256);
        var keySet = await sut.ReadAsync(ct);

        var act = async () => await sut.CreateSignerAsync(keySet.Single().Id, ct);

        (await act.Should().ThrowAsync<ZeeKayDaConfigurationException>())
            .WithMessage("*secret_cer_mismatch*");
        capturedPrivateKey.Should().NotBeNull();
        var useAfterFailure = () => ((System.Security.Cryptography.ECDsa)capturedPrivateKey!).ExportParameters(includePrivateParameters: false);
        useAfterFailure.Should().Throw<ObjectDisposedException>();
    }

    [Fact]
    public async Task CreateSignerAsync_rejects_a_downloaded_private_key_whose_type_differs_from_the_published_one()
    {
        // The published Cer reports RSA; the linked secret hands back an EC key — the sharpest
        // possible secret substitution, and the mismatch arm no comparison branch covers.
        var ct = TestContext.Current.CancellationToken;
        var reader = new FakeKeyVaultCertificateReader();
        reader.AddRsaVersion("v1", createdOn: T0);
        using var divergedKey = System.Security.Cryptography.ECDsa.Create(System.Security.Cryptography.ECCurve.NamedCurves.nistP256);
        reader.SetMismatchedPrivateKeyMaterial("v1", divergedKey.ExportParameters(includePrivateParameters: true));
        var sut = BuildSource(reader);
        var keySet = await sut.ReadAsync(ct);

        var act = async () => await sut.CreateSignerAsync(keySet.Single().Id, ct);

        (await act.Should().ThrowAsync<ZeeKayDaConfigurationException>())
            .WithMessage("*secret_cer_mismatch*");
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
            .WithMessage("*no_active_key*");
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
    public async Task ReadAsync_throws_and_does_not_memoize_when_the_listing_fails_mid_enumeration()
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
            "the partial two-version read must not have been memoized — the retry sees the full history");
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

    // ── Read-once ────────────────────────────────────────────────────────────────────────────────

    [Fact]
    public async Task ReadAsync_reads_the_vault_exactly_once_and_ignores_versions_rotated_in_afterwards()
    {
        var ct = TestContext.Current.CancellationToken;
        var reader = new FakeKeyVaultCertificateReader();
        reader.AddRsaVersion("v1", createdOn: T0);
        var timeProvider = new FakeTimeProvider(T0);
        var sut = BuildSource(reader);

        var first = await sut.ReadAsync(ct);

        reader.AddRsaVersion("v2", createdOn: T0 + TimeSpan.FromMinutes(1));
        timeProvider.SetUtcNow(T0 + TimeSpan.FromDays(30));
        var second = await sut.ReadAsync(ct);

        second.Should().BeSameAs(first, "read-once is a property of this source, not only of the ring");
        reader.GetCertificateVersionsCallCount.Should().Be(1);
        PublishedIds(second).Should().Equal(["v1"]);
    }

    [Fact]
    public async Task ReadAsync_reads_the_vault_exactly_once_under_concurrent_readers()
    {
        var ct = TestContext.Current.CancellationToken;
        var reader = new FakeKeyVaultCertificateReader();
        reader.AddRsaVersion("v1", createdOn: T0);
        var sut = BuildSource(reader);

        var first = sut.ReadAsync(ct);
        var second = sut.ReadAsync(ct);
        var results = await Task.WhenAll(first, second);

        results[1].Should().BeSameAs(results[0]);
        reader.GetCertificateVersionsCallCount.Should().Be(1);
    }
}
