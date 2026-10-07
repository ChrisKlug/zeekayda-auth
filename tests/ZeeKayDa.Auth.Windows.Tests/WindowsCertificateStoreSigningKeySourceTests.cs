using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Microsoft.Extensions.Options;
using ZeeKayDa.Auth.Tokens;
using ZeeKayDa.Auth.Windows.Tests.Fakes;
using ZeeKayDa.Auth.Windows.Tests.Fixtures;

namespace ZeeKayDa.Auth.Windows.Tests;

/// <summary>
/// Direct-construction tests for <see cref="WindowsCertificateStoreSigningKeySource"/>, bypassing DI
/// and the <c>AddWindowsCertificateStoreSigning</c> extension methods entirely, and mirroring
/// <c>PemFileSigningKeySourceTests</c>'s shape. The Windows Certificate Store-specific concern they
/// add is the access-path obligation: a store entry always carries its private key, so "listing a
/// certificate never opens its private key" has to be proven rather than being unrepresentable the
/// way it is for a certificate-only PEM file.
/// </summary>
/// <remarks>
/// The source holds no cache and no lock: every <c>ReadAsync</c> re-reads the store, so a removed or
/// replaced certificate is observed on the next read. Which key signs is decided by the core from
/// each listed key's validity window, never by this source, so it holds no <c>TimeProvider</c>.
/// The source depends only on <see cref="ICertificateStoreReader"/>, so these tests run on any OS,
/// unlike <c>Integration/WindowsCertificateStoreSigningIntegrationTests</c>.
/// </remarks>
public sealed class WindowsCertificateStoreSigningKeySourceTests
{
    private static readonly DateTimeOffset T0 = DateTimeOffset.Parse("2026-01-01T00:00:00Z");
    private const string OtherThumbprint = "1111111111111111111111111111111111111A";
    private const string CurrentThumbprint = "AABBCCDDEEFF00112233445566778899AABBCCD";
    private const string NextThumbprint = "2222222222222222222222222222222222222B";

    private static WindowsCertificateStoreSigningKeySource BuildSource(
        FakeCertificateStoreReader reader,
        string[]? thumbprints = null,
        SigningAlgorithm algorithm = SigningAlgorithm.RS256,
        ICertificateKeyExtractor? keyExtractor = null)
    {
        var options = new WindowsCertificateStoreSigningOptions
        {
            Algorithm = algorithm,
            StoreLocation = StoreLocation.CurrentUser,
            StoreName = StoreName.My,
        };
        foreach (var thumbprint in thumbprints ?? [CurrentThumbprint])
            options.Certificates.Add(CertificateLookup.ByThumbprint(thumbprint));

        return new WindowsCertificateStoreSigningKeySource(
            Options.Create(options), reader, keyExtractor ?? new FakeCertificateKeyExtractor());
    }

    private static X509Certificate2 CreateRsaCertificate(bool withPrivateKey = true) =>
        TestCertificateFactory.CreateRsaSelfSigned(
            "test", T0 - TimeSpan.FromDays(1), T0 + TimeSpan.FromDays(365), withPrivateKey: withPrivateKey);

    // ── Happy path ───────────────────────────────────────────────────────────────────────────────

    [Fact]
    public async Task ReadAsync_reports_the_listed_certificates_public_key()
    {
        var ct = TestContext.Current.CancellationToken;
        var reader = new FakeCertificateStoreReader();
        using var certificate = CreateRsaCertificate();
        reader.AddCertificate(CurrentThumbprint, certificate);
        var sut = BuildSource(reader);

        var keySet = await sut.ReadAsync(ct);

        keySet.Should().ContainSingle();
        keySet.Single().Id.Should().Be(new SourceKeyId(CurrentThumbprint));
        keySet.Single().Algorithm.Should().Be(SigningAlgorithm.RS256);
        keySet.Single().PublicKey.KeyType.Should().Be(SigningKeyType.Rsa);
        keySet.Single().PublicKey.RsaPublicParameters.Should().NotBeNull(
            "only public material may ever leave this source's read path");
    }

    [Fact]
    public async Task ReadAsync_reports_the_certificates_validity_window_on_both_ends()
    {
        var ct = TestContext.Current.CancellationToken;
        var reader = new FakeCertificateStoreReader();
        using var certificate = CreateRsaCertificate();
        reader.AddCertificate(CurrentThumbprint, certificate);
        var sut = BuildSource(reader);

        var keySet = await sut.ReadAsync(ct);

        keySet.Single().NotBefore.Should().Be(new DateTimeOffset(certificate.NotBefore));
        keySet.Single().ExpiresAt.Should().Be(new DateTimeOffset(certificate.NotAfter));
    }

    [Fact]
    public async Task CreateSignerAsync_returns_a_signer_whose_signature_verifies_against_the_reported_public_key()
    {
        var ct = TestContext.Current.CancellationToken;
        var reader = new FakeCertificateStoreReader();
        using var certificate = CreateRsaCertificate();
        reader.AddCertificate(CurrentThumbprint, certificate);
        var sut = BuildSource(reader);
        var keySet = await sut.ReadAsync(ct);

        using var signer = await sut.CreateSignerAsync(keySet.Single().Id, ct);
        var signingInput = "header.payload"u8.ToArray();
        var signature = await signer.SignAsync(signingInput, ct);

        using var rsa = RSA.Create(keySet.Single().PublicKey.RsaPublicParameters!.Value);
        rsa.VerifyData(signingInput, signature.Span, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1)
            .Should().BeTrue("the signer must be opened over the same key pair the read reported");
    }

    // ── Several listed certificates ──────────────────────────────────────────────────────────────

    [Fact]
    public async Task ReadAsync_lists_every_configured_certificate()
    {
        var ct = TestContext.Current.CancellationToken;
        var reader = new FakeCertificateStoreReader();
        using var firstCertificate = CreateRsaCertificate();
        using var secondCertificate = CreateRsaCertificate();
        using var thirdCertificate = CreateRsaCertificate();
        reader.AddCertificate(OtherThumbprint, firstCertificate);
        reader.AddCertificate(CurrentThumbprint, secondCertificate);
        reader.AddCertificate(NextThumbprint, thirdCertificate);
        var sut = BuildSource(reader, [OtherThumbprint, CurrentThumbprint, NextThumbprint]);

        var keySet = await sut.ReadAsync(ct);

        keySet.Select(k => k.Id.Value).Should()
            .BeEquivalentTo([CurrentThumbprint, OtherThumbprint, NextThumbprint]);
    }

    [Fact]
    public async Task ReadAsync_extracts_no_private_key_handle_for_any_certificate()
    {
        // The access-path guarantee, which is the honest one for this provider. Opening a store entry
        // hands back the private-key association whatever the caller wants, so "a listed
        // certificate's private key never materializes" is not something this source can promise the
        // way the PEM provider's certificate-only files can. What it can promise, and what this pins,
        // is that no read path asks the extractor for a private key at all.
        var ct = TestContext.Current.CancellationToken;
        var reader = new FakeCertificateStoreReader();
        var keyExtractor = new FakeCertificateKeyExtractor();
        using var firstCertificate = CreateRsaCertificate();
        using var secondCertificate = CreateRsaCertificate();
        reader.AddCertificate(OtherThumbprint, firstCertificate);
        reader.AddCertificate(CurrentThumbprint, secondCertificate);
        var sut = BuildSource(reader, [OtherThumbprint, CurrentThumbprint], keyExtractor: keyExtractor);

        await sut.ReadAsync(ct);

        keyExtractor.PrivateKeyExtractions.Should().BeEmpty("a read publishes public material only, for every certificate");
    }

    [Fact]
    public async Task CreateSignerAsync_extracts_the_private_key_of_the_requested_certificate_alone()
    {
        var ct = TestContext.Current.CancellationToken;
        var reader = new FakeCertificateStoreReader();
        var keyExtractor = new FakeCertificateKeyExtractor();
        using var firstCertificate = CreateRsaCertificate();
        using var secondCertificate = CreateRsaCertificate();
        reader.AddCertificate(OtherThumbprint, firstCertificate);
        reader.AddCertificate(CurrentThumbprint, secondCertificate);
        var sut = BuildSource(reader, [OtherThumbprint, CurrentThumbprint], keyExtractor: keyExtractor);
        await sut.ReadAsync(ct);

        using var signer = await sut.CreateSignerAsync(new SourceKeyId(CurrentThumbprint), ct);

        signer.Should().NotBeNull();
        keyExtractor.PrivateKeyExtractions.Should().Equal([CurrentThumbprint]);
    }

    // ── Every read hits the store ────────────────────────────────────────────────────────────────

    [Fact]
    public async Task ReadAsync_throws_after_a_listed_certificate_is_removed_from_the_store()
    {
        var ct = TestContext.Current.CancellationToken;
        var reader = new FakeCertificateStoreReader();
        using var certificate = CreateRsaCertificate();
        reader.AddCertificate(CurrentThumbprint, certificate);
        var sut = BuildSource(reader);
        await sut.ReadAsync(ct);
        reader.RemoveCertificate(CurrentThumbprint);

        var act = async () => await sut.ReadAsync(ct);

        (await act.Should().ThrowAsync<ZeeKayDaConfigurationException>())
            .Which.AggregatedFailures.Should()
            .ContainSingle(f => f.Code == "signing.windows_certificate_store.certificate_not_found");
    }

    [Fact]
    public async Task ReadAsync_observes_a_replaced_certificate_on_the_next_read()
    {
        var ct = TestContext.Current.CancellationToken;
        var reader = new FakeCertificateStoreReader();
        using var certificate = CreateRsaCertificate();
        using var replacement = CreateRsaCertificate();
        reader.AddCertificate(CurrentThumbprint, certificate);
        var sut = BuildSource(reader);

        var first = await sut.ReadAsync(ct);
        reader.AddCertificate(CurrentThumbprint, replacement);
        var second = await sut.ReadAsync(ct);

        second.Single().PublicKey.RsaPublicParameters!.Value.Modulus
            .Should().Equal(replacement.GetRSAPublicKey()!.ExportParameters(false).Modulus)
            .And.NotEqual(first.Single().PublicKey.RsaPublicParameters!.Value.Modulus);
    }

    [Fact]
    public async Task ReadAsync_reads_each_listed_certificate_from_the_store_on_every_call()
    {
        var ct = TestContext.Current.CancellationToken;
        var reader = new FakeCertificateStoreReader();
        using var firstCertificate = CreateRsaCertificate();
        using var secondCertificate = CreateRsaCertificate();
        reader.AddCertificate(OtherThumbprint, firstCertificate);
        reader.AddCertificate(CurrentThumbprint, secondCertificate);
        var sut = BuildSource(reader, [OtherThumbprint, CurrentThumbprint]);

        await sut.ReadAsync(ct);
        await sut.ReadAsync(ct);

        reader.Calls.Should().Equal([OtherThumbprint, CurrentThumbprint, OtherThumbprint, CurrentThumbprint]);
    }

    [Fact]
    public async Task ReadAsync_recovers_on_retry_after_a_failed_read()
    {
        // Nothing is remembered between reads: a process that hit a transient store failure is not
        // stuck on it, and the next read observes the store as it then is.
        var ct = TestContext.Current.CancellationToken;
        var reader = new FakeCertificateStoreReader();
        using var certificate = CreateRsaCertificate();
        var sut = BuildSource(reader);

        var failing = async () => await sut.ReadAsync(ct);
        await failing.Should().ThrowAsync<ZeeKayDaConfigurationException>("no certificate is in the store yet");

        reader.AddCertificate(CurrentThumbprint, certificate);
        var keySet = await sut.ReadAsync(ct);

        keySet.Single().Id.Should().Be(new SourceKeyId(CurrentThumbprint));
    }

    // ── Missing certificate and missing private key ──────────────────────────────────────────────

    [Fact]
    public async Task ReadAsync_throws_ZeeKayDaConfigurationException_when_the_certificate_is_not_found()
    {
        var ct = TestContext.Current.CancellationToken;
        var reader = new FakeCertificateStoreReader();
        var sut = BuildSource(reader);

        var act = async () => await sut.ReadAsync(ct);

        (await act.Should().ThrowAsync<ZeeKayDaConfigurationException>())
            .Which.AggregatedFailures.Should()
            .ContainSingle(f => f.Code == "signing.windows_certificate_store.certificate_not_found");
    }

    [Fact]
    public async Task ReadAsync_rejects_a_listed_certificate_with_no_private_key_without_extracting_one()
    {
        // Any listed certificate may be chosen to sign, so one installed without its private key fails
        // at the read rather than at the restart that chooses it. No handle is extracted to find out.
        var ct = TestContext.Current.CancellationToken;
        var reader = new FakeCertificateStoreReader();
        using var certificate = CreateRsaCertificate(withPrivateKey: false);
        reader.AddCertificate(CurrentThumbprint, certificate);
        var extractor = new FakeCertificateKeyExtractor();
        var sut = BuildSource(reader, keyExtractor: extractor);

        var act = async () => await sut.ReadAsync(ct);

        (await act.Should().ThrowAsync<ZeeKayDaConfigurationException>())
            .Which.AggregatedFailures.Should()
            .ContainSingle(f => f.Code == "signing.windows_certificate_store.private_key_not_found");
        extractor.PrivateKeyExtractions.Should().BeEmpty();
    }

    // ── EC certificates ──────────────────────────────────────────────────────────────────────────

    [Fact]
    public async Task ReadAsync_supports_EC_certificates_with_a_matching_EC_algorithm()
    {
        var ct = TestContext.Current.CancellationToken;
        var reader = new FakeCertificateStoreReader();
        using var certificate = TestCertificateFactory.CreateEcSelfSigned(
            "test", T0 - TimeSpan.FromDays(1), T0 + TimeSpan.FromDays(365));
        reader.AddCertificate(CurrentThumbprint, certificate);
        var sut = BuildSource(reader, algorithm: SigningAlgorithm.ES256);

        var keySet = await sut.ReadAsync(ct);

        keySet.Single().PublicKey.KeyType.Should().Be(SigningKeyType.Ec);
        keySet.Single().Algorithm.Should().Be(SigningAlgorithm.ES256);
    }

    [Fact]
    public async Task CreateSignerAsync_signs_with_an_EC_certificates_private_key()
    {
        var ct = TestContext.Current.CancellationToken;
        var reader = new FakeCertificateStoreReader();
        using var certificate = TestCertificateFactory.CreateEcSelfSigned(
            "test", T0 - TimeSpan.FromDays(1), T0 + TimeSpan.FromDays(365));
        reader.AddCertificate(CurrentThumbprint, certificate);
        var sut = BuildSource(reader, algorithm: SigningAlgorithm.ES256);
        var keySet = await sut.ReadAsync(ct);

        using var signer = await sut.CreateSignerAsync(keySet.Single().Id, ct);
        var signingInput = "header.payload"u8.ToArray();
        var signature = await signer.SignAsync(signingInput, ct);

        using var ecdsa = ECDsa.Create(keySet.Single().PublicKey.EcPublicParameters!.Value);
        ecdsa.VerifyData(signingInput, signature.Span, HashAlgorithmName.SHA256)
            .Should().BeTrue("the signer must be opened over the same key pair the read reported");
    }

    // ── Algorithm/key-type mismatch is the key set builder's call, not this source's ─────────────

    [Fact]
    public async Task ReadAsync_rejects_a_certificate_whose_key_does_not_suit_the_algorithm_naming_its_thumbprint()
    {
        var ct = TestContext.Current.CancellationToken;
        var reader = new FakeCertificateStoreReader();
        using var certificate = CreateRsaCertificate();
        reader.AddCertificate(CurrentThumbprint, certificate);
        var sut = BuildSource(reader, algorithm: SigningAlgorithm.ES256);

        var act = async () => await sut.ReadAsync(ct);

        var exception = await act.Should().ThrowAsync<ZeeKayDaConfigurationException>();
        exception.Which.AggregatedFailures.Should().ContainSingle(f => f.Code == "signing.key_algorithm_mismatch");
        exception.Which.Message.Should().Contain(CurrentThumbprint);
    }

    // ── CreateSignerAsync opens any listed certificate, and only a listed one ────────────────────

    [Fact]
    public async Task CreateSignerAsync_throws_when_called_for_a_key_id_that_is_not_listed()
    {
        var ct = TestContext.Current.CancellationToken;
        var reader = new FakeCertificateStoreReader();
        using var certificate = CreateRsaCertificate();
        reader.AddCertificate(CurrentThumbprint, certificate);
        var sut = BuildSource(reader);

        var act = async () => await sut.CreateSignerAsync(new SourceKeyId("DEADBEEF"), ct);

        (await act.Should().ThrowAsync<InvalidOperationException>())
            .WithMessage("*DEADBEEF*not a listed certificate*");
    }

    [Fact]
    public async Task CreateSignerAsync_throws_for_a_certificate_that_is_in_the_store_but_not_listed()
    {
        var ct = TestContext.Current.CancellationToken;
        var reader = new FakeCertificateStoreReader();
        var keyExtractor = new FakeCertificateKeyExtractor();
        using var listedCertificate = CreateRsaCertificate();
        using var unlistedCertificate = CreateRsaCertificate();
        reader.AddCertificate(CurrentThumbprint, listedCertificate);
        reader.AddCertificate(OtherThumbprint, unlistedCertificate);
        var sut = BuildSource(reader, [CurrentThumbprint], keyExtractor: keyExtractor);

        var act = async () => await sut.CreateSignerAsync(new SourceKeyId(OtherThumbprint), ct);

        await act.Should().ThrowAsync<InvalidOperationException>();
        keyExtractor.PrivateKeyExtractions.Should().BeEmpty(
            "a rejected request must not have opened the private key it was refused");
    }

    [Fact]
    public async Task CreateSignerAsync_opens_a_signer_for_any_listed_certificate()
    {
        var ct = TestContext.Current.CancellationToken;
        var reader = new FakeCertificateStoreReader();
        using var firstCertificate = CreateRsaCertificate();
        using var secondCertificate = CreateRsaCertificate();
        reader.AddCertificate(OtherThumbprint, firstCertificate);
        reader.AddCertificate(CurrentThumbprint, secondCertificate);
        var sut = BuildSource(reader, [CurrentThumbprint, OtherThumbprint]);
        var signingInput = "header.payload"u8.ToArray();

        using var signer = await sut.CreateSignerAsync(new SourceKeyId(OtherThumbprint), ct);
        var signature = await signer.SignAsync(signingInput, ct);

        firstCertificate.GetRSAPublicKey()!
            .VerifyData(signingInput, signature.Span, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1)
            .Should().BeTrue("the signer must be opened over the certificate that was asked for, not the first listed");
    }
}
