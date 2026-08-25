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
/// add is the bundled-format least-privilege obligation: a store entry always carries its private
/// key, so "a published-only slot's private key is never opened" has to be proven rather than being
/// unrepresentable the way it is for a certificate-only PEM file.
/// </summary>
/// <remarks>
/// The source reads its three slots exactly once and never re-reads them, so there is no reload or
/// change-detection surface here — a rotated-in, removed, or replaced certificate is never picked up
/// without a restart. Which key signs is decided entirely by which slot it is configured in, never
/// by the clock, so this type holds no <c>TimeProvider</c>: the one clock check that remains, on the
/// signing key's own validity window, belongs to <c>StaticSigningKeyRing</c> and is tested there.
/// The source depends only on <see cref="ICertificateStoreReader"/>, so these tests run on any OS,
/// unlike <c>Integration/WindowsCertificateStoreSigningIntegrationTests</c>.
/// </remarks>
public sealed class WindowsCertificateStoreSigningKeySourceTests
{
    private static readonly DateTimeOffset T0 = DateTimeOffset.Parse("2026-01-01T00:00:00Z");
    private const string PreviousThumbprint = "1111111111111111111111111111111111111A";
    private const string CurrentThumbprint = "AABBCCDDEEFF00112233445566778899AABBCCD";
    private const string NextThumbprint = "2222222222222222222222222222222222222B";

    private static WindowsCertificateStoreSigningKeySource BuildSource(
        FakeCertificateStoreReader reader,
        string? current = CurrentThumbprint,
        string? previous = null,
        string? next = null,
        SigningAlgorithm algorithm = SigningAlgorithm.RS256,
        ICertificateKeyExtractor? keyExtractor = null)
    {
        var options = new WindowsCertificateStoreSigningOptions
        {
            Previous = previous is null ? null : CertificateLookup.ByThumbprint(previous),
            Current = current is null ? null : CertificateLookup.ByThumbprint(current),
            Next = next is null ? null : CertificateLookup.ByThumbprint(next),
            Algorithm = algorithm,
            StoreLocation = StoreLocation.CurrentUser,
            StoreName = StoreName.My,
        };

        return new WindowsCertificateStoreSigningKeySource(
            Options.Create(options), reader, keyExtractor ?? new FakeCertificateKeyExtractor());
    }

    private static X509Certificate2 CreateRsaCertificate(bool withPrivateKey = true) =>
        TestCertificateFactory.CreateRsaSelfSigned(
            "test", T0 - TimeSpan.FromDays(1), T0 + TimeSpan.FromDays(365), withPrivateKey: withPrivateKey);

    // ── Happy path ───────────────────────────────────────────────────────────────────────────────

    [Fact]
    public async Task ReadAsync_reports_the_Current_certificates_public_key_as_the_signing_key()
    {
        var ct = TestContext.Current.CancellationToken;
        var reader = new FakeCertificateStoreReader();
        using var certificate = CreateRsaCertificate();
        reader.AddCertificate(CurrentThumbprint, certificate);
        var sut = BuildSource(reader);

        var keySet = await sut.ReadAsync(ct);

        keySet.Keys.Should().ContainSingle();
        keySet.SigningKey.Id.Should().Be(new SourceKeyId(CurrentThumbprint));
        keySet.SigningKey.Algorithm.Should().Be(SigningAlgorithm.RS256);
        keySet.SigningKey.PublicKey.KeyType.Should().Be(SigningKeyType.Rsa);
        keySet.SigningKey.PublicKey.RsaPublicParameters.Should().NotBeNull(
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

        keySet.SigningKey.NotBefore.Should().Be(new DateTimeOffset(certificate.NotBefore));
        keySet.SigningKey.ExpiresAt.Should().Be(new DateTimeOffset(certificate.NotAfter));
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

        using var signer = await sut.CreateSignerAsync(keySet.SigningKey.Id, ct);
        var signingInput = "header.payload"u8.ToArray();
        var signature = await signer.SignAsync(signingInput, ct);

        signer.Algorithm.Should().Be(SigningAlgorithm.RS256);
        using var rsa = RSA.Create(keySet.SigningKey.PublicKey.RsaPublicParameters!.Value);
        rsa.VerifyData(signingInput, signature.Span, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1)
            .Should().BeTrue("the signer must be opened over the same key pair the read reported");
    }

    // ── The three slots ──────────────────────────────────────────────────────────────────────────

    [Fact]
    public async Task ReadAsync_publishes_every_configured_slot_and_signs_with_Current()
    {
        var ct = TestContext.Current.CancellationToken;
        var reader = new FakeCertificateStoreReader();
        using var previousCertificate = CreateRsaCertificate();
        using var currentCertificate = CreateRsaCertificate();
        using var nextCertificate = CreateRsaCertificate();
        reader.AddCertificate(PreviousThumbprint, previousCertificate);
        reader.AddCertificate(CurrentThumbprint, currentCertificate);
        reader.AddCertificate(NextThumbprint, nextCertificate);
        var sut = BuildSource(reader, previous: PreviousThumbprint, next: NextThumbprint);

        var keySet = await sut.ReadAsync(ct);

        keySet.Keys.Should().HaveCount(3);
        keySet.SigningKey.Id.Should().Be(new SourceKeyId(CurrentThumbprint));
        keySet.Keys.Select(k => k.Id.Value).Should()
            .BeEquivalentTo([CurrentThumbprint, PreviousThumbprint, NextThumbprint]);
    }

    [Fact]
    public async Task ReadAsync_throws_when_no_Current_slot_is_configured()
    {
        var ct = TestContext.Current.CancellationToken;
        var reader = new FakeCertificateStoreReader();
        using var certificate = CreateRsaCertificate();
        reader.AddCertificate(NextThumbprint, certificate);
        var sut = BuildSource(reader, current: null, next: NextThumbprint);

        var act = async () => await sut.ReadAsync(ct);

        (await act.Should().ThrowAsync<ZeeKayDaConfigurationException>())
            .Which.AggregatedFailures.Should().ContainSingle(f => f.Code == "signing.no_current_key");
    }

    [Fact]
    public async Task ReadAsync_never_opens_private_material_for_Previous_or_Next()
    {
        // Unlike a certificate-only PEM file, a store entry always carries its private key, so this
        // has to be proven rather than being unrepresentable: only Current may ever reach
        // ExtractPrivateKey, and only from CreateSignerAsync.
        var ct = TestContext.Current.CancellationToken;
        var reader = new FakeCertificateStoreReader();
        var keyExtractor = new FakeCertificateKeyExtractor();
        using var previousCertificate = CreateRsaCertificate();
        using var currentCertificate = CreateRsaCertificate();
        using var nextCertificate = CreateRsaCertificate();
        reader.AddCertificate(PreviousThumbprint, previousCertificate);
        reader.AddCertificate(CurrentThumbprint, currentCertificate);
        reader.AddCertificate(NextThumbprint, nextCertificate);
        var sut = BuildSource(reader, previous: PreviousThumbprint, next: NextThumbprint, keyExtractor: keyExtractor);

        await sut.ReadAsync(ct);

        keyExtractor.PrivateKeyExtractions.Should().BeEmpty("a read publishes public material only");
        keyExtractor.PublicKeyExtractions.Should()
            .BeEquivalentTo([PreviousThumbprint, CurrentThumbprint, NextThumbprint]);
    }

    [Fact]
    public async Task CreateSignerAsync_opens_the_private_key_of_Current_alone()
    {
        var ct = TestContext.Current.CancellationToken;
        var reader = new FakeCertificateStoreReader();
        var keyExtractor = new FakeCertificateKeyExtractor();
        using var previousCertificate = CreateRsaCertificate();
        using var currentCertificate = CreateRsaCertificate();
        reader.AddCertificate(PreviousThumbprint, previousCertificate);
        reader.AddCertificate(CurrentThumbprint, currentCertificate);
        var sut = BuildSource(reader, previous: PreviousThumbprint, keyExtractor: keyExtractor);
        var keySet = await sut.ReadAsync(ct);

        using var signer = await sut.CreateSignerAsync(keySet.SigningKey.Id, ct);

        signer.Should().NotBeNull();
        keyExtractor.PrivateKeyExtractions.Should().Equal([CurrentThumbprint]);
    }

    // ── Read-once ────────────────────────────────────────────────────────────────────────────────

    [Fact]
    public async Task ReadAsync_returns_the_same_key_set_after_the_Current_certificate_is_removed_from_the_store()
    {
        var ct = TestContext.Current.CancellationToken;
        var reader = new FakeCertificateStoreReader();
        using var certificate = CreateRsaCertificate();
        reader.AddCertificate(CurrentThumbprint, certificate);
        var sut = BuildSource(reader);

        var first = await sut.ReadAsync(ct);
        reader.RemoveCertificate(CurrentThumbprint);
        var second = await sut.ReadAsync(ct);

        second.Should().BeSameAs(first, "the source reads its slots exactly once and never re-reads them");
    }

    [Fact]
    public async Task ReadAsync_returns_the_same_key_set_after_a_configured_certificate_is_replaced_in_the_store()
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

        second.SigningKey.PublicKey.RsaPublicParameters!.Value.Modulus
            .Should().BeEquivalentTo(first.SigningKey.PublicKey.RsaPublicParameters!.Value.Modulus);
    }

    [Fact]
    public async Task ReadAsync_reads_each_configured_slot_from_the_store_exactly_once_however_often_it_is_called()
    {
        var ct = TestContext.Current.CancellationToken;
        var reader = new FakeCertificateStoreReader();
        using var previousCertificate = CreateRsaCertificate();
        using var currentCertificate = CreateRsaCertificate();
        reader.AddCertificate(PreviousThumbprint, previousCertificate);
        reader.AddCertificate(CurrentThumbprint, currentCertificate);
        var sut = BuildSource(reader, previous: PreviousThumbprint);

        await sut.ReadAsync(ct);
        await sut.ReadAsync(ct);
        await sut.ReadAsync(ct);

        reader.Calls.Should().Equal([PreviousThumbprint, CurrentThumbprint]);
    }

    [Fact]
    public async Task A_published_only_slots_store_entry_is_never_reopened_after_the_read()
    {
        // The bundled-format least-privilege obligation: Previous is read once, transiently, for its
        // public half, and signing reopens only Current.
        var ct = TestContext.Current.CancellationToken;
        var reader = new FakeCertificateStoreReader();
        using var previousCertificate = CreateRsaCertificate();
        using var currentCertificate = CreateRsaCertificate();
        reader.AddCertificate(PreviousThumbprint, previousCertificate);
        reader.AddCertificate(CurrentThumbprint, currentCertificate);
        var sut = BuildSource(reader, previous: PreviousThumbprint);
        var keySet = await sut.ReadAsync(ct);

        using var signer = await sut.CreateSignerAsync(keySet.SigningKey.Id, ct);

        signer.Should().NotBeNull();
        reader.Calls.Should().Equal([PreviousThumbprint, CurrentThumbprint, CurrentThumbprint]);
        reader.Calls.Count(thumbprint => thumbprint == PreviousThumbprint).Should().Be(1);
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
    public async Task ReadAsync_succeeds_for_a_certificate_with_no_private_key()
    {
        // A read only ever needs public material, so a certificate installed without its private key
        // still publishes. The failure belongs at the point signing is attempted, not before.
        var ct = TestContext.Current.CancellationToken;
        var reader = new FakeCertificateStoreReader();
        using var certificate = CreateRsaCertificate(withPrivateKey: false);
        reader.AddCertificate(CurrentThumbprint, certificate);
        var sut = BuildSource(reader);

        var keySet = await sut.ReadAsync(ct);

        keySet.SigningKey.PublicKey.RsaPublicParameters.Should().NotBeNull();
    }

    [Fact]
    public async Task CreateSignerAsync_throws_when_the_Current_certificate_has_no_private_key()
    {
        var ct = TestContext.Current.CancellationToken;
        var reader = new FakeCertificateStoreReader();
        using var certificate = CreateRsaCertificate(withPrivateKey: false);
        reader.AddCertificate(CurrentThumbprint, certificate);
        var sut = BuildSource(reader);
        var keySet = await sut.ReadAsync(ct);

        var act = async () => await sut.CreateSignerAsync(keySet.SigningKey.Id, ct);

        (await act.Should().ThrowAsync<ZeeKayDaConfigurationException>())
            .Which.AggregatedFailures.Should()
            .ContainSingle(f => f.Code == "signing.windows_certificate_store.private_key_not_found");
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

        keySet.SigningKey.PublicKey.KeyType.Should().Be(SigningKeyType.Ec);
        keySet.SigningKey.Algorithm.Should().Be(SigningAlgorithm.ES256);
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

        using var signer = await sut.CreateSignerAsync(keySet.SigningKey.Id, ct);
        var signingInput = "header.payload"u8.ToArray();
        var signature = await signer.SignAsync(signingInput, ct);

        using var ecdsa = ECDsa.Create(keySet.SigningKey.PublicKey.EcPublicParameters!.Value);
        ecdsa.VerifyData(signingInput, signature.Span, HashAlgorithmName.SHA256)
            .Should().BeTrue("the signer must be opened over the same key pair the read reported");
    }

    // ── Algorithm/key-type mismatch is the key set builder's call, not this source's ─────────────

    [Fact]
    public async Task ReadAsync_reports_a_mismatched_algorithm_verbatim_and_leaves_the_rejection_to_the_key_set_builder()
    {
        // The provider's own algorithm/key-type check is deliberately gone: SigningKeySetBuilder
        // rejects the same mismatch centrally, plus EC curve pairing the local check never covered,
        // keyed on the source id — the thumbprint — so its failure still names the certificate.
        var ct = TestContext.Current.CancellationToken;
        var reader = new FakeCertificateStoreReader();
        using var certificate = CreateRsaCertificate();
        reader.AddCertificate(CurrentThumbprint, certificate);
        var sut = BuildSource(reader, algorithm: SigningAlgorithm.ES256);

        var keySet = await sut.ReadAsync(ct);

        keySet.SigningKey.Algorithm.Should().Be(SigningAlgorithm.ES256, "the source reports what it was configured with");
        keySet.SigningKey.PublicKey.KeyType.Should().Be(SigningKeyType.Rsa, "and the key type it actually found");
    }

    // ── Defensive invariant: only Current is ever openable for signing ───────────────────────────

    [Fact]
    public async Task CreateSignerAsync_throws_when_called_for_a_key_id_that_is_not_configured_at_all()
    {
        var ct = TestContext.Current.CancellationToken;
        var reader = new FakeCertificateStoreReader();
        using var certificate = CreateRsaCertificate();
        reader.AddCertificate(CurrentThumbprint, certificate);
        var sut = BuildSource(reader);

        var act = async () => await sut.CreateSignerAsync(new SourceKeyId("DEADBEEF"), ct);

        (await act.Should().ThrowAsync<InvalidOperationException>())
            .WithMessage("*DEADBEEF*not the configured Current certificate*");
    }

    [Fact]
    public async Task CreateSignerAsync_throws_when_called_for_the_Previous_slot()
    {
        var ct = TestContext.Current.CancellationToken;
        var reader = new FakeCertificateStoreReader();
        var keyExtractor = new FakeCertificateKeyExtractor();
        using var previousCertificate = CreateRsaCertificate();
        using var currentCertificate = CreateRsaCertificate();
        reader.AddCertificate(PreviousThumbprint, previousCertificate);
        reader.AddCertificate(CurrentThumbprint, currentCertificate);
        var sut = BuildSource(reader, previous: PreviousThumbprint, keyExtractor: keyExtractor);
        await sut.ReadAsync(ct);

        var act = async () => await sut.CreateSignerAsync(new SourceKeyId(PreviousThumbprint), ct);

        await act.Should().ThrowAsync<InvalidOperationException>();
        keyExtractor.PrivateKeyExtractions.Should().BeEmpty(
            "a rejected request must not have opened the private key it was refused");
    }

    [Fact]
    public async Task CreateSignerAsync_throws_when_called_for_the_Next_slot()
    {
        var ct = TestContext.Current.CancellationToken;
        var reader = new FakeCertificateStoreReader();
        var keyExtractor = new FakeCertificateKeyExtractor();
        using var currentCertificate = CreateRsaCertificate();
        using var nextCertificate = CreateRsaCertificate();
        reader.AddCertificate(CurrentThumbprint, currentCertificate);
        reader.AddCertificate(NextThumbprint, nextCertificate);
        var sut = BuildSource(reader, next: NextThumbprint, keyExtractor: keyExtractor);
        await sut.ReadAsync(ct);

        var act = async () => await sut.CreateSignerAsync(new SourceKeyId(NextThumbprint), ct);

        await act.Should().ThrowAsync<InvalidOperationException>();
        keyExtractor.PrivateKeyExtractions.Should().BeEmpty(
            "a rejected request must not have opened the private key it was refused");
    }
}
