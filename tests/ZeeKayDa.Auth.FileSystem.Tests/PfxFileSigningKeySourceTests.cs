using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Microsoft.Extensions.Options;
using ZeeKayDa.Auth.FileSystem.Tests.Fixtures;
using ZeeKayDa.Auth.Tokens;

namespace ZeeKayDa.Auth.FileSystem.Tests;

/// <summary>
/// Direct-construction tests for <see cref="PfxFileSigningKeySource"/>, bypassing DI and the
/// <c>AddPfxFileSigning</c> extension methods entirely. A fake reader is never substituted: this
/// source's whole job is real filesystem interaction (permission enforcement, symlink detection),
/// so every test below exercises the real <see cref="FileSigningKeyReader"/> against real temporary
/// bundles.
/// </summary>
/// <remarks>
/// The source holds no cache and no lock: every <c>ReadAsync</c> re-reads the bundles from disk, so a
/// replaced or deleted file is observed on the next read. Which key signs is decided by the core from
/// each listed key's validity window, never by this source, so it holds no <c>TimeProvider</c>.
/// </remarks>
public sealed class PfxFileSigningKeySourceTests
{
    private static readonly DateTimeOffset T0 = DateTimeOffset.Parse("2026-01-01T00:00:00Z");
    private const string CorrectPassword = "correct horse battery staple";

    private static Func<CancellationToken, Task<string>> Password(string password = CorrectPassword) =>
        _ => Task.FromResult(password);

    private static PfxFileSigningKeySource BuildSource(
        PfxFile file,
        SigningAlgorithm algorithm = SigningAlgorithm.RS256) =>
        BuildSource([file], algorithm);

    private static PfxFileSigningKeySource BuildSource(
        IEnumerable<PfxFile> files,
        SigningAlgorithm algorithm = SigningAlgorithm.RS256)
    {
        var options = new PfxFileSigningOptions();
        foreach (var file in files)
            options.Files.Add(file);

        options.Algorithm = algorithm;

        return new PfxFileSigningKeySource(
            Options.Create(options),
            new FileSigningKeyReader(NullSanitizingLogger<FileSigningKeyReader>.Instance));
    }

    private static X509Certificate2 CreateRsaCertificate() =>
        TestCertificateFactory.CreateRsaSelfSigned("test", T0 - TimeSpan.FromDays(1), T0 + TimeSpan.FromDays(365));

    // ── Happy path ───────────────────────────────────────────────────────────────────────────────

    [Fact]
    public async Task ReadAsync_reports_the_listed_bundles_public_key()
    {
        var ct = TestContext.Current.CancellationToken;
        using var tempDir = new TempSigningKeyDirectory();
        using var certificate = CreateRsaCertificate();
        var path = tempDir.WritePfxFile("current.pfx", certificate, CorrectPassword);
        var sut = BuildSource(new PfxFile(path, Password()));

        var keySet = await sut.ReadAsync(ct);

        keySet.Should().ContainSingle();
        keySet.Single().Id.Should().Be(new SourceKeyId(path));
        sut.Algorithm.Should().Be(SigningAlgorithm.RS256);
        keySet.Single().PublicKey.KeyType.Should().Be(SigningKeyType.Rsa);
        keySet.Single().PublicKey.RsaPublicParameters.Should().NotBeNull(
            "only public material may ever leave this source's read path");
    }

    [Fact]
    public async Task ReadAsync_reports_the_certificates_validity_window_on_both_ends()
    {
        var ct = TestContext.Current.CancellationToken;
        using var tempDir = new TempSigningKeyDirectory();
        using var certificate = CreateRsaCertificate();
        var path = tempDir.WritePfxFile("current.pfx", certificate, CorrectPassword);
        var sut = BuildSource(new PfxFile(path, Password()));

        var keySet = await sut.ReadAsync(ct);

        keySet.Single().NotBefore.Should().Be(new DateTimeOffset(certificate.NotBefore));
        keySet.Single().ExpiresAt.Should().Be(new DateTimeOffset(certificate.NotAfter));
    }

    [Fact]
    public async Task CreateSignerAsync_returns_a_signer_whose_signature_verifies_against_the_reported_public_key()
    {
        var ct = TestContext.Current.CancellationToken;
        using var tempDir = new TempSigningKeyDirectory();
        using var certificate = CreateRsaCertificate();
        var path = tempDir.WritePfxFile("current.pfx", certificate, CorrectPassword);
        var sut = BuildSource(new PfxFile(path, Password()));
        var keySet = await sut.ReadAsync(ct);

        using var signer = await sut.CreateSignerAsync(keySet.Single().Id, ct);
        var signingInput = "header.payload"u8.ToArray();
        var signature = await signer.SignAsync(signingInput, ct);

        using var rsa = RSA.Create(keySet.Single().PublicKey.RsaPublicParameters!.Value);
        rsa.VerifyData(signingInput, signature.Span, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1)
            .Should().BeTrue("the signer must be opened over the same key pair the read reported");
    }

    // ── The key bag is never decrypted on the read path ──────────────────────────────────────────

    [Fact]
    public async Task ReadAsync_reads_every_bundle_without_ever_producing_a_certificate_that_carries_its_private_key()
    {
        // The read path walks the PKCS#12 structure and takes the certificate bag, leaving the
        // shrouded key bag encrypted. Nothing it produces carries private material, so a listed
        // bundle's private key is only ever materialised when it is chosen to sign.
        var ct = TestContext.Current.CancellationToken;
        using var tempDir = new TempSigningKeyDirectory();
        using var firstCertificate = CreateRsaCertificate();
        using var secondCertificate = CreateRsaCertificate();
        var firstPath = tempDir.WritePfxFile("first.pfx", firstCertificate, "first-password");
        var secondPath = tempDir.WritePfxFile("second.pfx", secondCertificate, CorrectPassword);
        var sut = BuildSource(
            [new PfxFile(firstPath, Password("first-password")), new PfxFile(secondPath, Password())]);

        var keySet = await sut.ReadAsync(ct);

        keySet.Should().HaveCount(2);
        keySet.Should().AllSatisfy(key =>
            key.PublicKey.RsaPublicParameters.Should().NotBeNull("every file yields public material only"));
    }

    [Fact]
    public async Task ReadAsync_lists_a_bundle_whose_key_bag_cannot_be_decrypted_because_it_never_imports_the_key()
    {
        // The key bag is shrouded under a different password from the one configured, so any import
        // of the key fails. The read still succeeds, which it could not if it imported the key; the
        // signer, which does import it, is where the failure surfaces.
        var ct = TestContext.Current.CancellationToken;
        using var tempDir = new TempSigningKeyDirectory();
        var bundle = AdversarialPkcs12Factory.KeyBagUnderAnotherPassword(
            CorrectPassword, "another-password", T0 - TimeSpan.FromDays(1), T0 + TimeSpan.FromDays(365));
        var path = tempDir.WriteBytes("current.pfx", bundle);
        var sut = BuildSource(new PfxFile(path, Password()));

        var keySet = await sut.ReadAsync(ct);

        keySet.Should().ContainSingle();
        var act = async () => await sut.CreateSignerAsync(keySet.Single().Id, ct);
        (await act.Should().ThrowAsync<ZeeKayDaConfigurationException>())
            .Which.AggregatedFailures.Should().ContainSingle(f => f.Code == "signing.file_signing.invalid_pfx");
    }

    [Fact]
    public async Task ReadAsync_rejects_a_bundle_that_carries_no_private_key()
    {
        // The shape `openssl pkcs12 -export -nokeys` produces. Any listed bundle may be chosen to
        // sign, so a keyless one is rejected when it is read rather than when it is first chosen.
        var ct = TestContext.Current.CancellationToken;
        using var tempDir = new TempSigningKeyDirectory();
        using var certificate = CreateRsaCertificate();
        using var publicOnly = X509CertificateLoader.LoadCertificate(certificate.RawData);
        var path = tempDir.WritePfxFile("keyless.pfx", publicOnly, CorrectPassword);
        var sut = BuildSource(new PfxFile(path, Password()));

        var act = async () => await sut.ReadAsync(ct);

        var exception = await act.Should().ThrowAsync<ZeeKayDaConfigurationException>();
        exception.Which.AggregatedFailures.Should().ContainSingle(f => f.Code == "signing.file_signing.invalid_pfx");
        exception.Which.Message.Should().Contain("carries no private key").And.Contain(path);
    }

    // ── Integrity: the password must actually authenticate the bundle ───────────────────────────

    [Fact]
    public async Task ReadAsync_rejects_a_bundle_whose_certificate_safe_is_unencrypted_when_the_password_is_wrong()
    {
        // The exploit this closes: reaching a certificate in an unencrypted safe needs no password,
        // so without a MAC check any substituted bundle is accepted. A bundle that is listed but not
        // the one chosen to sign is never opened by the signer, so the ring's self-test would not catch
        // it either — an attacker's public key would simply appear in the JWKS as a valid verification key.
        var ct = TestContext.Current.CancellationToken;
        using var tempDir = new TempSigningKeyDirectory();
        var bundle = AdversarialPkcs12Factory.UnencryptedCertificateSafe(
            "the-real-password", "attacker", T0 - TimeSpan.FromDays(1), T0 + TimeSpan.FromDays(365));
        var path = tempDir.WriteBytes("current.pfx", bundle);
        var sut = BuildSource(new PfxFile(path, Password("a completely different password")));

        var act = async () => await sut.ReadAsync(ct);

        var exception = await act.Should().ThrowAsync<ZeeKayDaConfigurationException>();
        exception.Which.AggregatedFailures.Should().ContainSingle(f => f.Code == "signing.file_signing.invalid_pfx");
        exception.Which.Message.Should().Contain("integrity check");
    }

    [Fact]
    public async Task ReadAsync_accepts_a_bundle_whose_certificate_safe_is_unencrypted_when_the_password_is_correct()
    {
        var ct = TestContext.Current.CancellationToken;
        using var tempDir = new TempSigningKeyDirectory();
        var bundle = AdversarialPkcs12Factory.UnencryptedCertificateSafe(
            CorrectPassword, "unencrypted-safe", T0 - TimeSpan.FromDays(1), T0 + TimeSpan.FromDays(365));
        var path = tempDir.WriteBytes("current.pfx", bundle);
        var sut = BuildSource(new PfxFile(path, Password()));

        var keySet = await sut.ReadAsync(ct);

        keySet.Single().Id.Should().Be(new SourceKeyId(path));
        keySet.Single().PublicKey.RsaPublicParameters.Should().NotBeNull();
        keySet.Single().NotBefore.Should().BeCloseTo(T0 - TimeSpan.FromDays(1), TimeSpan.FromSeconds(1));
    }

    [Fact]
    public async Task ReadAsync_rejects_a_bundle_with_no_integrity_protection_at_all()
    {
        // Nothing in such a bundle can be authenticated against the configured password, so accepting
        // it would mean the password is not a control on this path.
        var ct = TestContext.Current.CancellationToken;
        using var tempDir = new TempSigningKeyDirectory();
        var bundle = AdversarialPkcs12Factory.NoIntegrityProtection(
            "no-mac", T0 - TimeSpan.FromDays(1), T0 + TimeSpan.FromDays(365));
        var path = tempDir.WriteBytes("current.pfx", bundle);
        var sut = BuildSource(new PfxFile(path, Password()));

        var act = async () => await sut.ReadAsync(ct);

        var exception = await act.Should().ThrowAsync<ZeeKayDaConfigurationException>();
        exception.Which.AggregatedFailures.Should().ContainSingle(f => f.Code == "signing.file_signing.invalid_pfx");
        exception.Which.Message.Should().Contain("integrity mode");
    }

    [Fact]
    public async Task ReadAsync_rejects_a_wrong_password_on_any_listed_bundle_rather_than_deferring_it_to_the_day_it_signs()
    {
        // A listed bundle that is not (yet) the signer would otherwise never have its password
        // exercised. If a wrong one passed startup, the operator would discover it only when that
        // bundle becomes the signing one.
        var ct = TestContext.Current.CancellationToken;
        using var tempDir = new TempSigningKeyDirectory();
        using var currentCertificate = CreateRsaCertificate();
        var currentPath = tempDir.WritePfxFile("current.pfx", currentCertificate, CorrectPassword);
        var nextBundle = AdversarialPkcs12Factory.UnencryptedCertificateSafe(
            "next-real-password", "next", T0 + TimeSpan.FromDays(1), T0 + TimeSpan.FromDays(400));
        var nextPath = tempDir.WriteBytes("next.pfx", nextBundle);
        var sut = BuildSource([new PfxFile(currentPath, Password()), new PfxFile(nextPath, Password("wrong"))]);

        var act = async () => await sut.ReadAsync(ct);

        var exception = await act.Should().ThrowAsync<ZeeKayDaConfigurationException>();
        exception.Which.AggregatedFailures.Should().ContainSingle(f => f.Code == "signing.file_signing.invalid_pfx");
        exception.Which.Message.Should().Contain(nextPath);
    }

    // ── Chain bundles: the signing certificate, not the first one ───────────────────────────────

    [Fact]
    public async Task ReadAsync_reports_the_signing_certificate_when_a_chain_certificate_is_stored_first()
    {
        // PKCS#12 imposes no bag ordering, so "the first certificate" is not the one that signs.
        // Publishing a chain certificate's key would put a key nothing can sign with into the JWKS,
        // while the tokens the real key signed carry a kid that is no longer published at all.
        var ct = TestContext.Current.CancellationToken;
        using var tempDir = new TempSigningKeyDirectory();
        var (bundle, signingSubject, signingPublicKey) = AdversarialPkcs12Factory.ChainCertificateFirst(
            CorrectPassword, T0 - TimeSpan.FromDays(1), T0 + TimeSpan.FromDays(365));
        var path = tempDir.WriteBytes("current.pfx", bundle);
        var sut = BuildSource(new PfxFile(path, Password()));

        var keySet = await sut.ReadAsync(ct);

        keySet.Single().PublicKey.RsaPublicParameters!.Value.Modulus
            .Should().BeEquivalentTo(signingPublicKey.Modulus, "the leaf's key signs, not the CA's");

        // The certificate the old first-bag walk would have returned, proving the two differ and that
        // this test would fail if selection regressed to it.
        using var chainCertificate = X509CertificateLoader.LoadPkcs12(bundle, CorrectPassword);
        chainCertificate.Subject.Should().Be(signingSubject);
    }

    [Fact]
    public async Task CreateSignerAsync_opens_the_same_certificate_the_read_reported_for_a_chain_bundle()
    {
        // The read path and the signing path must not disagree about which certificate is the signing
        // one, or the ring would publish one key and sign with another.
        var ct = TestContext.Current.CancellationToken;
        using var tempDir = new TempSigningKeyDirectory();
        var (bundle, _, _) = AdversarialPkcs12Factory.ChainCertificateFirst(
            CorrectPassword, T0 - TimeSpan.FromDays(1), T0 + TimeSpan.FromDays(365));
        var path = tempDir.WriteBytes("current.pfx", bundle);
        var sut = BuildSource(new PfxFile(path, Password()));
        var keySet = await sut.ReadAsync(ct);

        using var signer = await sut.CreateSignerAsync(keySet.Single().Id, ct);
        var signingInput = "header.payload"u8.ToArray();
        var signature = await signer.SignAsync(signingInput, ct);

        using var rsa = RSA.Create(keySet.Single().PublicKey.RsaPublicParameters!.Value);
        rsa.VerifyData(signingInput, signature.Span, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1)
            .Should().BeTrue("the published key and the signing key must be the same key pair");
    }

    [Fact]
    public async Task ReadAsync_rejects_a_bundle_with_several_certificates_and_nothing_identifying_the_signer()
    {
        var ct = TestContext.Current.CancellationToken;
        using var tempDir = new TempSigningKeyDirectory();
        var bundle = AdversarialPkcs12Factory.TwoCertificatesUnmarkedKey(
            CorrectPassword, T0 - TimeSpan.FromDays(1), T0 + TimeSpan.FromDays(365));
        var path = tempDir.WriteBytes("current.pfx", bundle);
        var sut = BuildSource(new PfxFile(path, Password()));

        var act = async () => await sut.ReadAsync(ct);

        var exception = await act.Should().ThrowAsync<ZeeKayDaConfigurationException>();
        exception.Which.AggregatedFailures.Should().ContainSingle(f => f.Code == "signing.file_signing.invalid_pfx");
        exception.Which.Message.Should().Contain("nothing identifying which one signs");
    }

    [Fact]
    public async Task ReadAsync_rejects_a_bundle_whose_certificates_are_each_paired_to_their_own_key()
    {
        // Two complete keypairs in one bundle: both certificates are legitimately "the one with a
        // key", so which signs is genuinely ambiguous and guessing would be worse than failing.
        var ct = TestContext.Current.CancellationToken;
        using var tempDir = new TempSigningKeyDirectory();
        var bundle = AdversarialPkcs12Factory.TwoPairedKeypairs(
            CorrectPassword, T0 - TimeSpan.FromDays(1), T0 + TimeSpan.FromDays(365));
        var path = tempDir.WriteBytes("current.pfx", bundle);
        var sut = BuildSource(new PfxFile(path, Password()));

        var act = async () => await sut.ReadAsync(ct);

        var exception = await act.Should().ThrowAsync<ZeeKayDaConfigurationException>();
        exception.Which.AggregatedFailures.Should().ContainSingle(f => f.Code == "signing.file_signing.invalid_pfx");
        exception.Which.Message.Should().Contain("ambiguous");
    }

    [Fact]
    public async Task ReadAsync_loads_a_single_certificate_whose_key_bag_localKeyId_matches_nothing()
    {
        // A lone certificate is unambiguous whatever the attributes say, so a bundle whose key bag
        // carries a localKeyId matching no certificate must still load rather than fail on a
        // technicality.
        var ct = TestContext.Current.CancellationToken;
        using var tempDir = new TempSigningKeyDirectory();
        var bundle = AdversarialPkcs12Factory.SingleCertificateWithUnmatchedKeyId(
            CorrectPassword, T0 - TimeSpan.FromDays(1), T0 + TimeSpan.FromDays(365));
        var path = tempDir.WriteBytes("current.pfx", bundle);
        var sut = BuildSource(new PfxFile(path, Password()));

        var keySet = await sut.ReadAsync(ct);

        keySet.Single().PublicKey.RsaPublicParameters.Should().NotBeNull();
    }

    [Fact]
    public async Task ReadAsync_rejects_a_key_stripped_chain_bundle_even_when_its_leaf_is_marked()
    {
        // The shape `openssl pkcs12 -export -nokeys` produces for a chain. The leaf is identifiable
        // from the localKeyId of the stripped key, but the bundle can never sign, and any listed
        // bundle may be chosen to.
        var ct = TestContext.Current.CancellationToken;
        using var tempDir = new TempSigningKeyDirectory();
        var (bundle, _) = AdversarialPkcs12Factory.CertificateOnlyChainWithMarkedLeaf(
            CorrectPassword, T0 - TimeSpan.FromDays(1), T0 + TimeSpan.FromDays(365));
        var path = tempDir.WriteBytes("stripped.pfx", bundle);
        var sut = BuildSource(new PfxFile(path, Password()));

        var act = async () => await sut.ReadAsync(ct);

        var exception = await act.Should().ThrowAsync<ZeeKayDaConfigurationException>();
        exception.Which.AggregatedFailures.Should().ContainSingle(f => f.Code == "signing.file_signing.invalid_pfx");
        exception.Which.Message.Should().Contain("carries no private key");
    }

    [Fact]
    public async Task ReadAsync_rejects_a_bundle_holding_an_unmarked_key_beside_a_marked_chain_certificate()
    {
        // The bundle does hold a private key, so the mark is not to be trusted on its own: the marked
        // certificate is the issuer's, while CreateSignerAsync would open the leaf's key. Publishing one key and signing with another is unverifiable at every relying party.
        var ct = TestContext.Current.CancellationToken;
        using var tempDir = new TempSigningKeyDirectory();
        var bundle = AdversarialPkcs12Factory.UnmarkedKeyBagWithMarkedChainCertificate(
            CorrectPassword, T0 - TimeSpan.FromDays(1), T0 + TimeSpan.FromDays(365));
        var path = tempDir.WriteBytes("current.pfx", bundle);
        var sut = BuildSource(new PfxFile(path, Password()));

        var act = async () => await sut.ReadAsync(ct);

        (await act.Should().ThrowAsync<ZeeKayDaConfigurationException>())
            .Which.AggregatedFailures.Should().ContainSingle(f => f.Code == "signing.file_signing.invalid_pfx");
    }

    [Fact]
    public async Task ReadAsync_rejects_a_bundle_whose_key_names_a_certificate_it_does_not_carry()
    {
        var ct = TestContext.Current.CancellationToken;
        using var tempDir = new TempSigningKeyDirectory();
        var bundle = AdversarialPkcs12Factory.KeyIdMatchingNoCertificate(
            CorrectPassword, T0 - TimeSpan.FromDays(1), T0 + TimeSpan.FromDays(365));
        var path = tempDir.WriteBytes("current.pfx", bundle);
        var sut = BuildSource(new PfxFile(path, Password()));

        var act = async () => await sut.ReadAsync(ct);

        var exception = await act.Should().ThrowAsync<ZeeKayDaConfigurationException>();
        exception.Which.AggregatedFailures.Should().ContainSingle(f => f.Code == "signing.file_signing.invalid_pfx");
        exception.Which.Message.Should().Contain("not among the certificates it carries");
    }

    // ── Several listed files, and every read hits the disk ───────────────────────────────────────

    [Fact]
    public async Task ReadAsync_lists_every_configured_file()
    {
        var ct = TestContext.Current.CancellationToken;
        using var tempDir = new TempSigningKeyDirectory();
        using var firstCertificate = CreateRsaCertificate();
        using var secondCertificate = CreateRsaCertificate();
        using var thirdCertificate = CreateRsaCertificate();
        var firstPath = tempDir.WritePfxFile("first.pfx", firstCertificate, CorrectPassword);
        var secondPath = tempDir.WritePfxFile("second.pfx", secondCertificate, CorrectPassword);
        var thirdPath = tempDir.WritePfxFile("third.pfx", thirdCertificate, CorrectPassword);
        var sut = BuildSource(
            [new PfxFile(firstPath, Password()), new PfxFile(secondPath, Password()), new PfxFile(thirdPath, Password())]);

        var keySet = await sut.ReadAsync(ct);

        keySet.Select(k => k.Id.Value).Should().BeEquivalentTo([firstPath, secondPath, thirdPath]);
    }

    [Fact]
    public async Task ReadAsync_throws_after_a_listed_bundle_is_deleted()
    {
        var ct = TestContext.Current.CancellationToken;
        using var tempDir = new TempSigningKeyDirectory();
        using var certificate = CreateRsaCertificate();
        var path = tempDir.WritePfxFile("current.pfx", certificate, CorrectPassword);
        var sut = BuildSource(new PfxFile(path, Password()));
        await sut.ReadAsync(ct);
        File.Delete(path);

        var act = async () => await sut.ReadAsync(ct);

        (await act.Should().ThrowAsync<ZeeKayDaConfigurationException>())
            .Which.AggregatedFailures.Should().ContainSingle(f => f.Code == "signing.file_signing.file_not_found");
    }

    [Fact]
    public async Task ReadAsync_observes_a_replaced_bundle_on_the_next_read()
    {
        var ct = TestContext.Current.CancellationToken;
        using var tempDir = new TempSigningKeyDirectory();
        using var certificate = CreateRsaCertificate();
        using var replacement = CreateRsaCertificate();
        var path = tempDir.WritePfxFile("current.pfx", certificate, CorrectPassword);
        var sut = BuildSource(new PfxFile(path, Password()));

        var first = await sut.ReadAsync(ct);
        File.Delete(path);
        tempDir.WritePfxFile("current.pfx", replacement, CorrectPassword);
        var second = await sut.ReadAsync(ct);

        second.Single().PublicKey.RsaPublicParameters!.Value.Modulus
            .Should().Equal(replacement.GetRSAPublicKey()!.ExportParameters(false).Modulus)
            .And.NotEqual(first.Single().PublicKey.RsaPublicParameters!.Value.Modulus);
    }

    // ── Missing file, wrong password, invalid bundle ─────────────────────────────────────────────

    [Fact]
    public async Task ReadAsync_throws_when_a_listed_file_does_not_exist()
    {
        var ct = TestContext.Current.CancellationToken;
        using var tempDir = new TempSigningKeyDirectory();
        var missingPath = tempDir.GetPath("does-not-exist.pfx");
        var sut = BuildSource(new PfxFile(missingPath, Password()));

        var act = async () => await sut.ReadAsync(ct);

        var exception = await act.Should().ThrowAsync<ZeeKayDaConfigurationException>();
        exception.Which.AggregatedFailures.Should().ContainSingle(f => f.Code == "signing.file_signing.file_not_found");
        exception.Which.Message.Should().Contain(missingPath);
    }

    [Fact]
    public async Task ReadAsync_throws_for_an_incorrect_password_and_never_leaks_it()
    {
        const string wrongPassword = "hunter2-is-not-the-password";
        var ct = TestContext.Current.CancellationToken;
        using var tempDir = new TempSigningKeyDirectory();
        using var certificate = CreateRsaCertificate();
        var path = tempDir.WritePfxFile("current.pfx", certificate, CorrectPassword);
        var sut = BuildSource(new PfxFile(path, Password(wrongPassword)));

        var act = async () => await sut.ReadAsync(ct);

        var exception = await act.Should().ThrowAsync<ZeeKayDaConfigurationException>();
        exception.Which.AggregatedFailures.Should().ContainSingle(f => f.Code == "signing.file_signing.invalid_pfx");
        exception.Which.Message.Should().NotContain(wrongPassword).And.NotContain(CorrectPassword);
    }

    [Fact]
    public async Task ReadAsync_throws_for_an_incorrect_password_on_any_listed_file()
    {
        var ct = TestContext.Current.CancellationToken;
        using var tempDir = new TempSigningKeyDirectory();
        using var currentCertificate = CreateRsaCertificate();
        using var nextCertificate = CreateRsaCertificate();
        var currentPath = tempDir.WritePfxFile("current.pfx", currentCertificate, CorrectPassword);
        var nextPath = tempDir.WritePfxFile("next.pfx", nextCertificate, CorrectPassword);
        var sut = BuildSource([new PfxFile(currentPath, Password()), new PfxFile(nextPath, Password("wrong"))]);

        var act = async () => await sut.ReadAsync(ct);

        var exception = await act.Should().ThrowAsync<ZeeKayDaConfigurationException>();
        exception.Which.AggregatedFailures.Should().ContainSingle(f => f.Code == "signing.file_signing.invalid_pfx");
        exception.Which.Message.Should().Contain(nextPath);
    }

    [Fact]
    public async Task ReadAsync_throws_for_an_empty_password_when_the_bundle_has_one()
    {
        var ct = TestContext.Current.CancellationToken;
        using var tempDir = new TempSigningKeyDirectory();
        using var certificate = CreateRsaCertificate();
        var path = tempDir.WritePfxFile("current.pfx", certificate, CorrectPassword);
        var sut = BuildSource(new PfxFile(path, Password(string.Empty)));

        var act = async () => await sut.ReadAsync(ct);

        (await act.Should().ThrowAsync<ZeeKayDaConfigurationException>())
            .Which.AggregatedFailures.Should().ContainSingle(f => f.Code == "signing.file_signing.invalid_pfx");
    }

    [Fact]
    public async Task ReadAsync_throws_when_the_file_is_not_a_PKCS12_bundle_at_all()
    {
        var ct = TestContext.Current.CancellationToken;
        using var tempDir = new TempSigningKeyDirectory();
        var path = tempDir.WriteTextFile("garbage.pfx", "this is definitely not a PKCS#12 bundle");
        var sut = BuildSource(new PfxFile(path, Password()));

        var act = async () => await sut.ReadAsync(ct);

        var exception = await act.Should().ThrowAsync<ZeeKayDaConfigurationException>();
        exception.Which.AggregatedFailures.Should().ContainSingle(f => f.Code == "signing.file_signing.invalid_pfx");
        exception.Which.Message.Should().Contain(path);
    }

    // ── Permission enforcement ───────────────────────────────────────────────────────────────────

    [Fact]
    public async Task ReadAsync_throws_when_the_file_is_broader_than_0600_on_Unix()
    {
        Assert.SkipWhen(OperatingSystem.IsWindows(), "0600-mode enforcement is the Unix permission model.");

        var ct = TestContext.Current.CancellationToken;
        using var tempDir = new TempSigningKeyDirectory();
        using var certificate = CreateRsaCertificate();
        var path = tempDir.WritePfxFile("current.pfx", certificate, CorrectPassword);
        tempDir.MakeTooPermissive(path);
        var sut = BuildSource(new PfxFile(path, Password()));

        var act = async () => await sut.ReadAsync(ct);

        (await act.Should().ThrowAsync<ZeeKayDaConfigurationException>())
            .Which.AggregatedFailures.Should().ContainSingle(f => f.Code == "signing.file_signing.file_too_permissive");
    }

    [Fact]
    public async Task ReadAsync_throws_when_the_ACL_grants_a_broad_principal_on_Windows()
    {
        Assert.SkipUnless(OperatingSystem.IsWindows(), "broad-principal ACL enforcement is the Windows permission model.");

        var ct = TestContext.Current.CancellationToken;
        using var tempDir = new TempSigningKeyDirectory();
        using var certificate = CreateRsaCertificate();
        var path = tempDir.WritePfxFile("current.pfx", certificate, CorrectPassword);
        tempDir.MakeTooPermissive(path);
        var sut = BuildSource(new PfxFile(path, Password()));

        var act = async () => await sut.ReadAsync(ct);

        (await act.Should().ThrowAsync<ZeeKayDaConfigurationException>())
            .Which.AggregatedFailures.Should().ContainSingle(f => f.Code == "signing.file_signing.file_too_permissive");
    }

    [Fact]
    public async Task ReadAsync_succeeds_when_the_file_is_secured_to_the_current_identity()
    {
        var ct = TestContext.Current.CancellationToken;
        using var tempDir = new TempSigningKeyDirectory();
        using var certificate = CreateRsaCertificate();
        var path = tempDir.WritePfxFile("current.pfx", certificate, CorrectPassword);
        var sut = BuildSource(new PfxFile(path, Password()));

        var act = async () => await sut.ReadAsync(ct);

        await act.Should().NotThrowAsync();
    }

    [Fact]
    public async Task ReadAsync_enforces_permissions_on_every_listed_file()
    {
        Assert.SkipWhen(OperatingSystem.IsWindows(), "0600-mode enforcement is the Unix permission model.");

        var ct = TestContext.Current.CancellationToken;
        using var tempDir = new TempSigningKeyDirectory();
        using var previousCertificate = CreateRsaCertificate();
        using var currentCertificate = CreateRsaCertificate();
        var previousPath = tempDir.WritePfxFile("previous.pfx", previousCertificate, CorrectPassword);
        var currentPath = tempDir.WritePfxFile("current.pfx", currentCertificate, CorrectPassword);
        tempDir.MakeTooPermissive(previousPath);
        var sut = BuildSource([new PfxFile(currentPath, Password()), new PfxFile(previousPath, Password())]);

        var act = async () => await sut.ReadAsync(ct);

        (await act.Should().ThrowAsync<ZeeKayDaConfigurationException>())
            .Which.AggregatedFailures.Should().ContainSingle(f => f.Code == "signing.file_signing.file_too_permissive");
    }

    // ── Symlink rejection ────────────────────────────────────────────────────────────────────────

    [Fact]
    public async Task ReadAsync_throws_when_the_configured_path_is_a_symlink()
    {
        var ct = TestContext.Current.CancellationToken;
        using var tempDir = new TempSigningKeyDirectory();
        using var certificate = CreateRsaCertificate();
        var realPath = tempDir.WritePfxFile("real.pfx", certificate, CorrectPassword);
        var symlinkPath = tempDir.GetPath("link.pfx");

        try
        {
            File.CreateSymbolicLink(symlinkPath, realPath);
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            Assert.Skip("Creating a symlink requires elevated privileges/Developer Mode on this platform.");
            return;
        }

        var sut = BuildSource(new PfxFile(symlinkPath, Password()));

        var act = async () => await sut.ReadAsync(ct);

        (await act.Should().ThrowAsync<ZeeKayDaConfigurationException>())
            .Which.AggregatedFailures.Should().ContainSingle(f => f.Code == "signing.file_signing.symlink_detected");
    }

    // ── EC certificates ──────────────────────────────────────────────────────────────────────────

    [Fact]
    public async Task ReadAsync_supports_EC_certificates_with_a_matching_EC_algorithm()
    {
        var ct = TestContext.Current.CancellationToken;
        using var tempDir = new TempSigningKeyDirectory();
        using var certificate = TestCertificateFactory.CreateEcSelfSigned("ec-test", T0 - TimeSpan.FromDays(1), T0 + TimeSpan.FromDays(365));
        var path = tempDir.WritePfxFile("current.pfx", certificate, CorrectPassword);
        var sut = BuildSource(new PfxFile(path, Password()), algorithm: SigningAlgorithm.ES256);

        var keySet = await sut.ReadAsync(ct);

        keySet.Single().PublicKey.KeyType.Should().Be(SigningKeyType.Ec);
        keySet.Single().PublicKey.EcPublicParameters.Should().NotBeNull();
        sut.Algorithm.Should().Be(SigningAlgorithm.ES256);
    }

    [Fact]
    public async Task CreateSignerAsync_signs_with_an_EC_certificates_private_key()
    {
        var ct = TestContext.Current.CancellationToken;
        using var tempDir = new TempSigningKeyDirectory();
        using var certificate = TestCertificateFactory.CreateEcSelfSigned("ec-test", T0 - TimeSpan.FromDays(1), T0 + TimeSpan.FromDays(365));
        var path = tempDir.WritePfxFile("current.pfx", certificate, CorrectPassword);
        var sut = BuildSource(new PfxFile(path, Password()), algorithm: SigningAlgorithm.ES256);
        var keySet = await sut.ReadAsync(ct);

        using var signer = await sut.CreateSignerAsync(keySet.Single().Id, ct);
        var signingInput = "header.payload"u8.ToArray();
        var signature = await signer.SignAsync(signingInput, ct);

        using var ecdsa = ECDsa.Create(keySet.Single().PublicKey.EcPublicParameters!.Value);
        ecdsa.VerifyData(signingInput, signature.Span, HashAlgorithmName.SHA256).Should().BeTrue();
    }

    // ── CreateSignerAsync opens any listed file, and only a listed one ───────────────────────────

    [Fact]
    public async Task CreateSignerAsync_throws_when_called_for_a_key_id_that_is_not_listed()
    {
        var ct = TestContext.Current.CancellationToken;
        using var tempDir = new TempSigningKeyDirectory();
        using var certificate = CreateRsaCertificate();
        var path = tempDir.WritePfxFile("current.pfx", certificate, CorrectPassword);
        var sut = BuildSource(new PfxFile(path, Password()));

        var act = async () => await sut.CreateSignerAsync(new SourceKeyId("not-a-configured-file"), ct);

        await act.Should().ThrowAsync<InvalidOperationException>();
    }

    [Fact]
    public async Task CreateSignerAsync_throws_for_a_bundle_that_exists_on_disk_but_is_not_listed()
    {
        var ct = TestContext.Current.CancellationToken;
        using var tempDir = new TempSigningKeyDirectory();
        using var listedCertificate = CreateRsaCertificate();
        using var otherCertificate = CreateRsaCertificate();
        var listedPath = tempDir.WritePfxFile("listed.pfx", listedCertificate, CorrectPassword);
        var otherPath = tempDir.WritePfxFile("other.pfx", otherCertificate, CorrectPassword);
        var sut = BuildSource(new PfxFile(listedPath, Password()));

        var act = async () => await sut.CreateSignerAsync(new SourceKeyId(otherPath), ct);

        await act.Should().ThrowAsync<InvalidOperationException>(
            "a signer must never be opened over a file the host did not list");
    }

    [Fact]
    public async Task CreateSignerAsync_opens_a_signer_for_any_listed_file()
    {
        var ct = TestContext.Current.CancellationToken;
        using var tempDir = new TempSigningKeyDirectory();
        using var firstCertificate = CreateRsaCertificate();
        using var secondCertificate = CreateRsaCertificate();
        var firstPath = tempDir.WritePfxFile("first.pfx", firstCertificate, CorrectPassword);
        var secondPath = tempDir.WritePfxFile("second.pfx", secondCertificate, "second-password");
        var sut = BuildSource([new PfxFile(firstPath, Password()), new PfxFile(secondPath, Password("second-password"))]);
        var signingInput = "header.payload"u8.ToArray();

        using var signer = await sut.CreateSignerAsync(new SourceKeyId(secondPath), ct);
        var signature = await signer.SignAsync(signingInput, ct);

        secondCertificate.GetRSAPublicKey()!
            .VerifyData(signingInput, signature.Span, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1)
            .Should().BeTrue("the signer must be opened over the bundle whose path was asked for, not the first one");
    }

    [Fact]
    public async Task CreateSignerAsync_throws_private_key_not_found_when_a_bundle_that_has_since_lost_its_key_is_asked_to_sign()
    {
        // ReadAsync rejects a keyless bundle, so this is the file being swapped for a key-stripped one
        // after the read: the signer must fail with the certificate-level code, not sign garbage or NRE.
        var ct = TestContext.Current.CancellationToken;
        using var tempDir = new TempSigningKeyDirectory();
        using var certificate = CreateRsaCertificate();
        using var publicOnly = X509CertificateLoader.LoadCertificate(certificate.RawData);
        var path = tempDir.WritePfxFile("current.pfx", publicOnly, CorrectPassword);
        var sut = BuildSource(new PfxFile(path, Password()));

        var act = async () => await sut.CreateSignerAsync(new SourceKeyId(path), ct);

        var exception = await act.Should().ThrowAsync<ZeeKayDaConfigurationException>();
        exception.Which.AggregatedFailures.Should().ContainSingle(
            f => f.Code == "signing.certificate.private_key_not_found");
    }

    [Fact]
    public async Task CreateSignerAsync_throws_invalid_pfx_for_a_wrong_password_rather_than_leaking_the_raw_crypto_error()
    {
        // The signer-open path loads the bundle separately from ReadAsync, so its password failure
        // must be wrapped into the same configuration failure the read path produces.
        var ct = TestContext.Current.CancellationToken;
        using var tempDir = new TempSigningKeyDirectory();
        using var certificate = CreateRsaCertificate();
        var path = tempDir.WritePfxFile("current.pfx", certificate, CorrectPassword);
        var sut = BuildSource(new PfxFile(path, Password("not the password")));

        var act = async () => await sut.CreateSignerAsync(new SourceKeyId(path), ct);

        var exception = await act.Should().ThrowAsync<ZeeKayDaConfigurationException>();
        exception.Which.AggregatedFailures.Should().ContainSingle(
            f => f.Code == "signing.file_signing.invalid_pfx");
    }

    // ── The failure message never repeats the parser's own text (#764) ───────────────────────────

    [Fact]
    public async Task ReadAsync_names_the_parser_exception_type_rather_than_copying_its_message()
    {
        var ct = TestContext.Current.CancellationToken;
        using var tempDir = new TempSigningKeyDirectory();
        var path = tempDir.WriteBytes("current.pfx", [0x01, 0x02, 0x03, 0x04]);
        var sut = BuildSource(new PfxFile(path, Password()));

        var act = async () => await sut.ReadAsync(ct);

        var exception = await act.Should().ThrowAsync<ZeeKayDaConfigurationException>();
        AssertNamesTypeWithoutCopyingMessage(exception.Which);
    }

    [Fact]
    public async Task CreateSignerAsync_names_the_parser_exception_type_rather_than_copying_its_message()
    {
        // The signer path loads the bundle under the configured password, so the parser's text is
        // raised over a password-protected read. Only the type is reported.
        var ct = TestContext.Current.CancellationToken;
        using var tempDir = new TempSigningKeyDirectory();
        using var certificate = CreateRsaCertificate();
        var path = tempDir.WritePfxFile("current.pfx", certificate, CorrectPassword);
        var sut = BuildSource(new PfxFile(path, Password("not the password")));

        var act = async () => await sut.CreateSignerAsync(new SourceKeyId(path), ct);

        var exception = await act.Should().ThrowAsync<ZeeKayDaConfigurationException>();
        AssertNamesTypeWithoutCopyingMessage(exception.Which);
    }

    /// <summary>
    /// Asserts the contract on <c>ZeeKayDaConfigurationFailure.Message</c>: it names the underlying
    /// exception's type, never repeats that exception's own message, and leaves the original
    /// reachable as the inner exception.
    /// </summary>
    private static void AssertNamesTypeWithoutCopyingMessage(ZeeKayDaConfigurationException exception)
    {
        exception.InnerException.Should().NotBeNull();
        var cause = exception.InnerException!;

        var failure = exception.AggregatedFailures.Should()
            .ContainSingle(f => f.Code == "signing.file_signing.invalid_pfx").Subject;

        failure.Message.Should().Contain(cause.GetType().FullName);
        failure.Message.Should().Contain("See the inner exception for the root cause.");
        cause.Message.Should().NotBeNullOrWhiteSpace();
        failure.Message.Should().NotContain(cause.Message);
    }
}
