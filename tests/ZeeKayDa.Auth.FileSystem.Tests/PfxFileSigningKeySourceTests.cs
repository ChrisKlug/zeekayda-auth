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
/// The source reads its three slots exactly once and never re-reads them, so there is no reload or
/// change-detection surface here. Which key signs is decided entirely by which slot it is configured
/// in, never by the clock, so this type holds no <c>TimeProvider</c>: the one clock check that
/// remains, on the signing key's own validity window, belongs to <c>StaticSigningKeyRing</c> and is
/// tested there.
/// </remarks>
public sealed class PfxFileSigningKeySourceTests
{
    private static readonly DateTimeOffset T0 = DateTimeOffset.Parse("2026-01-01T00:00:00Z");
    private const string CorrectPassword = "correct horse battery staple";

    private static Func<CancellationToken, ValueTask<string>> Password(string password = CorrectPassword) =>
        _ => ValueTask.FromResult(password);

    private static PfxFileSigningKeySource BuildSource(
        PfxFile? current,
        PfxFile? previous = null,
        PfxFile? next = null,
        SigningAlgorithm algorithm = SigningAlgorithm.RS256)
    {
        var options = new PfxFileSigningOptions
        {
            Previous = previous,
            Current = current,
            Next = next,
        };
        options.Algorithm = algorithm;

        return new PfxFileSigningKeySource(
            Options.Create(options),
            new FileSigningKeyReader(NullSanitizingLogger<FileSigningKeyReader>.Instance));
    }

    private static X509Certificate2 CreateRsaCertificate() =>
        TestCertificateFactory.CreateRsaSelfSigned("test", T0 - TimeSpan.FromDays(1), T0 + TimeSpan.FromDays(365));

    // ── Happy path ───────────────────────────────────────────────────────────────────────────────

    [Fact]
    public async Task ReadAsync_reports_the_Current_bundles_public_key_as_the_signing_key()
    {
        var ct = TestContext.Current.CancellationToken;
        using var tempDir = new TempSigningKeyDirectory();
        using var certificate = CreateRsaCertificate();
        var path = tempDir.WritePfxFile("current.pfx", certificate, CorrectPassword);
        var sut = BuildSource(new PfxFile(path, Password()));

        var keySet = await sut.ReadAsync(ct);

        keySet.Keys.Should().ContainSingle();
        keySet.SigningKey.Id.Should().Be(new SourceKeyId(path));
        keySet.SigningKey.Algorithm.Should().Be(SigningAlgorithm.RS256);
        keySet.SigningKey.PublicKey.KeyType.Should().Be(SigningKeyType.Rsa);
        keySet.SigningKey.PublicKey.RsaPublicParameters.Should().NotBeNull(
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

        keySet.SigningKey.NotBefore.Should().Be(new DateTimeOffset(certificate.NotBefore));
        keySet.SigningKey.ExpiresAt.Should().Be(new DateTimeOffset(certificate.NotAfter));
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

        using var signer = await sut.CreateSignerAsync(keySet.SigningKey.Id, ct);
        var signingInput = "header.payload"u8.ToArray();
        var signature = await signer.SignAsync(signingInput, ct);

        signer.Algorithm.Should().Be(SigningAlgorithm.RS256);
        using var rsa = RSA.Create(keySet.SigningKey.PublicKey.RsaPublicParameters!.Value);
        rsa.VerifyData(signingInput, signature.Span, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1)
            .Should().BeTrue("the signer must be opened over the same key pair the read reported");
    }

    // ── The bundled-format obligation: a published-only slot's key bag is never decrypted ────────

    [Fact]
    public async Task ReadAsync_reads_a_bundle_without_ever_producing_a_certificate_that_carries_its_private_key()
    {
        // The read path walks the PKCS#12 structure and takes the certificate bag, leaving the
        // shrouded key bag encrypted. Nothing it produces carries private material — which is what
        // keeps a Previous or Next private key out of this process entirely, on every platform,
        // rather than merely narrowing the window in which it exists.
        var ct = TestContext.Current.CancellationToken;
        using var tempDir = new TempSigningKeyDirectory();
        using var previousCertificate = CreateRsaCertificate();
        using var currentCertificate = CreateRsaCertificate();
        using var nextCertificate = CreateRsaCertificate();
        var previousPath = tempDir.WritePfxFile("previous.pfx", previousCertificate, "previous-password");
        var currentPath = tempDir.WritePfxFile("current.pfx", currentCertificate, CorrectPassword);
        var nextPath = tempDir.WritePfxFile("next.pfx", nextCertificate, "next-password");
        var sut = BuildSource(
            new PfxFile(currentPath, Password()),
            previous: new PfxFile(previousPath, Password("previous-password")),
            next: new PfxFile(nextPath, Password("next-password")));

        var keySet = await sut.ReadAsync(ct);

        keySet.Keys.Should().HaveCount(3);
        keySet.Keys.Should().AllSatisfy(key =>
            key.PublicKey.RsaPublicParameters.Should().NotBeNull("every slot yields public material only"));
    }

    [Fact]
    public async Task ReadAsync_reads_a_published_slot_whose_password_only_ever_opens_its_certificate()
    {
        // A per-slot password is still required to reach a published-only certificate — the safe it
        // sits in is password-protected — so this proves the password is used for the safe and not
        // as a step towards the key.
        var ct = TestContext.Current.CancellationToken;
        using var tempDir = new TempSigningKeyDirectory();
        using var currentCertificate = CreateRsaCertificate();
        using var nextCertificate = CreateRsaCertificate();
        var currentPath = tempDir.WritePfxFile("current.pfx", currentCertificate, CorrectPassword);
        var nextPath = tempDir.WritePfxFile("next.pfx", nextCertificate, "a different password");
        var sut = BuildSource(
            new PfxFile(currentPath, Password()),
            next: new PfxFile(nextPath, Password("a different password")));

        var keySet = await sut.ReadAsync(ct);

        keySet.Keys.Should().HaveCount(2);
        keySet.Keys.Select(k => k.Id.Value).Should().BeEquivalentTo([currentPath, nextPath]);
    }

    // ── Integrity: the password must actually authenticate the bundle ───────────────────────────

    [Fact]
    public async Task ReadAsync_rejects_a_bundle_whose_certificate_safe_is_unencrypted_when_the_password_is_wrong()
    {
        // The exploit this closes: reaching a certificate in an unencrypted safe needs no password,
        // so without a MAC check any substituted bundle is accepted. Previous and Next are published
        // but never signed with, so the ring's self-test would not catch it either — an attacker's
        // public key would simply appear in the JWKS as a valid verification key.
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

        keySet.SigningKey.Id.Should().Be(new SourceKeyId(path));
        keySet.SigningKey.PublicKey.RsaPublicParameters.Should().NotBeNull();
        keySet.SigningKey.NotBefore.Should().BeCloseTo(T0 - TimeSpan.FromDays(1), TimeSpan.FromSeconds(1));
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
    public async Task ReadAsync_rejects_a_wrong_password_on_a_published_only_slot_rather_than_deferring_it_to_promotion()
    {
        // A published-only slot has no signer, so nothing else would ever exercise its password. If a
        // wrong one passed startup, the operator would discover it only when that slot is promoted to
        // Current and the service refuses to start — which is exactly what staging in Next exists to
        // avoid.
        var ct = TestContext.Current.CancellationToken;
        using var tempDir = new TempSigningKeyDirectory();
        using var currentCertificate = CreateRsaCertificate();
        var currentPath = tempDir.WritePfxFile("current.pfx", currentCertificate, CorrectPassword);
        var nextBundle = AdversarialPkcs12Factory.UnencryptedCertificateSafe(
            "next-real-password", "next", T0 + TimeSpan.FromDays(1), T0 + TimeSpan.FromDays(400));
        var nextPath = tempDir.WriteBytes("next.pfx", nextBundle);
        var sut = BuildSource(
            new PfxFile(currentPath, Password()),
            next: new PfxFile(nextPath, Password("wrong")));

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

        keySet.SigningKey.PublicKey.RsaPublicParameters!.Value.Modulus
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

        using var signer = await sut.CreateSignerAsync(keySet.SigningKey.Id, ct);
        var signingInput = "header.payload"u8.ToArray();
        var signature = await signer.SignAsync(signingInput, ct);

        using var rsa = RSA.Create(keySet.SigningKey.PublicKey.RsaPublicParameters!.Value);
        rsa.VerifyData(signingInput, signature.Span, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1)
            .Should().BeTrue("the published key and the signing key must be the same key pair");
    }

    [Fact]
    public async Task ReadAsync_rejects_a_bundle_with_several_certificates_and_nothing_identifying_the_signer()
    {
        var ct = TestContext.Current.CancellationToken;
        using var tempDir = new TempSigningKeyDirectory();
        var bundle = AdversarialPkcs12Factory.TwoCertificatesNoKey(
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

        keySet.SigningKey.PublicKey.RsaPublicParameters.Should().NotBeNull();
    }

    [Fact]
    public async Task ReadAsync_selects_the_marked_certificate_from_a_key_stripped_chain_bundle()
    {
        // The shape `openssl pkcs12 -export -nokeys` produces, and the right one for a published-only
        // slot: no private key at all, but the chain comes with it, so the leaf is identified only by
        // the localKeyId of the key that was stripped.
        var ct = TestContext.Current.CancellationToken;
        using var tempDir = new TempSigningKeyDirectory();
        var (bundle, expectedPublicKey) = AdversarialPkcs12Factory.CertificateOnlyChainWithMarkedLeaf(
            CorrectPassword, T0 - TimeSpan.FromDays(1), T0 + TimeSpan.FromDays(365));
        var currentPath = tempDir.WritePfxFile("current.pfx", CreateRsaCertificate(), CorrectPassword);
        var previousPath = tempDir.WriteBytes("previous.pfx", bundle);
        var sut = BuildSource(
            new PfxFile(currentPath, Password()),
            previous: new PfxFile(previousPath, Password()));

        var keySet = await sut.ReadAsync(ct);

        var previous = keySet.Keys.Single(k => k.Id.Value == previousPath);
        previous.PublicKey.RsaPublicParameters!.Value.Modulus
            .Should().BeEquivalentTo(expectedPublicKey.Modulus, "the leaf is the stripped key's certificate, not the CA");
    }

    [Fact]
    public async Task ReadAsync_rejects_a_bundle_holding_an_unmarked_key_beside_a_marked_chain_certificate()
    {
        // The bundle does hold a private key, so the "no key bag, trust the mark" fallback must not
        // fire: the marked certificate is the issuer's, while CreateSignerAsync would open the leaf's
        // key. Publishing one key and signing with another is unverifiable at every relying party.
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

    // ── The three slots ──────────────────────────────────────────────────────────────────────────

    [Fact]
    public async Task ReadAsync_publishes_every_configured_slot_and_signs_with_Current()
    {
        var ct = TestContext.Current.CancellationToken;
        using var tempDir = new TempSigningKeyDirectory();
        using var previousCertificate = CreateRsaCertificate();
        using var currentCertificate = CreateRsaCertificate();
        using var nextCertificate = CreateRsaCertificate();
        var previousPath = tempDir.WritePfxFile("previous.pfx", previousCertificate, CorrectPassword);
        var currentPath = tempDir.WritePfxFile("current.pfx", currentCertificate, CorrectPassword);
        var nextPath = tempDir.WritePfxFile("next.pfx", nextCertificate, CorrectPassword);
        var sut = BuildSource(
            new PfxFile(currentPath, Password()),
            previous: new PfxFile(previousPath, Password()),
            next: new PfxFile(nextPath, Password()));

        var keySet = await sut.ReadAsync(ct);

        keySet.Keys.Should().HaveCount(3);
        keySet.SigningKey.Id.Should().Be(new SourceKeyId(currentPath));
        keySet.Keys.Select(k => k.Id.Value).Should().BeEquivalentTo([currentPath, previousPath, nextPath]);
    }

    [Fact]
    public async Task ReadAsync_throws_when_no_Current_slot_is_configured()
    {
        var ct = TestContext.Current.CancellationToken;
        using var tempDir = new TempSigningKeyDirectory();
        using var certificate = CreateRsaCertificate();
        var path = tempDir.WritePfxFile("next.pfx", certificate, CorrectPassword);
        var sut = BuildSource(current: null, next: new PfxFile(path, Password()));

        var act = async () => await sut.ReadAsync(ct);

        (await act.Should().ThrowAsync<ZeeKayDaConfigurationException>())
            .Which.AggregatedFailures.Should().ContainSingle(f => f.Code == "signing.no_current_key");
    }

    // ── Read-once ────────────────────────────────────────────────────────────────────────────────

    [Fact]
    public async Task ReadAsync_returns_the_same_key_set_after_a_configured_bundle_is_deleted()
    {
        var ct = TestContext.Current.CancellationToken;
        using var tempDir = new TempSigningKeyDirectory();
        using var certificate = CreateRsaCertificate();
        var path = tempDir.WritePfxFile("current.pfx", certificate, CorrectPassword);
        var sut = BuildSource(new PfxFile(path, Password()));

        var first = await sut.ReadAsync(ct);
        File.Delete(path);
        var second = await sut.ReadAsync(ct);

        second.Should().BeSameAs(first, "the source reads its slots exactly once and never re-reads them");
    }

    // ── Missing file, wrong password, invalid bundle ─────────────────────────────────────────────

    [Fact]
    public async Task ReadAsync_throws_when_the_Current_file_does_not_exist()
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
    public async Task ReadAsync_throws_for_an_incorrect_password_on_a_published_only_slot()
    {
        var ct = TestContext.Current.CancellationToken;
        using var tempDir = new TempSigningKeyDirectory();
        using var currentCertificate = CreateRsaCertificate();
        using var nextCertificate = CreateRsaCertificate();
        var currentPath = tempDir.WritePfxFile("current.pfx", currentCertificate, CorrectPassword);
        var nextPath = tempDir.WritePfxFile("next.pfx", nextCertificate, CorrectPassword);
        var sut = BuildSource(
            new PfxFile(currentPath, Password()),
            next: new PfxFile(nextPath, Password("wrong")));

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
    public async Task ReadAsync_enforces_permissions_on_a_Previous_slots_file_too()
    {
        Assert.SkipWhen(OperatingSystem.IsWindows(), "0600-mode enforcement is the Unix permission model.");

        var ct = TestContext.Current.CancellationToken;
        using var tempDir = new TempSigningKeyDirectory();
        using var previousCertificate = CreateRsaCertificate();
        using var currentCertificate = CreateRsaCertificate();
        var previousPath = tempDir.WritePfxFile("previous.pfx", previousCertificate, CorrectPassword);
        var currentPath = tempDir.WritePfxFile("current.pfx", currentCertificate, CorrectPassword);
        tempDir.MakeTooPermissive(previousPath);
        var sut = BuildSource(
            new PfxFile(currentPath, Password()),
            previous: new PfxFile(previousPath, Password()));

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

        keySet.SigningKey.PublicKey.KeyType.Should().Be(SigningKeyType.Ec);
        keySet.SigningKey.PublicKey.EcPublicParameters.Should().NotBeNull();
        keySet.SigningKey.Algorithm.Should().Be(SigningAlgorithm.ES256);
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

        using var signer = await sut.CreateSignerAsync(keySet.SigningKey.Id, ct);
        var signingInput = "header.payload"u8.ToArray();
        var signature = await signer.SignAsync(signingInput, ct);

        using var ecdsa = ECDsa.Create(keySet.SigningKey.PublicKey.EcPublicParameters!.Value);
        ecdsa.VerifyData(signingInput, signature.Span, HashAlgorithmName.SHA256).Should().BeTrue();
    }

    [Fact]
    public async Task ReadAsync_reports_a_mismatched_algorithm_verbatim_and_leaves_the_rejection_to_the_key_set_builder()
    {
        // This source performs no key-pairing check of its own: SigningKeySetBuilder is the single
        // choke point where a mismatched algorithm is rejected, keyed on the source id — which here
        // is the file path, so the failure still names the offending bundle.
        var ct = TestContext.Current.CancellationToken;
        using var tempDir = new TempSigningKeyDirectory();
        using var certificate = CreateRsaCertificate();
        var path = tempDir.WritePfxFile("current.pfx", certificate, CorrectPassword);
        var sut = BuildSource(new PfxFile(path, Password()), algorithm: SigningAlgorithm.ES256);

        var keySet = await sut.ReadAsync(ct);
        var act = () => SigningKeySetBuilder.Build(keySet);

        keySet.SigningKey.Algorithm.Should().Be(SigningAlgorithm.ES256);
        var exception = act.Should().Throw<ZeeKayDaConfigurationException>();
        exception.Which.AggregatedFailures.Should().ContainSingle(f => f.Code == "signing.key_algorithm_mismatch");
        exception.Which.Message.Should().Contain(path);
    }

    // ── CreateSignerAsync is only ever openable for Current ──────────────────────────────────────

    [Fact]
    public async Task CreateSignerAsync_throws_when_called_for_a_key_id_that_is_not_configured_at_all()
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
    public async Task CreateSignerAsync_throws_when_called_for_the_Previous_slot()
    {
        // Previous is published, never signed with. Honouring this call would decrypt a key bag this
        // source otherwise never touches.
        var ct = TestContext.Current.CancellationToken;
        using var tempDir = new TempSigningKeyDirectory();
        using var previousCertificate = CreateRsaCertificate();
        using var currentCertificate = CreateRsaCertificate();
        var previousPath = tempDir.WritePfxFile("previous.pfx", previousCertificate, CorrectPassword);
        var currentPath = tempDir.WritePfxFile("current.pfx", currentCertificate, CorrectPassword);
        var sut = BuildSource(
            new PfxFile(currentPath, Password()),
            previous: new PfxFile(previousPath, Password()));

        var act = async () => await sut.CreateSignerAsync(new SourceKeyId(previousPath), ct);

        await act.Should().ThrowAsync<InvalidOperationException>();
    }

    [Fact]
    public async Task CreateSignerAsync_throws_when_called_for_the_Next_slot()
    {
        var ct = TestContext.Current.CancellationToken;
        using var tempDir = new TempSigningKeyDirectory();
        using var currentCertificate = CreateRsaCertificate();
        using var nextCertificate = CreateRsaCertificate();
        var currentPath = tempDir.WritePfxFile("current.pfx", currentCertificate, CorrectPassword);
        var nextPath = tempDir.WritePfxFile("next.pfx", nextCertificate, CorrectPassword);
        var sut = BuildSource(
            new PfxFile(currentPath, Password()),
            next: new PfxFile(nextPath, Password()));

        var act = async () => await sut.CreateSignerAsync(new SourceKeyId(nextPath), ct);

        await act.Should().ThrowAsync<InvalidOperationException>();
    }
}
