using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Microsoft.Extensions.Options;
using ZeeKayDa.Auth.FileSystem.Tests.Fixtures;
using ZeeKayDa.Auth.Tokens;

namespace ZeeKayDa.Auth.FileSystem.Tests;

/// <summary>
/// Direct-construction tests for <see cref="PemFileSigningKeySource"/>, bypassing DI and the
/// <c>AddPemFileSigning</c> extension methods entirely. A fake reader is never substituted: this
/// source's whole job is real filesystem interaction (permission enforcement, symlink detection),
/// so every test below exercises the real <see cref="FileSigningKeyReader"/> against real temporary
/// files.
/// </summary>
/// <remarks>
/// The source reads its three slots exactly once and never re-reads them, so there is no reload or
/// change-detection surface here — a replaced, deleted, or newly-added file is never picked up
/// without a restart. Which key signs is decided entirely by which slot it is configured in, never
/// by the clock, so this type holds no <c>TimeProvider</c>: the one clock check that remains, on the
/// signing key's own validity window, belongs to <c>StaticSigningKeyRing</c> and is tested there.
/// </remarks>
public sealed class PemFileSigningKeySourceTests
{
    private static readonly DateTimeOffset T0 = DateTimeOffset.Parse("2026-01-01T00:00:00Z");

    private static PemFileSigningKeySource BuildSource(
        PemSigningFile? current,
        PemCertificateFile? previous = null,
        PemCertificateFile? next = null,
        SigningAlgorithm algorithm = SigningAlgorithm.RS256)
    {
        var options = new PemFileSigningOptions
        {
            Previous = previous,
            Current = current,
            Next = next,
            Algorithm = algorithm,
        };

        return new PemFileSigningKeySource(
            Options.Create(options),
            new FileSigningKeyReader(NullSanitizingLogger<FileSigningKeyReader>.Instance));
    }

    private static X509Certificate2 CreateRsaCertificate() =>
        TestCertificateFactory.CreateRsaSelfSigned("test", T0 - TimeSpan.FromDays(1), T0 + TimeSpan.FromDays(365));

    // ── Happy path ───────────────────────────────────────────────────────────────────────────────

    [Fact]
    public async Task ReadAsync_reports_the_Current_certificates_public_key_as_the_signing_key()
    {
        var ct = TestContext.Current.CancellationToken;
        using var tempDir = new TempSigningKeyDirectory();
        using var certificate = CreateRsaCertificate();
        var path = tempDir.WritePemFile("current.pem", certificate);
        var sut = BuildSource(new PemSigningFile(path));

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
        var path = tempDir.WritePemFile("current.pem", certificate);
        var sut = BuildSource(new PemSigningFile(path));

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
        var path = tempDir.WritePemFile("current.pem", certificate);
        var sut = BuildSource(new PemSigningFile(path));
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
        using var tempDir = new TempSigningKeyDirectory();
        using var previousCertificate = CreateRsaCertificate();
        using var currentCertificate = CreateRsaCertificate();
        using var nextCertificate = CreateRsaCertificate();
        var previousPath = tempDir.WritePemFile("previous.pem", previousCertificate);
        var currentPath = tempDir.WritePemFile("current.pem", currentCertificate);
        var nextPath = tempDir.WritePemFile("next.pem", nextCertificate);
        var sut = BuildSource(
            new PemSigningFile(currentPath),
            previous: new PemCertificateFile(previousPath),
            next: new PemCertificateFile(nextPath));

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
        var path = tempDir.WritePemFile("next.pem", certificate);
        var sut = BuildSource(current: null, next: new PemCertificateFile(path));

        var act = async () => await sut.ReadAsync(ct);

        (await act.Should().ThrowAsync<ZeeKayDaConfigurationException>())
            .Which.AggregatedFailures.Should().ContainSingle(f => f.Code == "signing.no_current_key");
    }

    [Fact]
    public async Task ReadAsync_never_reads_private_material_for_Previous_or_Next()
    {
        // Previous and Next are PemCertificateFile, which has no KeyPath, so "opened a published-only
        // slot's private key" is unrepresentable rather than merely untested. What is left to prove is
        // that a certificate-only file is enough for those slots: no private key exists on disk for
        // either one here, and the read still succeeds.
        var ct = TestContext.Current.CancellationToken;
        using var tempDir = new TempSigningKeyDirectory();
        using var previousCertificate = CreateRsaCertificate();
        using var currentCertificate = CreateRsaCertificate();
        using var nextCertificate = CreateRsaCertificate();
        var previousCertPath = tempDir.WriteCertificateOnlyPemFile("previous.crt", previousCertificate);
        var nextCertPath = tempDir.WriteCertificateOnlyPemFile("next.crt", nextCertificate);
        var currentPath = tempDir.WritePemFile("current.pem", currentCertificate);
        var sut = BuildSource(
            new PemSigningFile(currentPath),
            previous: new PemCertificateFile(previousCertPath),
            next: new PemCertificateFile(nextCertPath));

        var keySet = await sut.ReadAsync(ct);

        keySet.Keys.Should().HaveCount(3);
    }

    // ── Read-once ────────────────────────────────────────────────────────────────────────────────

    [Fact]
    public async Task ReadAsync_returns_the_same_key_set_after_a_configured_file_is_deleted()
    {
        var ct = TestContext.Current.CancellationToken;
        using var tempDir = new TempSigningKeyDirectory();
        using var certificate = CreateRsaCertificate();
        var path = tempDir.WritePemFile("current.pem", certificate);
        var sut = BuildSource(new PemSigningFile(path));

        var first = await sut.ReadAsync(ct);
        File.Delete(path);
        var second = await sut.ReadAsync(ct);

        second.Should().BeSameAs(first, "the source reads its slots exactly once and never re-reads them");
    }

    [Fact]
    public async Task ReadAsync_returns_the_same_key_set_after_a_configured_file_is_replaced()
    {
        var ct = TestContext.Current.CancellationToken;
        using var tempDir = new TempSigningKeyDirectory();
        using var certificate = CreateRsaCertificate();
        using var replacement = CreateRsaCertificate();
        var path = tempDir.WritePemFile("current.pem", certificate);
        var sut = BuildSource(new PemSigningFile(path));

        var first = await sut.ReadAsync(ct);
        tempDir.WritePemFile("current.pem", replacement);
        var second = await sut.ReadAsync(ct);

        second.SigningKey.PublicKey.RsaPublicParameters!.Value.Modulus
            .Should().BeEquivalentTo(first.SigningKey.PublicKey.RsaPublicParameters!.Value.Modulus);
    }

    // ── Missing and invalid files ────────────────────────────────────────────────────────────────

    [Fact]
    public async Task ReadAsync_throws_when_the_Current_file_does_not_exist()
    {
        var ct = TestContext.Current.CancellationToken;
        using var tempDir = new TempSigningKeyDirectory();
        var missingPath = tempDir.GetPath("does-not-exist.pem");
        var sut = BuildSource(new PemSigningFile(missingPath));

        var act = async () => await sut.ReadAsync(ct);

        var exception = await act.Should().ThrowAsync<ZeeKayDaConfigurationException>();
        exception.Which.AggregatedFailures.Should().ContainSingle(f => f.Code == "signing.file_signing.file_not_found");
        exception.Which.Message.Should().Contain(missingPath);
    }

    [Fact]
    public async Task ReadAsync_throws_for_invalid_PEM_content()
    {
        var ct = TestContext.Current.CancellationToken;
        using var tempDir = new TempSigningKeyDirectory();
        var path = tempDir.WriteTextFile("garbage.pem", "not a pem file at all");
        var sut = BuildSource(new PemSigningFile(path));

        var act = async () => await sut.ReadAsync(ct);

        var exception = await act.Should().ThrowAsync<ZeeKayDaConfigurationException>();
        exception.Which.AggregatedFailures.Should().ContainSingle(f => f.Code == "signing.file_signing.invalid_pem");
        exception.Which.Message.Should().Contain(path);
    }

    [Fact]
    public async Task CreateSignerAsync_throws_when_the_separately_registered_key_file_has_invalid_PEM_content()
    {
        var ct = TestContext.Current.CancellationToken;
        using var tempDir = new TempSigningKeyDirectory();
        using var certificate = CreateRsaCertificate();
        var certPath = tempDir.WriteCertificateOnlyPemFile("cert.crt", certificate);
        var keyPath = tempDir.WriteTextFile("key.pem", "-----BEGIN PRIVATE KEY-----\nnot base64\n-----END PRIVATE KEY-----");
        var sut = BuildSource(new PemSigningFile(certPath, keyPath));
        var keySet = await sut.ReadAsync(ct);

        var act = async () => await sut.CreateSignerAsync(keySet.SigningKey.Id, ct);

        var exception = await act.Should().ThrowAsync<ZeeKayDaConfigurationException>();
        exception.Which.AggregatedFailures.Should().ContainSingle(f => f.Code == "signing.file_signing.invalid_pem");
        exception.Which.Message.Should().Contain(certPath).And.Contain(keyPath);
    }

    // ── Permission enforcement ───────────────────────────────────────────────────────────────────

    [Fact]
    public async Task ReadAsync_throws_when_the_file_is_broader_than_0600_on_Unix()
    {
        Assert.SkipWhen(OperatingSystem.IsWindows(), "0600-mode enforcement is the Unix permission model.");

        var ct = TestContext.Current.CancellationToken;
        using var tempDir = new TempSigningKeyDirectory();
        using var certificate = CreateRsaCertificate();
        var path = tempDir.WritePemFile("current.pem", certificate);
        tempDir.MakeTooPermissive(path);
        var sut = BuildSource(new PemSigningFile(path));

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
        var path = tempDir.WritePemFile("current.pem", certificate);
        tempDir.MakeTooPermissive(path);
        var sut = BuildSource(new PemSigningFile(path));

        var act = async () => await sut.ReadAsync(ct);

        (await act.Should().ThrowAsync<ZeeKayDaConfigurationException>())
            .Which.AggregatedFailures.Should().ContainSingle(f => f.Code == "signing.file_signing.file_too_permissive");
    }

    [Fact]
    public async Task ReadAsync_succeeds_when_the_file_is_secured_to_the_current_identity()
    {
        // Positive counterpart to the two permission tests above: proves the default fixture output
        // (what a correctly-configured operator deployment looks like) is accepted on every OS.
        var ct = TestContext.Current.CancellationToken;
        using var tempDir = new TempSigningKeyDirectory();
        using var certificate = CreateRsaCertificate();
        var path = tempDir.WritePemFile("current.pem", certificate);
        var sut = BuildSource(new PemSigningFile(path));

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
        var previousPath = tempDir.WritePemFile("previous.pem", previousCertificate);
        var currentPath = tempDir.WritePemFile("current.pem", currentCertificate);
        tempDir.MakeTooPermissive(previousPath);
        var sut = BuildSource(new PemSigningFile(currentPath), previous: new PemCertificateFile(previousPath));

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
        var realPath = tempDir.WritePemFile("real.pem", certificate);
        var symlinkPath = tempDir.GetPath("link.pem");

        try
        {
            File.CreateSymbolicLink(symlinkPath, realPath);
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            Assert.Skip("Creating a symlink requires elevated privileges/Developer Mode on this platform.");
            return;
        }

        var sut = BuildSource(new PemSigningFile(symlinkPath));

        var act = async () => await sut.ReadAsync(ct);

        (await act.Should().ThrowAsync<ZeeKayDaConfigurationException>())
            .Which.AggregatedFailures.Should().ContainSingle(f => f.Code == "signing.file_signing.symlink_detected");
    }

    // ── Split cert/key files ─────────────────────────────────────────────────────────────────────

    [Fact]
    public async Task ReadAsync_reads_the_certificate_from_a_separate_cert_file()
    {
        var ct = TestContext.Current.CancellationToken;
        using var tempDir = new TempSigningKeyDirectory();
        using var certificate = CreateRsaCertificate();
        var certPath = tempDir.WriteCertificateOnlyPemFile("cert.crt", certificate);
        var keyPath = tempDir.WriteKeyOnlyPemFile("key.pem", certificate);
        var sut = BuildSource(new PemSigningFile(certPath, keyPath));

        var keySet = await sut.ReadAsync(ct);

        keySet.SigningKey.Id.Should().Be(new SourceKeyId(certPath), "the certificate path identifies the slot");
        keySet.SigningKey.PublicKey.RsaPublicParameters.Should().NotBeNull();
    }

    [Fact]
    public async Task CreateSignerAsync_signs_with_the_private_key_from_the_separate_key_file()
    {
        var ct = TestContext.Current.CancellationToken;
        using var tempDir = new TempSigningKeyDirectory();
        using var certificate = CreateRsaCertificate();
        var certPath = tempDir.WriteCertificateOnlyPemFile("cert.crt", certificate);
        var keyPath = tempDir.WriteKeyOnlyPemFile("key.pem", certificate);
        var sut = BuildSource(new PemSigningFile(certPath, keyPath));
        var keySet = await sut.ReadAsync(ct);

        using var signer = await sut.CreateSignerAsync(keySet.SigningKey.Id, ct);
        var signingInput = "header.payload"u8.ToArray();
        var signature = await signer.SignAsync(signingInput, ct);

        using var rsa = RSA.Create(keySet.SigningKey.PublicKey.RsaPublicParameters!.Value);
        rsa.VerifyData(signingInput, signature.Span, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1)
            .Should().BeTrue();
    }

    [Fact]
    public async Task CreateSignerAsync_throws_when_the_separate_key_file_is_broader_than_0600_on_Unix()
    {
        Assert.SkipWhen(OperatingSystem.IsWindows(), "0600-mode enforcement is the Unix permission model.");

        var ct = TestContext.Current.CancellationToken;
        using var tempDir = new TempSigningKeyDirectory();
        using var certificate = CreateRsaCertificate();
        var certPath = tempDir.WriteCertificateOnlyPemFile("cert.crt", certificate);
        var keyPath = tempDir.WriteKeyOnlyPemFile("key.pem", certificate);
        tempDir.MakeTooPermissive(keyPath);
        var sut = BuildSource(new PemSigningFile(certPath, keyPath));
        var keySet = await sut.ReadAsync(ct);

        var act = async () => await sut.CreateSignerAsync(keySet.SigningKey.Id, ct);

        (await act.Should().ThrowAsync<ZeeKayDaConfigurationException>())
            .Which.AggregatedFailures.Should().ContainSingle(f => f.Code == "signing.file_signing.file_too_permissive");
    }

    [Fact]
    public async Task CreateSignerAsync_throws_when_the_separate_key_files_ACL_grants_a_broad_principal_on_Windows()
    {
        Assert.SkipUnless(OperatingSystem.IsWindows(), "broad-principal ACL enforcement is the Windows permission model.");

        var ct = TestContext.Current.CancellationToken;
        using var tempDir = new TempSigningKeyDirectory();
        using var certificate = CreateRsaCertificate();
        var certPath = tempDir.WriteCertificateOnlyPemFile("cert.crt", certificate);
        var keyPath = tempDir.WriteKeyOnlyPemFile("key.pem", certificate);
        tempDir.MakeTooPermissive(keyPath);
        var sut = BuildSource(new PemSigningFile(certPath, keyPath));
        var keySet = await sut.ReadAsync(ct);

        var act = async () => await sut.CreateSignerAsync(keySet.SigningKey.Id, ct);

        (await act.Should().ThrowAsync<ZeeKayDaConfigurationException>())
            .Which.AggregatedFailures.Should().ContainSingle(f => f.Code == "signing.file_signing.file_too_permissive");
    }

    [Fact]
    public async Task CreateSignerAsync_throws_when_the_separate_key_file_does_not_exist()
    {
        var ct = TestContext.Current.CancellationToken;
        using var tempDir = new TempSigningKeyDirectory();
        using var certificate = CreateRsaCertificate();
        var certPath = tempDir.WriteCertificateOnlyPemFile("cert.crt", certificate);
        var missingKeyPath = tempDir.GetPath("does-not-exist.key");
        var sut = BuildSource(new PemSigningFile(certPath, missingKeyPath));
        var keySet = await sut.ReadAsync(ct);

        var act = async () => await sut.CreateSignerAsync(keySet.SigningKey.Id, ct);

        var exception = await act.Should().ThrowAsync<ZeeKayDaConfigurationException>();
        exception.Which.AggregatedFailures.Should().ContainSingle(f => f.Code == "signing.file_signing.file_not_found");
        exception.Which.Message.Should().Contain(missingKeyPath);
    }

    [Fact]
    public async Task ReadAsync_succeeds_even_when_the_Currents_separate_key_file_is_missing()
    {
        // Least privilege: building the published key set must never require private material, not
        // even for the slot that signs.
        var ct = TestContext.Current.CancellationToken;
        using var tempDir = new TempSigningKeyDirectory();
        using var certificate = CreateRsaCertificate();
        var certPath = tempDir.WriteCertificateOnlyPemFile("cert.crt", certificate);
        var sut = BuildSource(new PemSigningFile(certPath, tempDir.GetPath("does-not-exist.key")));

        var keySet = await sut.ReadAsync(ct);

        keySet.SigningKey.PublicKey.RsaPublicParameters.Should().NotBeNull();
    }

    // ── EC certificates ──────────────────────────────────────────────────────────────────────────

    [Fact]
    public async Task ReadAsync_supports_EC_certificates_with_a_matching_EC_algorithm()
    {
        var ct = TestContext.Current.CancellationToken;
        using var tempDir = new TempSigningKeyDirectory();
        using var certificate = TestCertificateFactory.CreateEcSelfSigned("ec-test", T0 - TimeSpan.FromDays(1), T0 + TimeSpan.FromDays(365));
        var path = tempDir.WritePemFile("current.pem", certificate);
        var sut = BuildSource(new PemSigningFile(path), algorithm: SigningAlgorithm.ES256);

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
        var path = tempDir.WritePemFile("current.pem", certificate);
        var sut = BuildSource(new PemSigningFile(path), algorithm: SigningAlgorithm.ES256);
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
        // is the file path, so the failure still names the offending file.
        var ct = TestContext.Current.CancellationToken;
        using var tempDir = new TempSigningKeyDirectory();
        using var certificate = CreateRsaCertificate();
        var path = tempDir.WritePemFile("current.pem", certificate);
        var sut = BuildSource(new PemSigningFile(path), algorithm: SigningAlgorithm.ES256);

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
        var path = tempDir.WritePemFile("current.pem", certificate);
        var sut = BuildSource(new PemSigningFile(path));

        var act = async () => await sut.CreateSignerAsync(new SourceKeyId("not-a-configured-file"), ct);

        await act.Should().ThrowAsync<InvalidOperationException>();
    }

    [Fact]
    public async Task CreateSignerAsync_throws_when_called_for_the_Previous_slot()
    {
        // Previous is published, never signed with. Honouring this call would read a private key
        // this source otherwise never opens.
        var ct = TestContext.Current.CancellationToken;
        using var tempDir = new TempSigningKeyDirectory();
        using var previousCertificate = CreateRsaCertificate();
        using var currentCertificate = CreateRsaCertificate();
        var previousPath = tempDir.WritePemFile("previous.pem", previousCertificate);
        var currentPath = tempDir.WritePemFile("current.pem", currentCertificate);
        var sut = BuildSource(new PemSigningFile(currentPath), previous: new PemCertificateFile(previousPath));

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
        var currentPath = tempDir.WritePemFile("current.pem", currentCertificate);
        var nextPath = tempDir.WritePemFile("next.pem", nextCertificate);
        var sut = BuildSource(new PemSigningFile(currentPath), next: new PemCertificateFile(nextPath));

        var act = async () => await sut.CreateSignerAsync(new SourceKeyId(nextPath), ct);

        await act.Should().ThrowAsync<InvalidOperationException>();
    }
}
