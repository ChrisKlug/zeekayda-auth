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
/// The source holds no cache and no lock: every <c>ReadAsync</c> re-reads the files from disk, so a
/// replaced or deleted file is observed on the next read. Which key signs is decided by the core from
/// each listed key's validity window, never by this source, so it holds no <c>TimeProvider</c>.
/// </remarks>
public sealed class PemFileSigningKeySourceTests
{
    private static readonly DateTimeOffset T0 = DateTimeOffset.Parse("2026-01-01T00:00:00Z");

    private static PemFileSigningKeySource BuildSource(
        PemSigningFile file,
        SigningAlgorithm algorithm = SigningAlgorithm.RS256) =>
        BuildSource([file], algorithm);

    private static PemFileSigningKeySource BuildSource(
        IEnumerable<PemSigningFile> files,
        SigningAlgorithm algorithm = SigningAlgorithm.RS256)
    {
        var options = new PemFileSigningOptions { Algorithm = algorithm };
        foreach (var file in files)
            options.Files.Add(file);

        return new PemFileSigningKeySource(
            Options.Create(options),
            new FileSigningKeyReader(NullSanitizingLogger<FileSigningKeyReader>.Instance));
    }

    private static X509Certificate2 CreateRsaCertificate() =>
        TestCertificateFactory.CreateRsaSelfSigned("test", T0 - TimeSpan.FromDays(1), T0 + TimeSpan.FromDays(365));

    /// <summary>
    /// A DSA self-signed certificate (openssl-generated, valid for a century) — a key type this
    /// library deliberately refuses to sign with. Checked in as text because
    /// <see cref="System.Security.Cryptography.X509Certificates.CertificateRequest"/> can only
    /// produce RSA and ECDSA certificates, so the shape cannot be generated at test run time.
    /// </summary>
    private const string DsaCertificatePem = """
        -----BEGIN CERTIFICATE-----
        MIIElTCCBEKgAwIBAgIUZ/wI0gCPxUhIqWpdcLL3roeD0IwwCwYJYIZIAWUDBAMC
        MCwxKjAoBgNVBAMMIXprZGEtdW5zdXBwb3J0ZWQta2V5LXR5cGUtZml4dHVyZTAg
        Fw0yNjA4MjcxNzU5MzBaGA8yMTI2MDgwMzE3NTkzMFowLDEqMCgGA1UEAwwhemtk
        YS11bnN1cHBvcnRlZC1rZXktdHlwZS1maXh0dXJlMIIDQzCCAjYGByqGSM44BAEw
        ggIpAoIBAQDv6fOMTzPI5adGpTaFuWakccaXuc6SQtlB3bUhfyf662ZemTmWo/Ls
        3EUVGAzZFdbouNuTSHPVxbD5OI85TD1c5z2ne/dE5Wd+2jyKUrN0ZYWhWHCPz7dQ
        vNaiiWAm+JX+ndXNuVSL+TwotwnhLd2z8dTTEIbr2ywL09vsw/8N55//P0mfY/kY
        nWUVCAOqR6hVbjPAvGqtWrYpIVIBVZ9f37mI39cXI1aJXE5gYFigYJMYghHzEMvE
        4WkrlA28TBCqskKFKYw/o2Idp4hxpIsYZ53VK6NrAk74qh92haWokXErgzjVCgoB
        qQTSeM92s4FslzPeWYFyd4KPH6rX5GvHAh0AwrOMBSMLQp0cPVC0h6EFROtpKVLb
        GwDFPgVVzQKCAQEAyfeCNUlrPEfGR4jc7Aep4akKdozKFqVzT+DxW0acdFJ1Oe7M
        zZNButmzw8z6fdotWGt7u9KgmYX9wcs4Zvl2bEIxU5mAba3bPggdgfots+sM9aq6
        DOt168/lWBX5PbsbUweM8u3jEIONaYsYlw6AMhPCR2gtd8vOlA7KnUGA+W6h+5Qp
        bUW7yPIymXDRhw/ihe5iqEcltQAUL24YFtIErcYmxZeQdkziaAHkUclAUtfuKI16
        XaNllYfdwr/Kjrmff+GFkxjk4YCSV3I5ANJ7UGFhm7Acabgaf/4y407SDwNMQ0NM
        U/fMDLFMu5beccxX7egLZyxy2EpKLJqKolkUyAOCAQUAAoIBAA0qFz942DK40Yk5
        7yhG8j6oWorxtE3oSFTgJ+moEEyPKUu4M2AO7yFL3RNOLWU59RU0kNCQTyDV7get
        Q2eTHDbaTYADVzw5FiuBY3jTO6s2VrIMJSXveAmO5NVWU8VmNdek944Ymuu5BUg6
        7wMqAEzHGu79jHrCmYry9KycvkmEic8qhQceuMseNLjNvf9IlpkRgnXc8tp7r7Kq
        3MGQ3m6ec+J4jE0FNoYVHEL+5lpnSFKoW1EyG2QBSAbThMIH9s/HI4u6F2KeAc6n
        q/IFESvn7yrKp+BJr3QydVxrzgit0+1l94t7KmbbNAgeKhQDM4vhM8eCooomwqz8
        MaWVUXGjUzBRMB0GA1UdDgQWBBRvM48hp1aJB/YXYSgVzu9fTu+CKDAfBgNVHSME
        GDAWgBRvM48hp1aJB/YXYSgVzu9fTu+CKDAPBgNVHRMBAf8EBTADAQH/MAsGCWCG
        SAFlAwQDAgNAADA9AhxsR8W1AJ9rSGQb2fZfbBlYHTFK/ezeh6wP4+9GAh0AiqnN
        nAJCNS2zwuZjpqaLnkmix9MkXCghY7eGuQ==
        -----END CERTIFICATE-----
        """;

    // ── Unsupported key types ────────────────────────────────────────────────────────────────────

    [Fact]
    public async Task ReadAsync_rejects_a_certificate_whose_key_is_neither_RSA_nor_EC()
    {
        Assert.SkipWhen(OperatingSystem.IsWindows(), "Windows' certificate stack may refuse to load a DSA certificate at all, which would surface as invalid_pem before the key-type check is reached.");

        var ct = TestContext.Current.CancellationToken;
        using var tempDir = new TempSigningKeyDirectory();
        var path = tempDir.WriteTextFile("dsa.pem", DsaCertificatePem);
        var sut = BuildSource(new PemSigningFile(path, tempDir.WriteTextFile("dsa.key", "unread")));

        var act = () => sut.ReadAsync(ct);

        var exception = await act.Should().ThrowAsync<ZeeKayDaConfigurationException>(
            "a key type the signing pipeline cannot sign with must be rejected at read time, not when the first token is issued");
        exception.Which.AggregatedFailures.Should().ContainSingle(
            f => f.Code == "signing.certificate.unsupported_key_type");
    }

    // ── Happy path ───────────────────────────────────────────────────────────────────────────────

    [Fact]
    public async Task ReadAsync_reports_the_listed_certificates_public_key()
    {
        var ct = TestContext.Current.CancellationToken;
        using var tempDir = new TempSigningKeyDirectory();
        using var certificate = CreateRsaCertificate();
        var path = tempDir.WritePemFile("current.pem", certificate);
        var sut = BuildSource(new PemSigningFile(path));

        var keySet = await sut.ReadAsync(ct);

        keySet.Should().ContainSingle();
        keySet.Single().Id.Should().Be(new SourceKeyId(path));
        keySet.Single().Algorithm.Should().Be(SigningAlgorithm.RS256);
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
        var path = tempDir.WritePemFile("current.pem", certificate);
        var sut = BuildSource(new PemSigningFile(path));

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
        var path = tempDir.WritePemFile("current.pem", certificate);
        var sut = BuildSource(new PemSigningFile(path));
        var keySet = await sut.ReadAsync(ct);

        using var signer = await sut.CreateSignerAsync(keySet.Single().Id, ct);
        var signingInput = "header.payload"u8.ToArray();
        var signature = await signer.SignAsync(signingInput, ct);

        using var rsa = RSA.Create(keySet.Single().PublicKey.RsaPublicParameters!.Value);
        rsa.VerifyData(signingInput, signature.Span, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1)
            .Should().BeTrue("the signer must be opened over the same key pair the read reported");
    }

    // ── Several listed files ─────────────────────────────────────────────────────────────────────

    [Fact]
    public async Task ReadAsync_lists_every_configured_file()
    {
        var ct = TestContext.Current.CancellationToken;
        using var tempDir = new TempSigningKeyDirectory();
        using var firstCertificate = CreateRsaCertificate();
        using var secondCertificate = CreateRsaCertificate();
        using var thirdCertificate = CreateRsaCertificate();
        var firstPath = tempDir.WritePemFile("first.pem", firstCertificate);
        var secondPath = tempDir.WritePemFile("second.pem", secondCertificate);
        var thirdPath = tempDir.WritePemFile("third.pem", thirdCertificate);
        var sut = BuildSource(
            [new PemSigningFile(firstPath), new PemSigningFile(secondPath), new PemSigningFile(thirdPath)]);

        var keySet = await sut.ReadAsync(ct);

        keySet.Select(k => k.Id.Value).Should().BeEquivalentTo([firstPath, secondPath, thirdPath]);
    }

    [Fact]
    public async Task ReadAsync_never_parses_a_separate_key_file_for_any_listed_file()
    {
        // Listing needs only public material: the key files named here hold no PEM at all, and the
        // read still succeeds for every file.
        var ct = TestContext.Current.CancellationToken;
        using var tempDir = new TempSigningKeyDirectory();
        using var firstCertificate = CreateRsaCertificate();
        using var secondCertificate = CreateRsaCertificate();
        var firstPath = tempDir.WriteCertificateOnlyPemFile("first.crt", firstCertificate);
        var secondPath = tempDir.WriteCertificateOnlyPemFile("second.crt", secondCertificate);
        var sut = BuildSource(
        [
            new PemSigningFile(firstPath, tempDir.WriteTextFile("first.key", "not a key")),
            new PemSigningFile(secondPath, tempDir.WriteTextFile("second.key", "not a key")),
        ]);

        var keySet = await sut.ReadAsync(ct);

        keySet.Should().HaveCount(2);
    }

    // ── Every read hits the disk ─────────────────────────────────────────────────────────────────

    [Fact]
    public async Task ReadAsync_throws_after_a_listed_file_is_deleted()
    {
        var ct = TestContext.Current.CancellationToken;
        using var tempDir = new TempSigningKeyDirectory();
        using var certificate = CreateRsaCertificate();
        var path = tempDir.WritePemFile("current.pem", certificate);
        var sut = BuildSource(new PemSigningFile(path));
        await sut.ReadAsync(ct);
        File.Delete(path);

        var act = async () => await sut.ReadAsync(ct);

        (await act.Should().ThrowAsync<ZeeKayDaConfigurationException>())
            .Which.AggregatedFailures.Should().ContainSingle(f => f.Code == "signing.file_signing.file_not_found");
    }

    [Fact]
    public async Task ReadAsync_observes_a_replaced_file_on_the_next_read()
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

        second.Single().PublicKey.RsaPublicParameters!.Value.Modulus
            .Should().Equal(replacement.GetRSAPublicKey()!.ExportParameters(false).Modulus)
            .And.NotEqual(first.Single().PublicKey.RsaPublicParameters!.Value.Modulus);
    }

    // ── Missing and invalid files ────────────────────────────────────────────────────────────────

    [Fact]
    public async Task ReadAsync_throws_when_a_listed_file_does_not_exist()
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

        var act = async () => await sut.CreateSignerAsync(keySet.Single().Id, ct);

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
    public async Task ReadAsync_enforces_permissions_on_every_listed_file()
    {
        Assert.SkipWhen(OperatingSystem.IsWindows(), "0600-mode enforcement is the Unix permission model.");

        var ct = TestContext.Current.CancellationToken;
        using var tempDir = new TempSigningKeyDirectory();
        using var previousCertificate = CreateRsaCertificate();
        using var currentCertificate = CreateRsaCertificate();
        var previousPath = tempDir.WritePemFile("previous.pem", previousCertificate);
        var currentPath = tempDir.WritePemFile("current.pem", currentCertificate);
        tempDir.MakeTooPermissive(previousPath);
        var sut = BuildSource([new PemSigningFile(currentPath), new PemSigningFile(previousPath)]);

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

        keySet.Single().Id.Should().Be(new SourceKeyId(certPath), "the certificate path identifies the file");
        keySet.Single().PublicKey.RsaPublicParameters.Should().NotBeNull();
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

        using var signer = await sut.CreateSignerAsync(keySet.Single().Id, ct);
        var signingInput = "header.payload"u8.ToArray();
        var signature = await signer.SignAsync(signingInput, ct);

        using var rsa = RSA.Create(keySet.Single().PublicKey.RsaPublicParameters!.Value);
        rsa.VerifyData(signingInput, signature.Span, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1)
            .Should().BeTrue();
    }

    [Fact]
    public async Task ReadAsync_rejects_a_separate_key_file_broader_than_0600_on_Unix_even_for_a_file_that_does_not_sign()
    {
        // The staged file never signs at this read, but its public key is published, so a readable
        // private key would let anyone forge tokens that verify.
        Assert.SkipWhen(OperatingSystem.IsWindows(), "0600-mode enforcement is the Unix permission model.");

        var ct = TestContext.Current.CancellationToken;
        using var tempDir = new TempSigningKeyDirectory();
        using var incumbent = CreateRsaCertificate();
        using var staged = CreateRsaCertificate();
        var incumbentPath = tempDir.WritePemFile("incumbent.pem", incumbent);
        var stagedPath = tempDir.WriteCertificateOnlyPemFile("staged.crt", staged);
        var stagedKeyPath = tempDir.WriteKeyOnlyPemFile("staged.key", staged);
        tempDir.MakeTooPermissive(stagedKeyPath);
        var sut = BuildSource([new PemSigningFile(incumbentPath), new PemSigningFile(stagedPath, stagedKeyPath)]);

        var act = async () => await sut.ReadAsync(ct);

        (await act.Should().ThrowAsync<ZeeKayDaConfigurationException>())
            .Which.AggregatedFailures.Should().ContainSingle(f => f.Code == "signing.file_signing.file_too_permissive");
    }

    [Fact]
    public async Task ReadAsync_rejects_a_separate_key_files_ACL_granting_a_broad_principal_on_Windows_even_for_a_file_that_does_not_sign()
    {
        Assert.SkipUnless(OperatingSystem.IsWindows(), "broad-principal ACL enforcement is the Windows permission model.");

        var ct = TestContext.Current.CancellationToken;
        using var tempDir = new TempSigningKeyDirectory();
        using var incumbent = CreateRsaCertificate();
        using var staged = CreateRsaCertificate();
        var incumbentPath = tempDir.WritePemFile("incumbent.pem", incumbent);
        var stagedPath = tempDir.WriteCertificateOnlyPemFile("staged.crt", staged);
        var stagedKeyPath = tempDir.WriteKeyOnlyPemFile("staged.key", staged);
        tempDir.MakeTooPermissive(stagedKeyPath);
        var sut = BuildSource([new PemSigningFile(incumbentPath), new PemSigningFile(stagedPath, stagedKeyPath)]);

        var act = async () => await sut.ReadAsync(ct);

        (await act.Should().ThrowAsync<ZeeKayDaConfigurationException>())
            .Which.AggregatedFailures.Should().ContainSingle(f => f.Code == "signing.file_signing.file_too_permissive");
    }

    [Fact]
    public async Task ReadAsync_rejects_a_combined_file_that_carries_no_private_key_block()
    {
        // No KeyPath, so the file itself must carry the key; it is checked for a key block without
        // the key being parsed.
        var ct = TestContext.Current.CancellationToken;
        using var tempDir = new TempSigningKeyDirectory();
        using var certificate = CreateRsaCertificate();
        var path = tempDir.WriteCertificateOnlyPemFile("cert-only.pem", certificate);
        var sut = BuildSource(new PemSigningFile(path));

        var act = async () => await sut.ReadAsync(ct);

        var exception = await act.Should().ThrowAsync<ZeeKayDaConfigurationException>();
        exception.Which.AggregatedFailures.Should().ContainSingle(f => f.Code == "signing.certificate.private_key_not_found");
        exception.Which.Message.Should().Contain(path);
    }

    [Fact]
    public async Task ReadAsync_rejects_a_combined_file_whose_only_key_block_is_encrypted()
    {
        // An encrypted key block cannot be imported, so the file could never sign.
        var ct = TestContext.Current.CancellationToken;
        using var tempDir = new TempSigningKeyDirectory();
        using var certificate = CreateRsaCertificate();
        using var key = certificate.GetRSAPrivateKey()!;
        var encryptedKey = key.ExportEncryptedPkcs8PrivateKeyPem(
            "password", new PbeParameters(PbeEncryptionAlgorithm.Aes256Cbc, HashAlgorithmName.SHA256, 100_000));
        var path = tempDir.WriteTextFile("encrypted.pem", certificate.ExportCertificatePem() + "\n" + encryptedKey);
        var sut = BuildSource(new PemSigningFile(path));

        var act = async () => await sut.ReadAsync(ct);

        (await act.Should().ThrowAsync<ZeeKayDaConfigurationException>())
            .Which.AggregatedFailures.Should().ContainSingle(f => f.Code == "signing.certificate.private_key_not_found");
    }

    [Fact]
    public async Task ReadAsync_rejects_a_combined_file_whose_key_block_is_truncated()
    {
        // The header alone is not a key: only a complete block counts, so a file that could never
        // sign fails now rather than at the restart that chooses it.
        var ct = TestContext.Current.CancellationToken;
        using var tempDir = new TempSigningKeyDirectory();
        using var certificate = CreateRsaCertificate();
        var path = tempDir.WriteTextFile(
            "truncated.pem", certificate.ExportCertificatePem() + "\n-----BEGIN PRIVATE KEY-----\nMIIE\n");
        var sut = BuildSource(new PemSigningFile(path));

        var act = async () => await sut.ReadAsync(ct);

        (await act.Should().ThrowAsync<ZeeKayDaConfigurationException>())
            .Which.AggregatedFailures.Should().ContainSingle(f => f.Code == "signing.certificate.private_key_not_found");
    }

    [Fact]
    public async Task ReadAsync_rejects_a_listed_file_whose_separate_key_file_does_not_exist()
    {
        var ct = TestContext.Current.CancellationToken;
        using var tempDir = new TempSigningKeyDirectory();
        using var certificate = CreateRsaCertificate();
        var certPath = tempDir.WriteCertificateOnlyPemFile("cert.crt", certificate);
        var missingKeyPath = tempDir.GetPath("does-not-exist.key");
        var sut = BuildSource(new PemSigningFile(certPath, missingKeyPath));

        var act = async () => await sut.ReadAsync(ct);

        var exception = await act.Should().ThrowAsync<ZeeKayDaConfigurationException>();
        exception.Which.AggregatedFailures.Should().ContainSingle(f => f.Code == "signing.file_signing.file_not_found");
        exception.Which.Message.Should().Contain(missingKeyPath);
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

        keySet.Single().PublicKey.KeyType.Should().Be(SigningKeyType.Ec);
        keySet.Single().PublicKey.EcPublicParameters.Should().NotBeNull();
        keySet.Single().Algorithm.Should().Be(SigningAlgorithm.ES256);
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

        using var signer = await sut.CreateSignerAsync(keySet.Single().Id, ct);
        var signingInput = "header.payload"u8.ToArray();
        var signature = await signer.SignAsync(signingInput, ct);

        using var ecdsa = ECDsa.Create(keySet.Single().PublicKey.EcPublicParameters!.Value);
        ecdsa.VerifyData(signingInput, signature.Span, HashAlgorithmName.SHA256).Should().BeTrue();
    }

    [Fact]
    public async Task ReadAsync_rejects_a_certificate_whose_key_does_not_suit_the_algorithm_naming_the_file()
    {
        var ct = TestContext.Current.CancellationToken;
        using var tempDir = new TempSigningKeyDirectory();
        using var certificate = CreateRsaCertificate();
        var path = tempDir.WritePemFile("current.pem", certificate);
        var sut = BuildSource(new PemSigningFile(path), algorithm: SigningAlgorithm.ES256);

        var act = async () => await sut.ReadAsync(ct);

        var exception = await act.Should().ThrowAsync<ZeeKayDaConfigurationException>();
        exception.Which.AggregatedFailures.Should().ContainSingle(f => f.Code == "signing.key_algorithm_mismatch");
        exception.Which.Message.Should().Contain(path);
    }

    // ── CreateSignerAsync opens any listed file, and only a listed one ───────────────────────────

    [Fact]
    public async Task CreateSignerAsync_throws_when_called_for_a_key_id_that_is_not_listed()
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
    public async Task CreateSignerAsync_throws_for_a_file_that_exists_on_disk_but_is_not_listed()
    {
        var ct = TestContext.Current.CancellationToken;
        using var tempDir = new TempSigningKeyDirectory();
        using var listedCertificate = CreateRsaCertificate();
        using var otherCertificate = CreateRsaCertificate();
        var listedPath = tempDir.WritePemFile("listed.pem", listedCertificate);
        var otherPath = tempDir.WritePemFile("other.pem", otherCertificate);
        var sut = BuildSource(new PemSigningFile(listedPath));

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
        var firstPath = tempDir.WritePemFile("first.pem", firstCertificate);
        var secondPath = tempDir.WritePemFile("second.pem", secondCertificate);
        var sut = BuildSource([new PemSigningFile(firstPath), new PemSigningFile(secondPath)]);
        var signingInput = "header.payload"u8.ToArray();

        using var signer = await sut.CreateSignerAsync(new SourceKeyId(secondPath), ct);
        var signature = await signer.SignAsync(signingInput, ct);

        secondCertificate.GetRSAPublicKey()!
            .VerifyData(signingInput, signature.Span, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1)
            .Should().BeTrue("the signer must be opened over the file whose path was asked for, not the first one");
    }

    // ── The failure message never repeats the parser's own text (#764) ───────────────────────────

    [Fact]
    public async Task ReadAsync_names_the_parser_exception_type_rather_than_copying_its_message()
    {
        var ct = TestContext.Current.CancellationToken;
        using var tempDir = new TempSigningKeyDirectory();
        var path = tempDir.WriteTextFile("garbage.pem", "not a pem file at all");
        var sut = BuildSource(new PemSigningFile(path));

        var act = async () => await sut.ReadAsync(ct);

        var exception = await act.Should().ThrowAsync<ZeeKayDaConfigurationException>();
        AssertNamesTypeWithoutCopyingMessage(exception.Which, "signing.file_signing.invalid_pem");
    }

    [Fact]
    public async Task CreateSignerAsync_names_the_parser_exception_type_rather_than_copying_its_message()
    {
        // The private-key path is the sharpest case: the text the parser failed on is key material.
        var ct = TestContext.Current.CancellationToken;
        using var tempDir = new TempSigningKeyDirectory();
        using var certificate = CreateRsaCertificate();
        var certPath = tempDir.WriteCertificateOnlyPemFile("cert.crt", certificate);
        var keyPath = tempDir.WriteTextFile("key.pem", "-----BEGIN PRIVATE KEY-----\nnot base64\n-----END PRIVATE KEY-----");
        var sut = BuildSource(new PemSigningFile(certPath, keyPath));
        var keySet = await sut.ReadAsync(ct);

        var act = async () => await sut.CreateSignerAsync(keySet.Single().Id, ct);

        var exception = await act.Should().ThrowAsync<ZeeKayDaConfigurationException>();
        AssertNamesTypeWithoutCopyingMessage(exception.Which, "signing.file_signing.invalid_pem");
    }

    /// <summary>
    /// Asserts the contract on <c>ZeeKayDaConfigurationFailure.Message</c>: it names the underlying
    /// exception's type, never repeats that exception's own message, and leaves the original
    /// reachable as the inner exception.
    /// </summary>
    private static void AssertNamesTypeWithoutCopyingMessage(
        ZeeKayDaConfigurationException exception, string expectedCode)
    {
        exception.InnerException.Should().NotBeNull();
        var cause = exception.InnerException!;

        var failure = exception.AggregatedFailures.Should()
            .ContainSingle(f => f.Code == expectedCode).Subject;

        failure.Message.Should().Contain(cause.GetType().FullName);
        failure.Message.Should().Contain("See the inner exception for the root cause.");
        cause.Message.Should().NotBeNullOrWhiteSpace();
        failure.Message.Should().NotContain(cause.Message);
    }
}
