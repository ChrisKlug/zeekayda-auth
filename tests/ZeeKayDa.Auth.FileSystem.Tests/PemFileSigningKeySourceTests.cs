using System.Runtime.Versioning;
using System.Security.AccessControl;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Microsoft.Extensions.Options;
using Microsoft.Extensions.Time.Testing;
using ZeeKayDa.Auth.FileSystem.Tests.Fixtures;
using ZeeKayDa.Auth.TestKit.Signing;
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
/// The source holds no lock, and every <c>ReadAsync</c> re-reads the files from disk, so a replaced or
/// deleted file is observed on the next read. Its one cache is which version of an encrypted key's files
/// last decrypted, so a password is checked again only when they change. Which key signs is decided by the core from
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
            new FileSigningKeyReader(TestSanitizingLogger.Create(NullLogger<FileSigningKeyReader>.Instance)));
    }

    /// <summary>
    /// A private key block whose label and base64 are well formed but whose content is not a key: listing
    /// accepts it on its label alone, and only a parse fails on it.
    /// </summary>
    private const string UnparseableKeyPem = "-----BEGIN PRIVATE KEY-----\nbm90IGEga2V5\n-----END PRIVATE KEY-----";

    private const string Password = "correct horse battery staple";

    /// <summary>
    /// A key in the legacy OpenSSL encrypted format. Only its header identifies the format, so the body
    /// need not be a real key.
    /// </summary>
    private const string LegacyEncryptedKeyPem = """
        -----BEGIN RSA PRIVATE KEY-----
        Proc-Type: 4,ENCRYPTED
        DEK-Info: AES-256-CBC,0123456789ABCDEF0123456789ABCDEF

        bm90IGEga2V5
        -----END RSA PRIVATE KEY-----
        """;

    private static string EncryptedKeyPem(X509Certificate2 certificate, string password = Password) =>
        EncryptedKeyPem(certificate, new PbeParameters(PbeEncryptionAlgorithm.Aes256Cbc, HashAlgorithmName.SHA256, 2048), password);

    private static string EncryptedKeyPem(X509Certificate2 certificate, PbeParameters parameters, string password = Password)
    {
        return certificate.GetRSAPrivateKey() is { } rsa
            ? rsa.ExportEncryptedPkcs8PrivateKeyPem(password, parameters)
            : certificate.GetECDsaPrivateKey()!.ExportEncryptedPkcs8PrivateKeyPem(password, parameters);
    }

    /// <summary>A password source that counts its calls and returns whatever <see cref="Value"/> is now.</summary>
    private sealed class PasswordSource(string value = Password)
    {
        public string Value { get; set; } = value;

        public int Calls { get; private set; }

        public Task<string> GetAsync(CancellationToken cancellationToken)
        {
            Calls++;
            return Task.FromResult(Value);
        }
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
        var sut = BuildSource(new PemSigningFile(path, tempDir.WriteTextFile("dsa.key", UnparseableKeyPem)));

        var listing = await sut.ReadAsync(ct);

        listing.ShouldReportOnly(path, "signing.certificate.unsupported_key_type");
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

        var keySet = (await sut.ReadAsync(ct)).Keys;

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
        var path = tempDir.WritePemFile("current.pem", certificate);
        var sut = BuildSource(new PemSigningFile(path));

        var keySet = (await sut.ReadAsync(ct)).Keys;

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
        var keySet = (await sut.ReadAsync(ct)).Keys;

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

        var keySet = (await sut.ReadAsync(ct)).Keys;

        keySet.Select(k => k.Id.Value).Should().BeEquivalentTo([firstPath, secondPath, thirdPath]);
    }

    [Fact]
    public async Task ReadAsync_reads_only_the_label_of_a_separate_key_file()
    {
        // Listing needs only public material: the key files named here carry a private key label over
        // content that is no key, and the read still succeeds for every file.
        var ct = TestContext.Current.CancellationToken;
        using var tempDir = new TempSigningKeyDirectory();
        using var firstCertificate = CreateRsaCertificate();
        using var secondCertificate = CreateRsaCertificate();
        var firstPath = tempDir.WriteCertificateOnlyPemFile("first.crt", firstCertificate);
        var secondPath = tempDir.WriteCertificateOnlyPemFile("second.crt", secondCertificate);
        var sut = BuildSource(
        [
            new PemSigningFile(firstPath, tempDir.WriteTextFile("first.key", UnparseableKeyPem)),
            new PemSigningFile(secondPath, tempDir.WriteTextFile("second.key", UnparseableKeyPem)),
        ]);

        var keySet = (await sut.ReadAsync(ct)).Keys;

        keySet.Should().HaveCount(2);
    }

    // ── Every read hits the disk ─────────────────────────────────────────────────────────────────

    [Fact]
    public async Task ReadAsync_no_longer_lists_a_deleted_file_so_deleting_it_revokes_the_key()
    {
        var ct = TestContext.Current.CancellationToken;
        using var tempDir = new TempSigningKeyDirectory();
        using var certificate = CreateRsaCertificate();
        var path = tempDir.WritePemFile("current.pem", certificate);
        var sut = BuildSource(new PemSigningFile(path));
        await sut.ReadAsync(ct);
        File.Delete(path);

        var keys = (await sut.ReadAsync(ct)).Keys;

        keys.Should().BeEmpty();
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

        var first = (await sut.ReadAsync(ct)).Keys;
        tempDir.WritePemFile("current.pem", replacement);
        var second = (await sut.ReadAsync(ct)).Keys;

        second.Single().PublicKey.RsaPublicParameters!.Value.Modulus
            .Should().Equal(replacement.GetRSAPublicKey()!.ExportParameters(false).Modulus)
            .And.NotEqual(first.Single().PublicKey.RsaPublicParameters!.Value.Modulus);
    }

    // ── Missing and invalid files ────────────────────────────────────────────────────────────────

    [Fact]
    public async Task ReadAsync_lists_nothing_for_a_listed_file_that_does_not_exist()
    {
        var ct = TestContext.Current.CancellationToken;
        using var tempDir = new TempSigningKeyDirectory();
        var missingPath = tempDir.GetPath("does-not-exist.pem");
        var sut = BuildSource(new PemSigningFile(missingPath));

        var keys = (await sut.ReadAsync(ct)).Keys;

        keys.Should().BeEmpty();
    }

    [Fact]
    public async Task ReadAsync_reports_invalid_PEM_content_as_a_per_entry_failure()
    {
        var ct = TestContext.Current.CancellationToken;
        using var tempDir = new TempSigningKeyDirectory();
        var path = tempDir.WriteTextFile("garbage.pem", "not a pem file at all");
        var sut = BuildSource(new PemSigningFile(path));

        var listing = await sut.ReadAsync(ct);

        var failure = listing.ShouldReportOnly(path, "signing.file_signing.invalid_pem");
        failure.Message.Should().Contain(path);
    }

    [Fact]
    public async Task CreateSignerAsync_throws_when_the_separately_registered_key_file_has_invalid_PEM_content()
    {
        var ct = TestContext.Current.CancellationToken;
        using var tempDir = new TempSigningKeyDirectory();
        using var certificate = CreateRsaCertificate();
        var certPath = tempDir.WriteCertificateOnlyPemFile("cert.crt", certificate);
        var keyPath = tempDir.WriteTextFile("key.pem", UnparseableKeyPem);
        var sut = BuildSource(new PemSigningFile(certPath, keyPath));
        var keySet = (await sut.ReadAsync(ct)).Keys;

        var act = async () => await sut.CreateSignerAsync(keySet.Single().Id, ct);

        var exception = await act.Should().ThrowAsync<ZeeKayDaConfigurationException>();
        exception.Which.AggregatedFailures.Should().ContainSingle(f => f.Code == "signing.file_signing.invalid_pem");
        exception.Which.Message.Should().Contain(certPath).And.Contain(keyPath);
    }

    // ── Permission enforcement ───────────────────────────────────────────────────────────────────

    [Fact]
    public async Task ReadAsync_reports_a_file_broader_than_0600_on_Unix_as_a_per_entry_failure()
    {
        Assert.SkipWhen(OperatingSystem.IsWindows(), "0600-mode enforcement is the Unix permission model.");

        var ct = TestContext.Current.CancellationToken;
        using var tempDir = new TempSigningKeyDirectory();
        using var certificate = CreateRsaCertificate();
        var path = tempDir.WritePemFile("current.pem", certificate);
        tempDir.MakeTooPermissive(path);
        var sut = BuildSource(new PemSigningFile(path));

        var listing = await sut.ReadAsync(ct);

        listing.ShouldReportOnly(path, "signing.file_signing.file_too_permissive");
    }

    [Fact]
    public async Task ReadAsync_reports_a_broad_principal_ACL_on_Windows_as_a_per_entry_failure()
    {
        Assert.SkipUnless(OperatingSystem.IsWindows(), "broad-principal ACL enforcement is the Windows permission model.");

        var ct = TestContext.Current.CancellationToken;
        using var tempDir = new TempSigningKeyDirectory();
        using var certificate = CreateRsaCertificate();
        var path = tempDir.WritePemFile("current.pem", certificate);
        tempDir.MakeTooPermissive(path);
        var sut = BuildSource(new PemSigningFile(path));

        var listing = await sut.ReadAsync(ct);

        listing.ShouldReportOnly(path, "signing.file_signing.file_too_permissive");
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

        var listing = await sut.ReadAsync(ct);

        listing.ShouldReportOnly(previousPath, "signing.file_signing.file_too_permissive");
    }

    [Fact]
    public async Task ReadAsync_reports_a_too_permissive_key_file_as_a_per_entry_failure_and_lists_the_rest()
    {
        Assert.SkipWhen(OperatingSystem.IsWindows(), "0600-mode enforcement is the Unix permission model.");

        var ct = TestContext.Current.CancellationToken;
        using var tempDir = new TempSigningKeyDirectory();
        using var goodCertificate = CreateRsaCertificate();
        using var brokenCertificate = CreateRsaCertificate();
        var goodPath = tempDir.WritePemFile("good.pem", goodCertificate);
        var brokenPath = tempDir.WritePemFile("broken.pem", brokenCertificate);
        tempDir.MakeTooPermissive(brokenPath);
        var sut = BuildSource([new PemSigningFile(goodPath), new PemSigningFile(brokenPath)]);

        var listing = await sut.ReadAsync(ct);

        listing.Keys.Select(k => k.Id).Should().Equal(new SourceKeyId(goodPath));
        listing.ShouldReportOnly(brokenPath, "signing.file_signing.file_too_permissive");
    }

    [Fact]
    public async Task ReadAsync_reports_a_certificate_whose_public_key_cannot_be_read_as_a_per_entry_failure_and_lists_the_rest()
    {
        var ct = TestContext.Current.CancellationToken;
        using var tempDir = new TempSigningKeyDirectory();
        using var goodCertificate = CreateRsaCertificate();
        using var malformed = CertificateWithMalformedRsaPublicKey();
        var goodPath = tempDir.WritePemFile("good.pem", goodCertificate);
        var brokenPath = tempDir.WriteCertificateOnlyPemFile("broken.crt", malformed);
        var brokenKeyPath = tempDir.WriteKeyOnlyPemFile("broken.key", goodCertificate);
        var sut = BuildSource([new PemSigningFile(goodPath), new PemSigningFile(brokenPath, brokenKeyPath)]);

        var listing = await sut.ReadAsync(ct);

        listing.Keys.Select(k => k.Id).Should().Equal(new SourceKeyId(goodPath));
        listing.ShouldReportOnly(brokenPath, "signing.certificate.invalid_public_key");
    }

    /// <summary>
    /// A certificate that parses but whose RSA key bytes are not an <c>RSAPublicKey</c>, so the
    /// failure comes from reading the public key, not from parsing the certificate.
    /// </summary>
    private static X509Certificate2 CertificateWithMalformedRsaPublicKey()
    {
        var malformed = new PublicKey(
            new Oid("1.2.840.113549.1.1.1"),
            parameters: new AsnEncodedData([0x05, 0x00]),
            keyValue: new AsnEncodedData([0x30, 0x03, 0x02, 0x01, 0x01]));
        var request = new CertificateRequest(new X500DistinguishedName("CN=test"), malformed, HashAlgorithmName.SHA256);
        using var issuerKey = RSA.Create(2048);
        var generator = X509SignatureGenerator.CreateForRSA(issuerKey, RSASignaturePadding.Pkcs1);
        return request.Create(
            new X500DistinguishedName("CN=issuer"), generator,
            DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddDays(30), serialNumber: [1, 2, 3, 4]);
    }

    // ── Symlink rejection ────────────────────────────────────────────────────────────────────────

    [Fact]
    public async Task ReadAsync_reports_a_symlinked_configured_path_as_a_per_entry_failure()
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

        var listing = await sut.ReadAsync(ct);

        listing.ShouldReportOnly(symlinkPath, "signing.file_signing.symlink_detected");
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

        var keySet = (await sut.ReadAsync(ct)).Keys;

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
        var keySet = (await sut.ReadAsync(ct)).Keys;

        using var signer = await sut.CreateSignerAsync(keySet.Single().Id, ct);
        var signingInput = "header.payload"u8.ToArray();
        var signature = await signer.SignAsync(signingInput, ct);

        using var rsa = RSA.Create(keySet.Single().PublicKey.RsaPublicParameters!.Value);
        rsa.VerifyData(signingInput, signature.Span, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1)
            .Should().BeTrue();
    }

    [Fact]
    public async Task ReadAsync_accepts_a_world_readable_certificate_only_file_beside_an_owner_only_key_file()
    {
        // certbot's layout: fullchain.pem is 0644, privkey.pem 0600. A certificate is public.
        Assert.SkipWhen(OperatingSystem.IsWindows(), "0644 is a Unix permission mode.");

        var ct = TestContext.Current.CancellationToken;
        using var tempDir = new TempSigningKeyDirectory();
        using var certificate = CreateRsaCertificate();
        var certPath = tempDir.WriteCertificateOnlyPemFile("fullchain.pem", certificate);
        var keyPath = tempDir.WriteKeyOnlyPemFile("privkey.pem", certificate);
        tempDir.SetUnixMode(certPath,
            UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.GroupRead | UnixFileMode.OtherRead);
        var sut = BuildSource(new PemSigningFile(certPath, keyPath));

        var listing = await sut.ReadAsync(ct);
        using var signer = await sut.CreateSignerAsync(listing.Keys.Single().Id, ct);

        listing.Failures.Should().BeEmpty();
        signer.Should().NotBeNull();
    }

    [Theory]
    [InlineData(UnixFileMode.GroupWrite)]
    [InlineData(UnixFileMode.OtherWrite)]
    public async Task ReadAsync_rejects_a_certificate_only_file_writable_by_group_or_other_on_Unix(UnixFileMode writeBit)
    {
        // Whoever can write the certificate file can publish their own key in the JWKS.
        Assert.SkipWhen(OperatingSystem.IsWindows(), "group/other write bits are the Unix permission model.");

        var ct = TestContext.Current.CancellationToken;
        using var tempDir = new TempSigningKeyDirectory();
        using var certificate = CreateRsaCertificate();
        var certPath = tempDir.WriteCertificateOnlyPemFile("cert.crt", certificate);
        var keyPath = tempDir.WriteKeyOnlyPemFile("key.pem", certificate);
        tempDir.SetUnixMode(certPath, UnixFileMode.UserRead | UnixFileMode.UserWrite | writeBit);
        var sut = BuildSource(new PemSigningFile(certPath, keyPath));

        var listing = await sut.ReadAsync(ct);

        listing.ShouldReportOnly(certPath, "signing.file_signing.file_too_permissive");
    }

    [Theory]
    [InlineData(FileSystemRights.Read)]
    [InlineData(FileSystemRights.ReadAndExecute)]
    [SupportedOSPlatform("windows")]
    public async Task ReadAsync_accepts_a_certificate_only_file_a_broad_principal_may_only_read_on_Windows(FileSystemRights rights)
    {
        Assert.SkipUnless(OperatingSystem.IsWindows(), "broad-principal ACL enforcement is the Windows permission model.");

        var ct = TestContext.Current.CancellationToken;
        using var tempDir = new TempSigningKeyDirectory();
        using var certificate = CreateRsaCertificate();
        var certPath = tempDir.WriteCertificateOnlyPemFile("cert.crt", certificate);
        var keyPath = tempDir.WriteKeyOnlyPemFile("key.pem", certificate);
        TempSigningKeyDirectory.GrantEveryoneWindows(certPath, rights);
        var sut = BuildSource(new PemSigningFile(certPath, keyPath));

        var listing = await sut.ReadAsync(ct);

        listing.Failures.Should().BeEmpty();
    }

    [Theory]
    [InlineData(FileSystemRights.WriteData)]
    [InlineData(FileSystemRights.AppendData)]
    [InlineData(FileSystemRights.Delete)]
    [InlineData(FileSystemRights.ChangePermissions)]
    [InlineData(FileSystemRights.TakeOwnership)]
    [SupportedOSPlatform("windows")]
    public async Task ReadAsync_rejects_a_certificate_only_file_a_broad_principal_may_write_or_take_over_on_Windows(FileSystemRights rights)
    {
        // Changing the ACL or taking ownership lets the holder grant themselves write, then publish their own key.
        Assert.SkipUnless(OperatingSystem.IsWindows(), "broad-principal ACL enforcement is the Windows permission model.");

        var ct = TestContext.Current.CancellationToken;
        using var tempDir = new TempSigningKeyDirectory();
        using var certificate = CreateRsaCertificate();
        var certPath = tempDir.WriteCertificateOnlyPemFile("cert.crt", certificate);
        var keyPath = tempDir.WriteKeyOnlyPemFile("key.pem", certificate);
        TempSigningKeyDirectory.GrantEveryoneWindows(certPath, rights);
        var sut = BuildSource(new PemSigningFile(certPath, keyPath));

        var listing = await sut.ReadAsync(ct);

        listing.ShouldReportOnly(certPath, "signing.file_signing.file_too_permissive");
    }

    [Fact]
    public async Task ReadAsync_rejects_a_private_key_in_a_certificate_only_file_without_a_password()
    {
        // A certificate-only file may be world-readable, so a key copy there would be readable by anyone.
        var ct = TestContext.Current.CancellationToken;
        using var tempDir = new TempSigningKeyDirectory();
        using var certificate = CreateRsaCertificate();
        var certPath = tempDir.WritePemFile("cert.pem", certificate);
        var keyPath = tempDir.WriteKeyOnlyPemFile("key.pem", certificate);
        var sut = BuildSource(new PemSigningFile(certPath, keyPath));

        var listing = await sut.ReadAsync(ct);

        listing.ShouldReportOnly(certPath, "signing.file_signing.private_key_in_certificate_file");
    }

    [Fact]
    public async Task ReadAsync_rejects_a_certificate_only_file_carrying_a_private_key_without_its_footer()
    {
        // A key that lost its END line when a combined file was split is still recoverable key material.
        var ct = TestContext.Current.CancellationToken;
        using var tempDir = new TempSigningKeyDirectory();
        using var certificate = CreateRsaCertificate();
        var keyPem = certificate.GetRSAPrivateKey()!.ExportPkcs8PrivateKeyPem();
        var withoutFooter = keyPem[..keyPem.IndexOf("-----END", StringComparison.Ordinal)];
        var certPath = tempDir.WriteTextFile("cert.pem", certificate.ExportCertificatePem() + "\n" + withoutFooter);
        var keyPath = tempDir.WriteKeyOnlyPemFile("key.pem", certificate);
        var sut = BuildSource(new PemSigningFile(certPath, keyPath));

        var listing = await sut.ReadAsync(ct);

        listing.ShouldReportOnly(certPath, "signing.file_signing.private_key_in_certificate_file");
    }

    [Fact]
    public async Task ReadAsync_rejects_a_chain_file_whose_first_certificate_issued_the_second()
    {
        // An X.509 v1 root carries no Basic Constraints, so only issuance shows it is the CA.
        var ct = TestContext.Current.CancellationToken;
        using var tempDir = new TempSigningKeyDirectory();
        var (root, leaf, leafKey) = CreateChain(rootIsMarkedCa: false);
        using (root)
        using (leaf)
        using (leafKey)
        {
            var certPath = tempDir.WriteTextFile("chain.pem", root.ExportCertificatePem() + "\n" + leaf.ExportCertificatePem());
            var keyPath = tempDir.WriteTextFile("key.pem", leafKey.ExportPkcs8PrivateKeyPem());
            var sut = BuildSource(new PemSigningFile(certPath, keyPath));

            var listing = await sut.ReadAsync(ct);

            listing.ShouldReportOnly(certPath, "signing.file_signing.certificate_is_a_ca");
        }
    }

    [Fact]
    public async Task CreateSignerAsync_reports_a_chain_reordered_root_first_after_listing_as_certificate_is_a_ca()
    {
        var ct = TestContext.Current.CancellationToken;
        using var tempDir = new TempSigningKeyDirectory();
        var (root, leaf, leafKey) = CreateChain(rootIsMarkedCa: true);
        using (root)
        using (leaf)
        using (leafKey)
        {
            var certPath = tempDir.WriteTextFile("chain.pem", leaf.ExportCertificatePem() + "\n" + root.ExportCertificatePem());
            var keyPath = tempDir.WriteTextFile("key.pem", leafKey.ExportPkcs8PrivateKeyPem());
            var sut = BuildSource(new PemSigningFile(certPath, keyPath));
            var id = (await sut.ReadAsync(ct)).Keys.Single().Id;
            tempDir.WriteTextFile("chain.pem", root.ExportCertificatePem() + "\n" + leaf.ExportCertificatePem());

            var act = async () => await sut.CreateSignerAsync(id, ct);

            (await act.Should().ThrowAsync<ZeeKayDaConfigurationException>())
                .Which.AggregatedFailures.Should().ContainSingle(f => f.Code == "signing.file_signing.certificate_is_a_ca");
        }
    }

    private static (X509Certificate2 Root, X509Certificate2 Leaf, RSA LeafKey) CreateChain(bool rootIsMarkedCa)
    {
        using var rootKey = RSA.Create(2048);
        var rootRequest = new CertificateRequest("CN=test-root", rootKey, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        if (rootIsMarkedCa)
            rootRequest.CertificateExtensions.Add(new X509BasicConstraintsExtension(true, false, 0, true));
        var root = rootRequest.CreateSelfSigned(T0 - TimeSpan.FromDays(1), T0 + TimeSpan.FromDays(365));
        var leafKey = RSA.Create(2048);
        var leafRequest = new CertificateRequest("CN=test", leafKey, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);

        // The generator overload, because Create(X509Certificate2, ...) refuses an issuer not marked as a CA.
        var leaf = leafRequest.Create(
            root.SubjectName, X509SignatureGenerator.CreateForRSA(rootKey, RSASignaturePadding.Pkcs1),
            T0 - TimeSpan.FromDays(1), T0 + TimeSpan.FromDays(30), [1, 2, 3, 4]);
        return (root, leaf, leafKey);
    }

    [Fact]
    public async Task ReadAsync_rejects_a_chain_file_whose_first_certificate_is_a_ca()
    {
        // CreateFromPem takes the first CERTIFICATE block, so a root-first chain would publish the CA's key.
        var ct = TestContext.Current.CancellationToken;
        using var tempDir = new TempSigningKeyDirectory();
        using var caKey = RSA.Create(2048);
        var caRequest = new CertificateRequest("CN=test-ca", caKey, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        caRequest.CertificateExtensions.Add(new X509BasicConstraintsExtension(true, false, 0, true));
        using var ca = caRequest.CreateSelfSigned(T0 - TimeSpan.FromDays(1), T0 + TimeSpan.FromDays(365));
        using var leafKey = RSA.Create(2048);
        var leafRequest = new CertificateRequest("CN=test", leafKey, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        using var leaf = leafRequest.Create(ca, T0 - TimeSpan.FromDays(1), T0 + TimeSpan.FromDays(30), [1, 2, 3, 4]);
        var certPath = tempDir.WriteTextFile("chain.pem", ca.ExportCertificatePem() + "\n" + leaf.ExportCertificatePem());
        var keyPath = tempDir.WriteTextFile("key.pem", leafKey.ExportPkcs8PrivateKeyPem());
        var sut = BuildSource(new PemSigningFile(certPath, keyPath));

        var listing = await sut.ReadAsync(ct);

        var failure = listing.ShouldReportOnly(certPath, "signing.file_signing.certificate_is_a_ca");
        failure.Message.Should().Contain("leaf-first");
    }

    [Fact]
    public async Task ReadAsync_accepts_a_lone_self_signed_certificate_marked_as_a_ca()
    {
        // openssl req -x509 marks a self-signed certificate as a CA by default; with no chain there is no ordering to get wrong.
        var ct = TestContext.Current.CancellationToken;
        using var tempDir = new TempSigningKeyDirectory();
        using var key = RSA.Create(2048);
        var request = new CertificateRequest("CN=test", key, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        request.CertificateExtensions.Add(new X509BasicConstraintsExtension(true, false, 0, true));
        using var certificate = request.CreateSelfSigned(T0 - TimeSpan.FromDays(1), T0 + TimeSpan.FromDays(365));
        var certPath = tempDir.WriteTextFile("cert.pem", certificate.ExportCertificatePem());
        var keyPath = tempDir.WriteTextFile("key.pem", key.ExportPkcs8PrivateKeyPem());
        var sut = BuildSource(new PemSigningFile(certPath, keyPath));

        var listing = await sut.ReadAsync(ct);
        using var signer = await sut.CreateSignerAsync(listing.Keys.Single().Id, ct);

        listing.Failures.Should().BeEmpty();
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

        var listing = await sut.ReadAsync(ct);

        listing.ShouldReportOnly(stagedPath, "signing.file_signing.file_too_permissive");
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

        var listing = await sut.ReadAsync(ct);

        listing.ShouldReportOnly(stagedPath, "signing.file_signing.file_too_permissive");
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

        var listing = await sut.ReadAsync(ct);

        var failure = listing.ShouldReportOnly(path, "signing.certificate.private_key_not_found");
        failure.Message.Should().Contain(path);
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

        var listing = await sut.ReadAsync(ct);

        listing.ShouldReportOnly(path, "signing.certificate.private_key_not_found");
    }

    [Fact]
    public async Task ReadAsync_rejects_a_separate_key_file_that_carries_no_private_key_block()
    {
        var ct = TestContext.Current.CancellationToken;
        using var tempDir = new TempSigningKeyDirectory();
        using var certificate = CreateRsaCertificate();
        var certPath = tempDir.WriteCertificateOnlyPemFile("cert.crt", certificate);
        var keyPath = tempDir.WriteTextFile("key.pem", "not a key");
        var sut = BuildSource(new PemSigningFile(certPath, keyPath));

        var listing = await sut.ReadAsync(ct);

        var failure = listing.ShouldReportOnly(certPath, "signing.certificate.private_key_not_found");
        failure.Message.Should().Contain(keyPath);
    }

    [Fact]
    public async Task ReadAsync_no_longer_lists_a_PEM_whose_separate_key_file_was_deleted()
    {
        var ct = TestContext.Current.CancellationToken;
        using var tempDir = new TempSigningKeyDirectory();
        using var certificate = CreateRsaCertificate();
        var certPath = tempDir.WriteCertificateOnlyPemFile("cert.crt", certificate);
        var keyPath = tempDir.WriteKeyOnlyPemFile("key.pem", certificate);
        var sut = BuildSource(new PemSigningFile(certPath, keyPath));
        (await sut.ReadAsync(ct)).Keys.Should().ContainSingle();
        File.Delete(keyPath);

        var keys = (await sut.ReadAsync(ct)).Keys;

        keys.Should().BeEmpty("deleting the private key revokes the key as deleting the certificate does");
    }

    // ── Encrypted keys ───────────────────────────────────────────────────────────────────────────

    [Fact]
    public async Task ReadAsync_lists_an_encrypted_key_file_when_a_password_is_configured()
    {
        var ct = TestContext.Current.CancellationToken;
        using var tempDir = new TempSigningKeyDirectory();
        using var certificate = CreateRsaCertificate();
        var certPath = tempDir.WriteCertificateOnlyPemFile("cert.crt", certificate);
        var keyPath = tempDir.WriteTextFile("key.pem", EncryptedKeyPem(certificate));
        var password = new PasswordSource();
        var sut = BuildSource(new PemSigningFile(certPath, keyPath, password.GetAsync));

        var listing = await sut.ReadAsync(ct);

        listing.Failures.Should().BeEmpty();
        listing.Keys.Should().ContainSingle().Which.Id.Should().Be(new SourceKeyId(certPath));
    }

    [Fact]
    public async Task ReadAsync_lists_a_combined_file_with_an_encrypted_key_when_a_password_is_configured()
    {
        var ct = TestContext.Current.CancellationToken;
        using var tempDir = new TempSigningKeyDirectory();
        using var certificate = CreateRsaCertificate();
        var path = tempDir.WriteTextFile("combined.pem", certificate.ExportCertificatePem() + "\n" + EncryptedKeyPem(certificate));
        var password = new PasswordSource();
        var sut = BuildSource(new PemSigningFile(path, PasswordSource: password.GetAsync));

        var listing = await sut.ReadAsync(ct);

        listing.Failures.Should().BeEmpty();
        listing.Keys.Should().ContainSingle();
    }

    [Fact]
    public async Task ReadAsync_rejects_an_encrypted_key_file_without_a_password_at_listing()
    {
        var ct = TestContext.Current.CancellationToken;
        using var tempDir = new TempSigningKeyDirectory();
        using var certificate = CreateRsaCertificate();
        var certPath = tempDir.WriteCertificateOnlyPemFile("cert.crt", certificate);
        var keyPath = tempDir.WriteTextFile("key.pem", EncryptedKeyPem(certificate));
        var sut = BuildSource(new PemSigningFile(certPath, keyPath));

        var listing = await sut.ReadAsync(ct);

        var failure = listing.ShouldReportOnly(certPath, "signing.file_signing.key_encryption_mismatch");
        failure.Message.Should().Contain(keyPath);
    }

    [Fact]
    public async Task ReadAsync_rejects_a_combined_file_with_an_encrypted_key_without_a_password_at_listing()
    {
        var ct = TestContext.Current.CancellationToken;
        using var tempDir = new TempSigningKeyDirectory();
        using var certificate = CreateRsaCertificate();
        var path = tempDir.WriteTextFile("combined.pem", certificate.ExportCertificatePem() + "\n" + EncryptedKeyPem(certificate));
        var sut = BuildSource(new PemSigningFile(path));

        var listing = await sut.ReadAsync(ct);

        listing.ShouldReportOnly(path, "signing.file_signing.key_encryption_mismatch");
    }

    [Fact]
    public async Task ReadAsync_rejects_a_plain_key_file_when_a_password_is_configured()
    {
        // The operator believes the key on disk is encrypted; it is not, so the password protects nothing.
        var ct = TestContext.Current.CancellationToken;
        using var tempDir = new TempSigningKeyDirectory();
        using var certificate = CreateRsaCertificate();
        var certPath = tempDir.WriteCertificateOnlyPemFile("cert.crt", certificate);
        var keyPath = tempDir.WriteKeyOnlyPemFile("key.pem", certificate);
        var password = new PasswordSource();
        var sut = BuildSource(new PemSigningFile(certPath, keyPath, password.GetAsync));

        var listing = await sut.ReadAsync(ct);

        listing.ShouldReportOnly(certPath, "signing.file_signing.key_encryption_mismatch");
        password.Calls.Should().Be(0, "a label mismatch is found without the password");
    }

    [Fact]
    public async Task ReadAsync_rejects_a_plain_key_in_the_certificate_file_beside_an_encrypted_key_file()
    {
        // A plaintext copy of the key beside the encrypted one leaves the password protecting nothing.
        var ct = TestContext.Current.CancellationToken;
        using var tempDir = new TempSigningKeyDirectory();
        using var certificate = CreateRsaCertificate();
        var certPath = tempDir.WritePemFile("cert.pem", certificate);
        var keyPath = tempDir.WriteTextFile("key.pem", EncryptedKeyPem(certificate));
        var password = new PasswordSource();
        var sut = BuildSource(new PemSigningFile(certPath, keyPath, password.GetAsync));

        var listing = await sut.ReadAsync(ct);

        var failure = listing.ShouldReportOnly(certPath, "signing.file_signing.private_key_in_certificate_file");
        failure.Message.Should().Contain(certPath);
    }

    [Fact]
    public async Task ReadAsync_rejects_a_plain_key_after_an_encrypted_one_in_the_certificate_file()
    {
        var ct = TestContext.Current.CancellationToken;
        using var tempDir = new TempSigningKeyDirectory();
        using var certificate = CreateRsaCertificate();
        var certPath = tempDir.WriteTextFile("cert.pem",
            certificate.ExportCertificatePem() + "\n" + EncryptedKeyPem(certificate) + "\n"
            + certificate.GetRSAPrivateKey()!.ExportPkcs8PrivateKeyPem());
        var keyPath = tempDir.WriteTextFile("key.pem", EncryptedKeyPem(certificate));
        var password = new PasswordSource();
        var sut = BuildSource(new PemSigningFile(certPath, keyPath, password.GetAsync));

        var listing = await sut.ReadAsync(ct);

        listing.ShouldReportOnly(certPath, "signing.file_signing.private_key_in_certificate_file");
    }

    [Fact]
    public async Task ReadAsync_rejects_a_combined_file_with_a_plain_key_after_its_encrypted_one()
    {
        var ct = TestContext.Current.CancellationToken;
        using var tempDir = new TempSigningKeyDirectory();
        using var certificate = CreateRsaCertificate();
        var path = tempDir.WriteTextFile("combined.pem",
            certificate.ExportCertificatePem() + "\n" + EncryptedKeyPem(certificate) + "\n"
            + certificate.GetRSAPrivateKey()!.ExportPkcs8PrivateKeyPem());
        var password = new PasswordSource();
        var sut = BuildSource(new PemSigningFile(path, PasswordSource: password.GetAsync));

        var listing = await sut.ReadAsync(ct);

        listing.ShouldReportOnly(path, "signing.file_signing.key_encryption_mismatch");
    }

    [Fact]
    public async Task ReadAsync_reports_a_password_source_that_returns_null_as_password_unavailable()
    {
        var ct = TestContext.Current.CancellationToken;
        using var tempDir = new TempSigningKeyDirectory();
        using var certificate = CreateRsaCertificate();
        var certPath = tempDir.WriteCertificateOnlyPemFile("cert.crt", certificate);
        var keyPath = tempDir.WriteTextFile("key.pem", EncryptedKeyPem(certificate));
        var sut = BuildSource(new PemSigningFile(certPath, keyPath, _ => Task.FromResult<string>(null!)));

        var listing = await sut.ReadAsync(ct);

        listing.ShouldReportOnly(certPath, "signing.file_signing.password_unavailable");
    }

    [Theory]
    [InlineData("combined")]
    [InlineData("split")]
    public async Task ReadAsync_refuses_a_legacy_encrypted_key_beside_a_valid_pkcs8_one(string form)
    {
        // A retained legacy copy is still the signing key, under whatever password it was made with.
        var ct = TestContext.Current.CancellationToken;
        using var tempDir = new TempSigningKeyDirectory();
        using var certificate = CreateRsaCertificate();
        var certPem = certificate.ExportCertificatePem() + "\n" + LegacyEncryptedKeyPem;
        var file = form == "combined"
            ? new PemSigningFile(tempDir.WriteTextFile("combined.pem", certPem + "\n" + EncryptedKeyPem(certificate)),
                PasswordSource: new PasswordSource().GetAsync)
            : new PemSigningFile(tempDir.WriteTextFile("cert.pem", certPem),
                tempDir.WriteTextFile("key.pem", EncryptedKeyPem(certificate)), new PasswordSource().GetAsync);
        var sut = BuildSource(file);

        var listing = await sut.ReadAsync(ct);

        listing.ShouldReportOnly(file.Path, "signing.file_signing.legacy_encrypted_key");
    }

    [Fact]
    public async Task ReadAsync_rejects_a_weakly_encrypted_key_copy_in_the_certificate_file()
    {
        // Only the key file's encryption is judged, so a copy in the certificate file would escape it.
        var ct = TestContext.Current.CancellationToken;
        using var tempDir = new TempSigningKeyDirectory();
        using var certificate = CreateRsaCertificate();
        var weakCopy = EncryptedKeyPem(certificate,
            new PbeParameters(PbeEncryptionAlgorithm.Aes256Cbc, HashAlgorithmName.SHA256, 1), "guessable");
        var certPath = tempDir.WriteTextFile("cert.pem", certificate.ExportCertificatePem() + "\n" + weakCopy);
        var keyPath = tempDir.WriteTextFile("key.pem", EncryptedKeyPem(certificate));
        var sut = BuildSource(new PemSigningFile(certPath, keyPath, new PasswordSource().GetAsync));

        var listing = await sut.ReadAsync(ct);

        listing.ShouldReportOnly(certPath, "signing.file_signing.private_key_in_certificate_file");
    }

    [Fact]
    public async Task ReadAsync_rejects_a_key_encrypted_with_a_cipher_other_than_AES_CBC()
    {
        // PBES2, PBKDF2 at 2048 iterations, des-ede3-cbc: openssl pkcs8 -topk8 -v2 des3 over a throwaway
        // P-256 key. Checked in because PbeParameters cannot produce PBES2 with 3DES. Only its header is read.
        const string des3Key = """
            -----BEGIN ENCRYPTED PRIVATE KEY-----
            MIHjME4GCSqGSIb3DQEFDTBBMCkGCSqGSIb3DQEFDDAcBAjENwtCTlOxsgICCAAw
            DAYIKoZIhvcNAgkFADAUBggqhkiG9w0DBwQIPTZISnzzwy4EgZCOuJPZO2tqS0KI
            FW9eW9djwIr716K/ZDlXvNABXRnTSrYD8kWemGrI7eqlOLk64uNx2szOT46m+tdS
            k8JXJuo4aftTHVnBhoyvJMKAYoHnRgmYo3dSj81AsQT2rdwD6hTU4Xe/ssNgqbUC
            AHkugmsXbgiM1OXuSSMZnTEDM6D3OQF8NFuMOBHGXGHdyk1ZJ4U=
            -----END ENCRYPTED PRIVATE KEY-----
            """;
        var ct = TestContext.Current.CancellationToken;
        using var tempDir = new TempSigningKeyDirectory();
        using var certificate = CreateRsaCertificate();
        var certPath = tempDir.WriteCertificateOnlyPemFile("cert.crt", certificate);
        var keyPath = tempDir.WriteTextFile("key.pem", des3Key);
        var sut = BuildSource(new PemSigningFile(certPath, keyPath, new PasswordSource().GetAsync));

        var listing = await sut.ReadAsync(ct);

        var failure = listing.ShouldReportOnly(certPath, "signing.file_signing.weak_key_encryption");
        failure.Message.Should().Contain("AES-CBC");
    }

    [Fact]
    public async Task CreateSignerAsync_refuses_a_plain_key_added_after_listing()
    {
        var ct = TestContext.Current.CancellationToken;
        using var tempDir = new TempSigningKeyDirectory();
        using var certificate = CreateRsaCertificate();
        var certPath = tempDir.WriteCertificateOnlyPemFile("cert.crt", certificate);
        var keyPath = tempDir.WriteTextFile("key.pem", EncryptedKeyPem(certificate));
        var sut = BuildSource(new PemSigningFile(certPath, keyPath, new PasswordSource().GetAsync));
        var key = (await sut.ReadAsync(ct)).Keys.Single();
        tempDir.WriteTextFile("key.pem", EncryptedKeyPem(certificate) + "\n" + certificate.GetRSAPrivateKey()!.ExportPkcs8PrivateKeyPem());

        var act = async () => await sut.CreateSignerAsync(key.Id, ct);

        var exception = await act.Should().ThrowAsync<ZeeKayDaConfigurationException>();
        exception.Which.AggregatedFailures.Should().ContainSingle(f => f.Code == "signing.file_signing.key_encryption_mismatch");
    }

    [Theory]
    [InlineData("combined")]
    [InlineData("split")]
    public async Task ReadAsync_rejects_a_second_encrypted_key_in_the_key_file(string form)
    {
        // Only the first is judged and imported, so a second, possibly weaker, copy would escape both.
        var ct = TestContext.Current.CancellationToken;
        using var tempDir = new TempSigningKeyDirectory();
        using var certificate = CreateRsaCertificate();
        var keys = EncryptedKeyPem(certificate) + "\n" + EncryptedKeyPem(certificate,
            new PbeParameters(PbeEncryptionAlgorithm.Aes256Cbc, HashAlgorithmName.SHA256, 1), "guessable");
        var file = form == "combined"
            ? new PemSigningFile(tempDir.WriteTextFile("combined.pem", certificate.ExportCertificatePem() + "\n" + keys),
                PasswordSource: new PasswordSource().GetAsync)
            : new PemSigningFile(tempDir.WriteCertificateOnlyPemFile("cert.crt", certificate),
                tempDir.WriteTextFile("key.pem", keys), new PasswordSource().GetAsync);
        var sut = BuildSource(file);

        var listing = await sut.ReadAsync(ct);

        listing.ShouldReportOnly(file.Path, "signing.file_signing.key_encryption_mismatch");
    }

    [Fact]
    public async Task ReadAsync_rejects_a_key_encrypted_with_a_PBES1_scheme()
    {
        var ct = TestContext.Current.CancellationToken;
        using var tempDir = new TempSigningKeyDirectory();
        using var certificate = CreateRsaCertificate();
        var certPath = tempDir.WriteCertificateOnlyPemFile("cert.crt", certificate);
        var keyPath = tempDir.WriteTextFile("key.pem", EncryptedKeyPem(certificate,
            new PbeParameters(PbeEncryptionAlgorithm.TripleDes3KeyPkcs12, HashAlgorithmName.SHA1, 2048)));
        var password = new PasswordSource();
        var sut = BuildSource(new PemSigningFile(certPath, keyPath, password.GetAsync));

        var listing = await sut.ReadAsync(ct);

        var failure = listing.ShouldReportOnly(certPath, "signing.file_signing.weak_key_encryption");
        failure.Message.Should().Contain("openssl pkcs8 -topk8 -v2 aes-256-cbc");
        password.Calls.Should().Be(0, "weak parameters are found without the password");
    }

    [Fact]
    public async Task ReadAsync_rejects_a_key_encrypted_with_fewer_than_2048_PBKDF2_iterations()
    {
        var ct = TestContext.Current.CancellationToken;
        using var tempDir = new TempSigningKeyDirectory();
        using var certificate = CreateRsaCertificate();
        var certPath = tempDir.WriteCertificateOnlyPemFile("cert.crt", certificate);
        var keyPath = tempDir.WriteTextFile("key.pem", EncryptedKeyPem(certificate,
            new PbeParameters(PbeEncryptionAlgorithm.Aes256Cbc, HashAlgorithmName.SHA256, 2047)));
        var sut = BuildSource(new PemSigningFile(certPath, keyPath, new PasswordSource().GetAsync));

        var listing = await sut.ReadAsync(ct);

        listing.ShouldReportOnly(certPath, "signing.file_signing.weak_key_encryption");
    }

    [Fact]
    public async Task ReadAsync_names_the_key_type_when_a_correctly_encrypted_key_is_not_the_certificates_type()
    {
        var ct = TestContext.Current.CancellationToken;
        using var tempDir = new TempSigningKeyDirectory();
        using var certificate = CreateRsaCertificate();
        using var ecCertificate = TestCertificateFactory.CreateEcSelfSigned(
            "ec", T0 - TimeSpan.FromDays(1), T0 + TimeSpan.FromDays(365));
        var certPath = tempDir.WriteCertificateOnlyPemFile("cert.crt", certificate);
        var keyPath = tempDir.WriteTextFile("key.pem", EncryptedKeyPem(ecCertificate));
        var sut = BuildSource(new PemSigningFile(certPath, keyPath, new PasswordSource().GetAsync));

        var listing = await sut.ReadAsync(ct);

        var failure = listing.ShouldReportOnly(certPath, "signing.file_signing.key_password_rejected");
        failure.Message.Should().Contain("not a key of the certificate's type");
    }

    [Fact]
    public async Task ReadAsync_reports_a_password_source_that_returns_an_empty_string_as_password_unavailable()
    {
        // Most often a missing secret bound to "", and a key encrypted under it is a plain key in disguise.
        var ct = TestContext.Current.CancellationToken;
        using var tempDir = new TempSigningKeyDirectory();
        using var certificate = CreateRsaCertificate();
        var certPath = tempDir.WriteCertificateOnlyPemFile("cert.crt", certificate);
        var keyPath = tempDir.WriteTextFile("key.pem", EncryptedKeyPem(certificate, password: ""));
        var sut = BuildSource(new PemSigningFile(certPath, keyPath, new PasswordSource("").GetAsync));

        var listing = await sut.ReadAsync(ct);

        listing.ShouldReportOnly(certPath, "signing.file_signing.password_unavailable");
    }

    [Fact]
    public async Task ReadAsync_reports_a_password_source_that_throws_as_password_unavailable_without_its_message()
    {
        var ct = TestContext.Current.CancellationToken;
        using var tempDir = new TempSigningKeyDirectory();
        using var certificate = CreateRsaCertificate();
        var certPath = tempDir.WriteCertificateOnlyPemFile("cert.crt", certificate);
        var keyPath = tempDir.WriteTextFile("key.pem", EncryptedKeyPem(certificate));
        var passwordFailure = new FileNotFoundException("the secret password file /run/secrets/pem is missing");
        var sut = BuildSource(new PemSigningFile(certPath, keyPath, _ => Task.FromException<string>(passwordFailure)));

        var listing = await sut.ReadAsync(ct);

        var failure = listing.ShouldReportOnly(certPath, "signing.file_signing.password_unavailable");
        failure.Message.Should().Contain(typeof(FileNotFoundException).FullName);
        failure.Message.Should().NotContain(passwordFailure.Message);
    }

    [Fact]
    public async Task ReadAsync_names_the_legacy_openssl_format_and_the_pkcs8_conversion()
    {
        var ct = TestContext.Current.CancellationToken;
        using var tempDir = new TempSigningKeyDirectory();
        using var certificate = CreateRsaCertificate();
        var certPath = tempDir.WriteCertificateOnlyPemFile("cert.crt", certificate);
        var keyPath = tempDir.WriteTextFile("key.pem", LegacyEncryptedKeyPem);
        var password = new PasswordSource();
        var sut = BuildSource(new PemSigningFile(certPath, keyPath, password.GetAsync));

        var listing = await sut.ReadAsync(ct);

        var failure = listing.ShouldReportOnly(certPath, "signing.file_signing.legacy_encrypted_key");
        failure.Message.Should().Contain("openssl pkcs8 -topk8");
    }

    [Fact]
    public async Task ReadAsync_rejects_a_wrong_password_at_listing()
    {
        var ct = TestContext.Current.CancellationToken;
        using var tempDir = new TempSigningKeyDirectory();
        using var certificate = CreateRsaCertificate();
        var certPath = tempDir.WriteCertificateOnlyPemFile("cert.crt", certificate);
        var keyPath = tempDir.WriteTextFile("key.pem", EncryptedKeyPem(certificate));
        var password = new PasswordSource("wrong password");
        var sut = BuildSource(new PemSigningFile(certPath, keyPath, password.GetAsync));

        var listing = await sut.ReadAsync(ct);

        var failure = listing.ShouldReportOnly(certPath, "signing.file_signing.key_password_rejected");
        failure.Message.Should().Contain(keyPath).And.NotContain("wrong password");
    }

    [Fact]
    public async Task ReadAsync_retries_a_rejected_password_on_the_next_read()
    {
        var ct = TestContext.Current.CancellationToken;
        using var tempDir = new TempSigningKeyDirectory();
        using var certificate = CreateRsaCertificate();
        var certPath = tempDir.WriteCertificateOnlyPemFile("cert.crt", certificate);
        var keyPath = tempDir.WriteTextFile("key.pem", EncryptedKeyPem(certificate));
        var password = new PasswordSource("wrong password");
        var sut = BuildSource(new PemSigningFile(certPath, keyPath, password.GetAsync));
        (await sut.ReadAsync(ct)).Keys.Should().BeEmpty();
        password.Value = Password;

        var listing = await sut.ReadAsync(ct);

        listing.Failures.Should().BeEmpty("the password was fixed at its source and the files did not change");
        listing.Keys.Should().ContainSingle();
    }

    [Fact]
    public async Task ReadAsync_fetches_the_password_only_when_the_key_file_changes()
    {
        var ct = TestContext.Current.CancellationToken;
        using var tempDir = new TempSigningKeyDirectory();
        using var certificate = CreateRsaCertificate();
        var certPath = tempDir.WriteCertificateOnlyPemFile("cert.crt", certificate);
        var keyPath = tempDir.WriteTextFile("key.pem", EncryptedKeyPem(certificate));
        var password = new PasswordSource();
        var sut = BuildSource(new PemSigningFile(certPath, keyPath, password.GetAsync));

        await sut.ReadAsync(ct);
        await sut.ReadAsync(ct);
        password.Calls.Should().Be(1, "an unchanged key is not decrypted again");

        // Re-encrypting gives a new salt and IV, so the same key is new text on disk.
        tempDir.WriteTextFile("key.pem", EncryptedKeyPem(certificate));
        await sut.ReadAsync(ct);

        password.Calls.Should().Be(2);
    }

    [Fact]
    public async Task ReadAsync_pairs_the_key_again_when_only_the_certificate_file_changes()
    {
        // A certificate swapped under an unchanged key file is a new pairing to check.
        var ct = TestContext.Current.CancellationToken;
        using var tempDir = new TempSigningKeyDirectory();
        using var certificate = CreateRsaCertificate();
        using var other = CreateRsaCertificate();
        var certPath = tempDir.WriteCertificateOnlyPemFile("cert.crt", certificate);
        var keyPath = tempDir.WriteTextFile("key.pem", EncryptedKeyPem(certificate));
        var password = new PasswordSource();
        var sut = BuildSource(new PemSigningFile(certPath, keyPath, password.GetAsync));
        (await sut.ReadAsync(ct)).Keys.Should().ContainSingle();
        tempDir.WriteCertificateOnlyPemFile("cert.crt", other);

        var listing = await sut.ReadAsync(ct);

        listing.ShouldReportOnly(certPath, "signing.file_signing.invalid_pem");
        password.Calls.Should().Be(2);
    }

    [Fact]
    public async Task ReadAsync_rejects_an_encrypted_key_that_does_not_belong_to_its_certificate()
    {
        var ct = TestContext.Current.CancellationToken;
        using var tempDir = new TempSigningKeyDirectory();
        using var certificate = CreateRsaCertificate();
        using var other = CreateRsaCertificate();
        var certPath = tempDir.WriteCertificateOnlyPemFile("cert.crt", certificate);
        var keyPath = tempDir.WriteTextFile("key.pem", EncryptedKeyPem(other));
        var password = new PasswordSource();
        var sut = BuildSource(new PemSigningFile(certPath, keyPath, password.GetAsync));

        var listing = await sut.ReadAsync(ct);

        listing.ShouldReportOnly(certPath, "signing.file_signing.invalid_pem");
    }

    [Fact]
    public async Task CreateSignerAsync_signs_with_an_encrypted_key_given_its_password()
    {
        var ct = TestContext.Current.CancellationToken;
        using var tempDir = new TempSigningKeyDirectory();
        using var certificate = CreateRsaCertificate();
        var certPath = tempDir.WriteCertificateOnlyPemFile("cert.crt", certificate);
        var keyPath = tempDir.WriteTextFile("key.pem", EncryptedKeyPem(certificate));
        var password = new PasswordSource();
        var sut = BuildSource(new PemSigningFile(certPath, keyPath, password.GetAsync));
        var key = (await sut.ReadAsync(ct)).Keys.Single();

        using var signer = await sut.CreateSignerAsync(key.Id, ct);
        var signingInput = "header.payload"u8.ToArray();
        var signature = await signer.SignAsync(signingInput, ct);

        using var rsa = RSA.Create(key.PublicKey.RsaPublicParameters!.Value);
        rsa.VerifyData(signingInput, signature.Span, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1)
            .Should().BeTrue();
    }

    [Fact]
    public async Task CreateSignerAsync_signs_with_a_combined_files_encrypted_EC_key_given_its_password()
    {
        var ct = TestContext.Current.CancellationToken;
        using var tempDir = new TempSigningKeyDirectory();
        using var certificate = TestCertificateFactory.CreateEcSelfSigned(
            "test", T0 - TimeSpan.FromDays(1), T0 + TimeSpan.FromDays(365));
        var path = tempDir.WriteTextFile("combined.pem", certificate.ExportCertificatePem() + "\n" + EncryptedKeyPem(certificate));
        var password = new PasswordSource();
        var sut = BuildSource(new PemSigningFile(path, PasswordSource: password.GetAsync), SigningAlgorithm.ES256);
        var key = (await sut.ReadAsync(ct)).Keys.Single();

        using var signer = await sut.CreateSignerAsync(key.Id, ct);
        var signingInput = "header.payload"u8.ToArray();
        var signature = await signer.SignAsync(signingInput, ct);

        using var ecdsa = certificate.GetECDsaPublicKey()!;
        ecdsa.VerifyData(signingInput, signature.Span, HashAlgorithmName.SHA256).Should().BeTrue();
    }

    [Fact]
    public async Task CreateSignerAsync_fetches_the_password_once()
    {
        var ct = TestContext.Current.CancellationToken;
        using var tempDir = new TempSigningKeyDirectory();
        using var certificate = CreateRsaCertificate();
        var certPath = tempDir.WriteCertificateOnlyPemFile("cert.crt", certificate);
        var keyPath = tempDir.WriteTextFile("key.pem", EncryptedKeyPem(certificate));
        var password = new PasswordSource();
        var sut = BuildSource(new PemSigningFile(certPath, keyPath, password.GetAsync));
        var key = (await sut.ReadAsync(ct)).Keys.Single();
        var callsAfterListing = password.Calls;

        using var signer = await sut.CreateSignerAsync(key.Id, ct);

        password.Calls.Should().Be(callsAfterListing + 1);
    }

    [Fact]
    public async Task A_password_rotated_without_a_file_change_is_seen_only_by_the_next_signer()
    {
        // Accepted residual: listing skips an unchanged file, and an open signer holds its own key.
        var ct = TestContext.Current.CancellationToken;
        using var tempDir = new TempSigningKeyDirectory();
        using var certificate = CreateRsaCertificate();
        var certPath = tempDir.WriteCertificateOnlyPemFile("cert.crt", certificate);
        var keyPath = tempDir.WriteTextFile("key.pem", EncryptedKeyPem(certificate));
        var password = new PasswordSource();
        var sut = BuildSource(new PemSigningFile(certPath, keyPath, password.GetAsync));
        var key = (await sut.ReadAsync(ct)).Keys.Single();
        using var openSigner = await sut.CreateSignerAsync(key.Id, ct);
        password.Value = "rotated";
        var callsBeforeRead = password.Calls;

        var listing = await sut.ReadAsync(ct);
        var signature = await openSigner.SignAsync("header.payload"u8.ToArray(), ct);
        var nextSigner = async () => await sut.CreateSignerAsync(key.Id, ct);

        listing.Failures.Should().BeEmpty();
        password.Calls.Should().Be(callsBeforeRead, "an unchanged file is not decrypted again");
        using var rsa = RSA.Create(key.PublicKey.RsaPublicParameters!.Value);
        rsa.VerifyData("header.payload"u8, signature.Span, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1)
            .Should().BeTrue();
        (await nextSigner.Should().ThrowAsync<ZeeKayDaConfigurationException>())
            .Which.AggregatedFailures.Should().ContainSingle(f => f.Code == "signing.file_signing.key_password_rejected");
    }

    [Fact]
    public async Task CreateSignerAsync_rejects_a_wrong_password_under_its_own_code_without_leaking_it()
    {
        // The password changed at its source after the key was listed.
        var ct = TestContext.Current.CancellationToken;
        using var tempDir = new TempSigningKeyDirectory();
        using var certificate = CreateRsaCertificate();
        var certPath = tempDir.WriteCertificateOnlyPemFile("cert.crt", certificate);
        var keyPath = tempDir.WriteTextFile("key.pem", EncryptedKeyPem(certificate));
        var password = new PasswordSource();
        var sut = BuildSource(new PemSigningFile(certPath, keyPath, password.GetAsync));
        var key = (await sut.ReadAsync(ct)).Keys.Single();
        password.Value = "wrong password";

        var act = async () => await sut.CreateSignerAsync(key.Id, ct);

        var exception = await act.Should().ThrowAsync<ZeeKayDaConfigurationException>();
        AssertNamesTypeWithoutCopyingMessage(exception.Which, "signing.file_signing.key_password_rejected");
        exception.Which.AggregatedFailures.Single().Message.Should().NotContain("wrong password");
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

        var keySet = (await sut.ReadAsync(ct)).Keys;

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
        var path = tempDir.WritePemFile("current.pem", certificate);
        var sut = BuildSource(new PemSigningFile(path), algorithm: SigningAlgorithm.ES256);
        var keySet = (await sut.ReadAsync(ct)).Keys;

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
        const string garbage = "not a pem file at all";
        var path = tempDir.WriteTextFile("garbage.pem", garbage);
        var parserMessage = Record.Exception(() => X509Certificate2.CreateFromPem(garbage))!.Message;
        var sut = BuildSource(new PemSigningFile(path));

        var listing = await sut.ReadAsync(ct);

        var failure = listing.ShouldReportOnly(path, "signing.file_signing.invalid_pem");
        failure.Message.Should().Contain(typeof(CryptographicException).FullName);
        failure.Message.Should().NotContain(parserMessage);
    }

    [Fact]
    public async Task CreateSignerAsync_names_the_parser_exception_type_rather_than_copying_its_message()
    {
        // The private-key path is the sharpest case: the text the parser failed on is key material.
        var ct = TestContext.Current.CancellationToken;
        using var tempDir = new TempSigningKeyDirectory();
        using var certificate = CreateRsaCertificate();
        var certPath = tempDir.WriteCertificateOnlyPemFile("cert.crt", certificate);
        var keyPath = tempDir.WriteTextFile("key.pem", UnparseableKeyPem);
        var sut = BuildSource(new PemSigningFile(certPath, keyPath));
        var keySet = (await sut.ReadAsync(ct)).Keys;

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

    // ── Driven by the ring ───────────────────────────────────────────────────────────────────────

    [Fact]
    public async Task Ring_stops_signing_at_the_next_read_after_the_only_listed_file_is_deleted()
    {
        var ct = TestContext.Current.CancellationToken;
        using var tempDir = new TempSigningKeyDirectory();
        using var certificate = CreateRsaCertificate();
        var path = tempDir.WritePemFile("current.pem", certificate);
        await using var harness = await SigningKeyRingHarness.StartAsync(
            BuildSource(new PemSigningFile(path)), new FakeTimeProvider(T0), cancellationToken: ct);

        File.Delete(path);
        await harness.ReadAsync(ct);

        harness.Ring.Current.SigningKey.Should().BeNull();
        harness.Ring.Current.Published.Should().BeEmpty();
    }
}
