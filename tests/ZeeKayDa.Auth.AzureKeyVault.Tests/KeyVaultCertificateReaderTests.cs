using System.Reflection;
using System.Security.Cryptography;
using System.Security.Cryptography.Pkcs;
using System.Security.Cryptography.X509Certificates;
using Azure;
using Azure.Security.KeyVault.Certificates;
using Azure.Security.KeyVault.Secrets;
using Microsoft.Extensions.Options;
using ZeeKayDa.Auth.AzureKeyVault.Tests.Fakes;
using ZeeKayDa.Auth.Tokens;

namespace ZeeKayDa.Auth.AzureKeyVault.Tests;

/// <summary>
/// Exercises <c>KeyVaultCertificateReader.ExtractPrivateKey</c> — the logic flagged as highest-risk
/// for this issue: detecting a non-exportable certificate policy by finding no key bag while
/// walking the decoded PKCS#12 structure after Key Vault has already returned HTTP 200 (there is
/// no dedicated "forbidden" error for this case), rejecting non-PKCS#12 content types (PEM is
/// explicitly unsupported), and surfacing malformed secret payloads as actionable
/// <see cref="ZeeKayDaConfigurationException"/>s rather than raw SDK or cryptography exceptions.
/// </summary>
/// <remarks>
/// <c>ExtractPrivateKey</c>'s decision logic is a pure function of an already-downloaded
/// <see cref="KeyVaultSecret"/> and does not touch either SDK client, so it is exercised here
/// directly via reflection against a reader instance whose constructor performs no network I/O.
/// The network-facing paths — version enumeration, public/private material retrieval, and the SDK
/// fault mapping — are exercised via faked <c>CertificateClient</c>/<c>SecretClient</c> instances
/// injected through the reader's internal test constructor. Only the real HTTP pipeline itself
/// remains covered by nothing but the known-gap note in
/// <c>Integration/AzureKeyVaultRemoteSigningIntegrationTests.cs</c>.
/// </remarks>
public sealed class KeyVaultCertificateReaderTests
{
    private static readonly Uri VaultUri = new("https://fake-vault.vault.azure.net/");
    private static readonly KeyVaultCertificateIdentifier CertificateIdentifier =
        new(new Uri(VaultUri, "certificates/fake-cert"));

    private static KeyVaultCertificateReader BuildReader() =>
        new(Options.Create(new AzureKeyVaultCachedSigningOptions
        {
            CertificateIdentifier = CertificateIdentifier,
            Credential = new FakeTokenCredential(),
            Algorithm = SigningAlgorithm.RS256,
        }));

    private static (AsymmetricAlgorithm PrivateKey, SigningKeyType KeyType) InvokeExtractPrivateKey(
        KeyVaultCertificateReader reader, KeyVaultSecret secret, string version = "v1")
    {
        var method = typeof(KeyVaultCertificateReader).GetMethod(
            "ExtractPrivateKey", BindingFlags.NonPublic | BindingFlags.Instance)!;

        try
        {
            var result = method.Invoke(reader, [secret, version]);
            return ((AsymmetricAlgorithm, SigningKeyType))result!;
        }
        catch (TargetInvocationException ex) when (ex.InnerException is not null)
        {
            throw ex.InnerException;
        }
    }

    private static (AsymmetricAlgorithm PublicKey, SigningKeyType KeyType) InvokeExtractPublicKey(
        KeyVaultCertificateReader reader, byte[] cerBytes, string version = "v1")
    {
        var method = typeof(KeyVaultCertificateReader).GetMethod(
            "ExtractPublicKey", BindingFlags.NonPublic | BindingFlags.Instance)!;

        try
        {
            var result = method.Invoke(reader, [cerBytes, version]);
            return ((AsymmetricAlgorithm, SigningKeyType))result!;
        }
        catch (TargetInvocationException ex) when (ex.InnerException is not null)
        {
            throw ex.InnerException;
        }
    }

    private static byte[] CreateSelfSignedRsaCerWithoutPrivateKey()
    {
        using var rsa = RSA.Create(2048);
        var request = new CertificateRequest("CN=test", rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        using var cert = request.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddDays(30));
        return cert.Export(X509ContentType.Cert);
    }

    private static byte[] CreateSelfSignedEcCerWithoutPrivateKey()
    {
        using var ecdsa = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var request = new CertificateRequest("CN=test", ecdsa, HashAlgorithmName.SHA256);
        using var cert = request.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddDays(30));
        return cert.Export(X509ContentType.Cert);
    }

    private static KeyVaultSecret BuildSecret(string base64Value, string? contentType = null)
    {
        var secret = new KeyVaultSecret("fake-cert", base64Value);
        if (contentType is not null)
            secret.Properties.ContentType = contentType;
        return secret;
    }

    private static byte[] CreateSelfSignedRsaPfxWithPrivateKey()
    {
        using var rsa = RSA.Create(2048);
        var request = new CertificateRequest("CN=test", rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        using var cert = request.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddDays(30));
        return cert.Export(X509ContentType.Pfx);
    }

    private static byte[] CreateSelfSignedEcPfxWithPrivateKey()
    {
        using var ecdsa = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var request = new CertificateRequest("CN=test", ecdsa, HashAlgorithmName.SHA256);
        using var cert = request.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddDays(30));
        return cert.Export(X509ContentType.Pfx);
    }

    /// <summary>
    /// Builds a PKCS#12 payload for a certificate with NO private key — reproducing, in a local
    /// test, the confirmed Key Vault behavior documented in <c>KeyVaultCertificateReader</c>: a
    /// non-exportable certificate policy's secret still downloads as HTTP 200 with a valid PKCS#12
    /// payload, it simply omits the private key.
    /// </summary>
    private static byte[] CreatePublicOnlyPfxWithoutPrivateKey()
    {
        using var rsa = RSA.Create(2048);
        var request = new CertificateRequest("CN=test", rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        using var certWithKey = request.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddDays(30));
        using var publicOnly = X509CertificateLoader.LoadCertificate(certWithKey.Export(X509ContentType.Cert));
        return publicOnly.Export(X509ContentType.Pfx);
    }

    // ── Happy path ────────────────────────────────────────────────────────────────────────────────

    [Fact]
    public void ExtractPrivateKey_returns_rsa_private_key_for_exportable_pkcs12_secret()
    {
        var reader = BuildReader();
        var secret = BuildSecret(Convert.ToBase64String(CreateSelfSignedRsaPfxWithPrivateKey()));

        var (privateKey, keyType) = InvokeExtractPrivateKey(reader, secret);
        using var _ = privateKey;

        keyType.Should().Be(SigningKeyType.Rsa);
        privateKey.Should().BeAssignableTo<RSA>();
    }

    [Fact]
    public void ExtractPrivateKey_returns_ec_private_key_for_exportable_pkcs12_secret()
    {
        var reader = BuildReader();
        var secret = BuildSecret(Convert.ToBase64String(CreateSelfSignedEcPfxWithPrivateKey()));

        var (privateKey, keyType) = InvokeExtractPrivateKey(reader, secret);
        using var _ = privateKey;

        keyType.Should().Be(SigningKeyType.Ec);
        privateKey.Should().BeAssignableTo<ECDsa>();
    }

    // ── Content type ─────────────────────────────────────────────────────────────────────────────

    [Fact]
    public void ExtractPrivateKey_succeeds_when_content_type_is_null_default_pkcs12_assumed()
    {
        var reader = BuildReader();
        var secret = BuildSecret(Convert.ToBase64String(CreateSelfSignedRsaPfxWithPrivateKey()), contentType: null);

        var (privateKey, _) = InvokeExtractPrivateKey(reader, secret);
        privateKey.Dispose();
    }

    [Fact]
    public void ExtractPrivateKey_succeeds_when_content_type_is_explicitly_pkcs12()
    {
        var reader = BuildReader();
        var secret = BuildSecret(
            Convert.ToBase64String(CreateSelfSignedRsaPfxWithPrivateKey()), contentType: "application/x-pkcs12");

        var (privateKey, _) = InvokeExtractPrivateKey(reader, secret);
        privateKey.Dispose();
    }

    [Fact]
    public void ExtractPrivateKey_throws_actionable_exception_for_pem_content_type()
    {
        // Developer note (highest-risk area, secondary case): PEM is explicitly unsupported and
        // must fail fast with a clear exception rather than being silently mishandled.
        var reader = BuildReader();
        var secret = BuildSecret(
            "irrelevant-value-because-content-type-is-checked-first", contentType: "application/x-pem-file");

        var act = () => InvokeExtractPrivateKey(reader, secret);

        act.Should().Throw<ZeeKayDaConfigurationException>()
            .WithMessage("*unsupported_certificate_content_type*");
    }

    // ── Non-exportable certificate policy (highest-risk logic, AC #5) ───────────────────────────

    [Fact]
    public void ExtractPrivateKey_throws_actionable_exception_when_certificate_has_no_private_key()
    {
        // Simulates Key Vault's confirmed behavior for a non-exportable certificate policy: HTTP
        // 200 with a PKCS#12 payload that contains the certificate but omits the private key —
        // finding no key bag while walking the decoded PKCS#12 structure is the only reliable
        // signal for this, and must be checked explicitly.
        var reader = BuildReader();
        var secret = BuildSecret(Convert.ToBase64String(CreatePublicOnlyPfxWithoutPrivateKey()));

        var act = () => InvokeExtractPrivateKey(reader, secret);

        act.Should().Throw<ZeeKayDaConfigurationException>()
            .WithMessage("*certificate_not_exportable*");
    }

    [Fact]
    public void ExtractPrivateKey_non_exportable_exception_message_names_the_remote_signing_alternative()
    {
        // AC #5 requires the exception to explain that AddAzureKeyVaultRemoteSigning should be
        // used instead for non-exportable keys.
        var reader = BuildReader();
        var secret = BuildSecret(Convert.ToBase64String(CreatePublicOnlyPfxWithoutPrivateKey()));

        var act = () => InvokeExtractPrivateKey(reader, secret);

        act.Should().Throw<ZeeKayDaConfigurationException>()
            .WithMessage("*AddAzureKeyVaultRemoteSigning*");
    }

    // ── Malformed secret payload ─────────────────────────────────────────────────────────────────

    [Fact]
    public void ExtractPrivateKey_throws_actionable_exception_for_non_base64_secret_value()
    {
        var reader = BuildReader();
        var secret = BuildSecret("not-valid-base64!!!");

        var act = () => InvokeExtractPrivateKey(reader, secret);

        act.Should().Throw<ZeeKayDaConfigurationException>()
            .WithMessage("*invalid_certificate_secret*");
    }

    [Fact]
    public void ExtractPrivateKey_throws_actionable_exception_for_null_secret_value()
    {
        // Regression test (security review finding L2): a null secret.Value previously escaped
        // as an unmapped ArgumentNullException from Convert.FromBase64String instead of the same
        // actionable ZeeKayDaConfigurationException the bad-base64 case already produces. The
        // public KeyVaultSecret constructor rejects a null value, so SecretModelFactory (designed
        // for mocking) is used to reproduce a secret whose Value is null, as could occur via the
        // SDK's own deserialization path.
        var reader = BuildReader();
        var properties = SecretModelFactory.SecretProperties(name: "fake-cert");
        var secret = SecretModelFactory.KeyVaultSecret(properties);

        var act = () => InvokeExtractPrivateKey(reader, secret);

        act.Should().Throw<ZeeKayDaConfigurationException>()
            .WithMessage("*invalid_certificate_secret*");
    }

    [Fact]
    public void ExtractPrivateKey_throws_actionable_exception_for_valid_base64_that_is_not_a_pkcs12_payload()
    {
        var reader = BuildReader();
        var secret = BuildSecret(Convert.ToBase64String("not a pkcs12 payload"u8.ToArray()));

        var act = () => InvokeExtractPrivateKey(reader, secret);

        act.Should().Throw<ZeeKayDaConfigurationException>()
            .WithMessage("*invalid_certificate_secret*");
    }

    // ── ExtractPublicKey (Fix for #312 medium finding: public-only path for non-active versions) ──

    [Fact]
    public void ExtractPublicKey_returns_rsa_public_only_key_with_no_private_parameters()
    {
        var reader = BuildReader();
        var cerBytes = CreateSelfSignedRsaCerWithoutPrivateKey();

        var (publicKey, keyType) = InvokeExtractPublicKey(reader, cerBytes);
        using var _ = publicKey;

        keyType.Should().Be(SigningKeyType.Rsa);
        publicKey.Should().BeAssignableTo<RSA>();
        ((RSA)publicKey).ExportParameters(includePrivateParameters: false).D.Should().BeNull(
            "ExtractPublicKey must never extract or hold private key material — it is built purely from the CER, not the secret/PFX");
    }

    [Fact]
    public void ExtractPublicKey_returns_ec_public_only_key_with_no_private_parameters()
    {
        var reader = BuildReader();
        var cerBytes = CreateSelfSignedEcCerWithoutPrivateKey();

        var (publicKey, keyType) = InvokeExtractPublicKey(reader, cerBytes);
        using var _ = publicKey;

        keyType.Should().Be(SigningKeyType.Ec);
        publicKey.Should().BeAssignableTo<ECDsa>();
        ((ECDsa)publicKey).ExportParameters(includePrivateParameters: false).D.Should().BeNull(
            "ExtractPublicKey must never extract or hold private key material — it is built purely from the CER, not the secret/PFX");
    }

    [Fact]
    public void ExtractPublicKey_throws_actionable_exception_for_malformed_cer_bytes()
    {
        // Regression test (security review finding L1): unlike every other failure path in this
        // class, a malformed Cer byte array previously escaped as a raw, unmapped
        // CryptographicException from X509CertificateLoader.LoadCertificate.
        var reader = BuildReader();

        var act = () => InvokeExtractPublicKey(reader, "not a valid certificate"u8.ToArray());

        act.Should().Throw<ZeeKayDaConfigurationException>()
            .WithMessage("*invalid_certificate_public_key*");
    }

    // ── Real Key Vault-exported fixtures (PR #312 architect finding) ───────────────────────────
    //
    // Every test above builds its PKCS#12 payloads with .NET's own CertificateRequest/Export —
    // which proves ExtractPrivateKeyFromPkcs12's logic is correct against .NET's own encoding
    // choices, but does NOT prove it against Key Vault's actual PBE algorithm, MAC scheme, and
    // key-bag-vs-shrouded-key-bag choice, which are not guaranteed to match .NET's defaults. These
    // two fixtures are the literal base64 `SecretClient.GetSecretAsync().Value.Value` strings
    // captured from a real Azure Key Vault certificate secret (exportable policy,
    // software-protected, no password) — one RSA, one EC (P-256) — exercised through the exact same
    // ExtractPrivateKey/ExtractPrivateKeyFromPkcs12 path production code uses.

    private const string RealRsaFixtureFileName = "real-keyvault-rsa-certificate-secret.base64.txt";
    private const string RealEcFixtureFileName = "real-keyvault-ec-certificate-secret.base64.txt";

    private static string ReadFixture(string fileName)
    {
        var path = Path.Join(AppContext.BaseDirectory, "Fixtures", "RealKeyVaultExports", fileName);
        File.Exists(path).Should().BeTrue(
            $"the real Key Vault export fixture should be copied to '{path}' " +
            "(see the <None Include=\"Fixtures/RealKeyVaultExports/*.txt\" ...> item in the test csproj)");
        return File.ReadAllText(path).Trim();
    }

    [Fact]
    public void ExtractPrivateKey_parses_a_real_keyvault_exported_rsa_certificate_secret()
    {
        var reader = BuildReader();
        var secret = BuildSecret(ReadFixture(RealRsaFixtureFileName), contentType: "application/x-pkcs12");

        var (privateKey, keyType) = InvokeExtractPrivateKey(reader, secret);
        using var rsa = (RSA)privateKey;

        keyType.Should().Be(SigningKeyType.Rsa);

        // Confirms the key is genuinely usable, not just structurally decoded: a full parameter
        // export (which requires a valid, consistent RSA private key) succeeds, the key size is a
        // realistic signing key size, and the key can actually sign and be verified.
        var parameters = rsa.ExportParameters(includePrivateParameters: true);
        parameters.D.Should().NotBeNullOrEmpty();
        rsa.KeySize.Should().BeGreaterThanOrEqualTo(2048);

        var payload = "real-keyvault-rsa-fixture-payload"u8.ToArray();
        var signature = rsa.SignData(payload, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        rsa.VerifyData(payload, signature, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1).Should().BeTrue();
    }

    [Fact]
    public void ExtractPrivateKey_parses_a_real_keyvault_exported_ec_certificate_secret()
    {
        var reader = BuildReader();
        var secret = BuildSecret(ReadFixture(RealEcFixtureFileName), contentType: "application/x-pkcs12");

        var (privateKey, keyType) = InvokeExtractPrivateKey(reader, secret);
        using var ecdsa = (ECDsa)privateKey;

        keyType.Should().Be(SigningKeyType.Ec);

        var parameters = ecdsa.ExportParameters(includePrivateParameters: true);
        parameters.D.Should().NotBeNullOrEmpty();
        parameters.Curve.Oid.Value.Should().Be(ECCurve.NamedCurves.nistP256.Oid.Value,
            "the fixture is a P-256 certificate — this pins the curve so a future fixture swap can't silently change it");

        var payload = "real-keyvault-ec-fixture-payload"u8.ToArray();
        var signature = ecdsa.SignData(payload, HashAlgorithmName.SHA256);
        ecdsa.VerifyData(payload, signature, HashAlgorithmName.SHA256).Should().BeTrue();
    }

    // ── MapVersion: fail-closed listing metadata ─────────────────────────────────────────────────

    private static readonly Uri MapVersionUri = new("https://fake-vault.vault.azure.net/certificates/fake-cert/v1");

    private static CertificateProperties BuildProperties(
        DateTimeOffset? createdOn, bool? enabled, DateTimeOffset? notBefore = null, DateTimeOffset? expiresOn = null)
    {
        var properties = CertificateModelFactory.CertificateProperties(
            id: MapVersionUri, name: "fake-cert", vaultUri: new Uri("https://fake-vault.vault.azure.net/"),
            version: "v1", notBefore: notBefore, expiresOn: expiresOn, createdOn: createdOn);
        properties.Enabled = enabled;
        return properties;
    }

    [Fact]
    public void MapVersion_maps_a_complete_listing_entry()
    {
        var createdOn = DateTimeOffset.Parse("2026-01-01T00:00:00Z");
        var properties = BuildProperties(
            createdOn, enabled: true,
            notBefore: createdOn - TimeSpan.FromDays(1), expiresOn: createdOn + TimeSpan.FromDays(365));

        var info = KeyVaultCertificateReader.MapVersion(properties, "fake-cert", new Uri("https://fake-vault.vault.azure.net/"));

        info.Id.Should().Be(MapVersionUri);
        info.Version.Should().Be("v1");
        info.Enabled.Should().BeTrue();
        info.CreatedOn.Should().Be(createdOn);
        info.NotBefore.Should().Be(createdOn - TimeSpan.FromDays(1));
        info.ExpiresOn.Should().Be(createdOn + TimeSpan.FromDays(365));
    }

    [Fact]
    public void MapVersion_fails_closed_when_CreatedOn_is_absent()
    {
        // An absent CreatedOn treated as ancient would satisfy the pre-activation age gate
        // immediately AND claim the first-ever exemption — the exact failure the gate exists to
        // prevent, reached through the one input the gate cannot see.
        var properties = BuildProperties(createdOn: null, enabled: true);

        var act = () => KeyVaultCertificateReader.MapVersion(properties, "fake-cert", new Uri("https://fake-vault.vault.azure.net/"));

        act.Should().Throw<ZeeKayDaConfigurationException>()
            .WithMessage("*incomplete_version_metadata*");
    }

    [Fact]
    public void MapVersion_fails_closed_when_Enabled_is_absent()
    {
        // An absent Enabled treated as enabled would bypass the operator's revocation lever.
        var properties = BuildProperties(createdOn: DateTimeOffset.Parse("2026-01-01T00:00:00Z"), enabled: null);

        var act = () => KeyVaultCertificateReader.MapVersion(properties, "fake-cert", new Uri("https://fake-vault.vault.azure.net/"));

        act.Should().Throw<ZeeKayDaConfigurationException>()
            .WithMessage("*incomplete_version_metadata*");
    }

    // ── Key-bag shapes .NET's own PFX export never produces ──────────────────────────────────────

    /// <summary>
    /// Builds a PKCS#12 payload whose private key sits in a plain (unencrypted)
    /// <see cref="Pkcs12KeyBag"/>. .NET's <c>Export(X509ContentType.Pfx)</c> always shrouds the
    /// key, so this bag shape — which the reader's PKCS#12 walk explicitly supports — is only
    /// reachable through a hand-built payload.
    /// </summary>
    private static byte[] CreatePlainKeyBagPfx(Action<Pkcs12SafeContents> addKey)
    {
        var contents = new Pkcs12SafeContents();
        addKey(contents);
        var builder = new Pkcs12Builder();
        builder.AddSafeContentsUnencrypted(contents);
        builder.SealWithoutIntegrity();
        return builder.Encode();
    }

    // Well-formed ASN.1 (SEQUENCE { INTEGER 0 }) that is not a PrivateKeyInfo, so both the RSA and
    // the EC import reject it.
    private static readonly byte[] NotAPrivateKey = [0x30, 0x03, 0x02, 0x01, 0x00];

    [Fact]
    public void ExtractPrivateKey_imports_an_rsa_key_from_a_plain_unencrypted_key_bag()
    {
        using var rsa = RSA.Create(2048);
        var pfx = CreatePlainKeyBagPfx(contents => contents.AddKeyUnencrypted(rsa));
        var reader = BuildReader();

        var (privateKey, keyType) = InvokeExtractPrivateKey(reader, BuildSecret(Convert.ToBase64String(pfx)));

        using var _ = privateKey;
        keyType.Should().Be(SigningKeyType.Rsa);
        privateKey.Should().BeAssignableTo<RSA>();
    }

    [Fact]
    public void ExtractPrivateKey_imports_an_ec_key_from_a_plain_unencrypted_key_bag()
    {
        using var ecdsa = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var pfx = CreatePlainKeyBagPfx(contents => contents.AddKeyUnencrypted(ecdsa));
        var reader = BuildReader();

        var (privateKey, keyType) = InvokeExtractPrivateKey(reader, BuildSecret(Convert.ToBase64String(pfx)));

        using var _ = privateKey;
        keyType.Should().Be(SigningKeyType.Ec);
        privateKey.Should().BeAssignableTo<ECDsa>();
    }

    [Fact]
    public void ExtractPrivateKey_rejects_a_plain_key_bag_that_is_neither_rsa_nor_ec()
    {
        var pfx = CreatePlainKeyBagPfx(contents => contents.AddSafeBag(new Pkcs12KeyBag(NotAPrivateKey)));
        var reader = BuildReader();

        var act = () => InvokeExtractPrivateKey(reader, BuildSecret(Convert.ToBase64String(pfx)));

        act.Should().Throw<ZeeKayDaConfigurationException>()
            .WithMessage("*unsupported_key_type*");
    }

    [Fact]
    public void ExtractPrivateKey_rejects_a_shrouded_key_bag_that_is_neither_rsa_nor_ec()
    {
        var pfx = CreatePlainKeyBagPfx(contents => contents.AddSafeBag(new Pkcs12ShroudedKeyBag(NotAPrivateKey)));
        var reader = BuildReader();

        var act = () => InvokeExtractPrivateKey(reader, BuildSecret(Convert.ToBase64String(pfx)));

        act.Should().Throw<ZeeKayDaConfigurationException>()
            .WithMessage("*unsupported_key_type*");
    }

    // ── Network-facing paths, via the internal test constructor ──────────────────────────────────

    // Deliberately NOT the certificate's own name/version: the linked secret's identifier is what
    // the download must follow, and a shared name would let a reader that wrongly reuses
    // _certificateName/version pass the assertion below.
    private static readonly Uri SecretIdUri = new("https://fake-vault.vault.azure.net/secrets/linked-secret/sv9");

    private static KeyVaultCertificateReader BuildReader(
        FakeCertificateClient certificateClient, FakeSecretClient? secretClient = null) =>
        new(
            certificateClient,
            secretClient ?? new FakeSecretClient
            {
                OnGetSecret = (_, _) => throw new InvalidOperationException(
                    "this test must never download the certificate's linked secret"),
            },
            CertificateIdentifier);

    private static KeyVaultCertificate BuildCertificate(byte[]? cer = null, Uri? secretId = null) =>
        CertificateModelFactory.KeyVaultCertificate(
            BuildProperties(createdOn: DateTimeOffset.Parse("2026-01-01T00:00:00Z"), enabled: true),
            keyId: null,
            secretId: secretId,
            cer: cer ?? CreateSelfSignedRsaCerWithoutPrivateKey());

    private static async Task<List<KeyVaultCertificateVersionInfo>> Collect(KeyVaultCertificateReader reader)
    {
        var versions = new List<KeyVaultCertificateVersionInfo>();
        await foreach (var version in reader.GetCertificateVersionsAsync(TestContext.Current.CancellationToken))
            versions.Add(version);
        return versions;
    }

    [Fact]
    public async Task GetCertificateVersionsAsync_yields_every_listed_version_mapped()
    {
        var client = new FakeCertificateClient
        {
            OnGetVersions = () => FakeAsyncPageable<CertificateProperties>.Of(
                BuildProperties(createdOn: DateTimeOffset.Parse("2026-01-01T00:00:00Z"), enabled: true),
                BuildProperties(createdOn: DateTimeOffset.Parse("2026-02-01T00:00:00Z"), enabled: false)),
        };

        var versions = await Collect(BuildReader(client));

        versions.Should().HaveCount(2);
        versions[0].Enabled.Should().BeTrue();
        versions[1].Enabled.Should().BeFalse();
        versions[1].CreatedOn.Should().Be(DateTimeOffset.Parse("2026-02-01T00:00:00Z"));
        client.RequestedNames.Should().Equal(["fake-cert"],
            "the listing must be for the configured certificate, nothing else");
    }

    [Theory]
    [InlineData(404, "certificate_not_found")]
    [InlineData(401, "access_denied")]
    [InlineData(403, "access_denied")]
    [InlineData(500, "startup_failure")]
    public async Task GetCertificateVersionsAsync_maps_a_failed_listing_to_a_stable_failure_code(
        int status, string expectedCode)
    {
        var client = new FakeCertificateClient
        {
            OnGetVersions = () => FakeAsyncPageable<CertificateProperties>.Throwing(
                new RequestFailedException(status, "boom")),
        };

        var act = () => Collect(BuildReader(client));

        await act.Should().ThrowAsync<ZeeKayDaConfigurationException>()
            .WithMessage($"*{expectedCode}*");
    }

    [Fact]
    public async Task GetCertificateVersionsAsync_maps_an_unexpected_listing_exception_to_startup_failure()
    {
        var client = new FakeCertificateClient
        {
            OnGetVersions = () => FakeAsyncPageable<CertificateProperties>.Throwing(
                new InvalidOperationException("SDK internal fault")),
        };

        var act = () => Collect(BuildReader(client));

        await act.Should().ThrowAsync<ZeeKayDaConfigurationException>()
            .WithMessage("*startup_failure*");
    }

    [Fact]
    public async Task GetCertificateVersionsAsync_lets_cancellation_escape_unmapped()
    {
        // A cancelled read is the host shutting down, not a vault misconfiguration — mapping it
        // to a configuration failure would tell the operator to go fix a vault that is fine.
        var client = new FakeCertificateClient
        {
            OnGetVersions = () => FakeAsyncPageable<CertificateProperties>.Throwing(
                new OperationCanceledException()),
        };

        var act = () => Collect(BuildReader(client));

        await act.Should().ThrowAsync<OperationCanceledException>();
    }

    [Fact]
    public async Task GetPublicKeyMaterialAsync_reads_only_the_cer_and_never_the_linked_secret()
    {
        string? requestedVersion = null;
        var client = new FakeCertificateClient
        {
            OnGetVersion = version =>
            {
                requestedVersion = version;
                return BuildCertificate(secretId: SecretIdUri);
            },
        };

        // BuildReader's default secret client throws on any call, so passing here proves the
        // public read needs no secrets/get.
        var (publicKey, keyType) = await BuildReader(client)
            .GetPublicKeyMaterialAsync("v3", TestContext.Current.CancellationToken);

        using var _ = publicKey;
        requestedVersion.Should().Be("v3");
        client.RequestedNames.Should().Equal(["fake-cert"],
            "the material must be fetched for the configured certificate, nothing else");
        keyType.Should().Be(SigningKeyType.Rsa);
        publicKey.Should().BeAssignableTo<RSA>();
    }

    [Fact]
    public async Task GetPrivateKeyMaterialAsync_downloads_the_linked_secret_and_returns_the_private_key()
    {
        var client = new FakeCertificateClient
        {
            OnGetVersion = _ => BuildCertificate(secretId: SecretIdUri),
        };
        (string Name, string? Version)? requestedSecret = null;
        var secretClient = new FakeSecretClient
        {
            OnGetSecret = (name, version) =>
            {
                requestedSecret = (name, version);
                return BuildSecret(Convert.ToBase64String(CreateSelfSignedRsaPfxWithPrivateKey()));
            },
        };

        var (privateKey, keyType) = await BuildReader(client, secretClient)
            .GetPrivateKeyMaterialAsync("v1", TestContext.Current.CancellationToken);

        using var _ = privateKey;
        requestedSecret.Should().Be(("linked-secret", "sv9"),
            "the secret must be fetched by the identifier the certificate version links to, " +
            "never by the certificate's own name and the requested version");
        keyType.Should().Be(SigningKeyType.Rsa);
        ((RSA)privateKey).ExportParameters(includePrivateParameters: true).D.Should().NotBeNull();
    }

    [Fact]
    public async Task GetPrivateKeyMaterialAsync_fails_closed_when_the_certificate_has_no_linked_secret_id()
    {
        // The SDK's KeyVaultCertificate.SecretId getter itself throws when the certificate carries
        // no sid at all, so the reader must not read it bare — an absent sid is the same
        // operator-facing condition as an unusable one and must surface with the same code.
        var client = new FakeCertificateClient
        {
            OnGetVersion = _ => BuildCertificate(secretId: null),
        };

        var act = () => BuildReader(client)
            .GetPrivateKeyMaterialAsync("v1", TestContext.Current.CancellationToken).AsTask();

        await act.Should().ThrowAsync<ZeeKayDaConfigurationException>()
            .WithMessage("*certificate_missing_secret*");
    }

    [Fact]
    public async Task GetPrivateKeyMaterialAsync_fails_closed_when_the_linked_secret_id_is_not_a_secret_identifier()
    {
        var client = new FakeCertificateClient
        {
            OnGetVersion = _ => BuildCertificate(secretId: new Uri("https://fake-vault.vault.azure.net/")),
        };

        var act = () => BuildReader(client)
            .GetPrivateKeyMaterialAsync("v1", TestContext.Current.CancellationToken).AsTask();

        await act.Should().ThrowAsync<ZeeKayDaConfigurationException>()
            .WithMessage("*certificate_missing_secret*");
    }

    [Fact]
    public async Task GetPrivateKeyMaterialAsync_maps_a_denied_secret_download_to_access_denied()
    {
        var client = new FakeCertificateClient
        {
            OnGetVersion = _ => BuildCertificate(secretId: SecretIdUri),
        };
        var secretClient = new FakeSecretClient
        {
            OnGetSecret = (_, _) => throw new RequestFailedException(403, "forbidden"),
        };

        var act = () => BuildReader(client, secretClient)
            .GetPrivateKeyMaterialAsync("v1", TestContext.Current.CancellationToken).AsTask();

        await act.Should().ThrowAsync<ZeeKayDaConfigurationException>()
            .WithMessage("*access_denied*");
    }

    // Every mapping arm builds its own ErrorCode clause, so each status class is exercised: the
    // not-found arm, the denied arm, and the catch-all arm.
    [Theory]
    [InlineData(404, "certificate_not_found")]
    [InlineData(403, "access_denied")]
    [InlineData(500, "startup_failure")]
    public async Task GetPublicKeyMaterialAsync_includes_the_sdk_error_code_in_the_failure_when_present(
        int status, string expectedCode)
    {
        var client = new FakeCertificateClient
        {
            OnGetVersion = _ => throw new RequestFailedException(
                status, "boom", "VaultErrorCode", innerException: null),
        };

        var act = () => BuildReader(client)
            .GetPublicKeyMaterialAsync("v1", TestContext.Current.CancellationToken).AsTask();

        await act.Should().ThrowAsync<ZeeKayDaConfigurationException>()
            .WithMessage($"*{expectedCode}*(HTTP {status}, ErrorCode: VaultErrorCode)*");
    }

    [Theory]
    [InlineData(404)]
    [InlineData(403)]
    [InlineData(500)]
    public async Task GetPublicKeyMaterialAsync_omits_the_error_code_clause_when_the_sdk_reports_none(int status)
    {
        var client = new FakeCertificateClient
        {
            OnGetVersion = _ => throw new RequestFailedException(status, "boom"),
        };

        var act = () => BuildReader(client)
            .GetPublicKeyMaterialAsync("v1", TestContext.Current.CancellationToken).AsTask();

        (await act.Should().ThrowAsync<ZeeKayDaConfigurationException>().WithMessage($"*(HTTP {status})*"))
            .Which.Message.Should().NotContain("ErrorCode",
                "an absent SDK error code must not leave a dangling 'ErrorCode:' clause in the operator message");
    }

    // ── Unexpected SDK faults on the download paths ──────────────────────────────────────────────

    [Fact]
    public async Task GetPublicKeyMaterialAsync_maps_an_unexpected_certificate_read_exception_to_startup_failure()
    {
        var client = new FakeCertificateClient
        {
            OnGetVersion = _ => throw new InvalidOperationException("SDK internal fault"),
        };

        var act = () => BuildReader(client)
            .GetPublicKeyMaterialAsync("v1", TestContext.Current.CancellationToken).AsTask();

        await act.Should().ThrowAsync<ZeeKayDaConfigurationException>()
            .WithMessage("*startup_failure*");
    }

    [Fact]
    public async Task GetPublicKeyMaterialAsync_lets_a_cancelled_certificate_read_escape_unmapped()
    {
        var client = new FakeCertificateClient
        {
            OnGetVersion = _ => throw new OperationCanceledException(),
        };

        var act = () => BuildReader(client)
            .GetPublicKeyMaterialAsync("v1", TestContext.Current.CancellationToken).AsTask();

        await act.Should().ThrowAsync<OperationCanceledException>();
    }

    [Fact]
    public async Task GetPrivateKeyMaterialAsync_maps_an_unexpected_secret_download_exception_to_startup_failure()
    {
        var client = new FakeCertificateClient
        {
            OnGetVersion = _ => BuildCertificate(secretId: SecretIdUri),
        };
        var secretClient = new FakeSecretClient
        {
            OnGetSecret = (_, _) => throw new InvalidOperationException("SDK internal fault"),
        };

        var act = () => BuildReader(client, secretClient)
            .GetPrivateKeyMaterialAsync("v1", TestContext.Current.CancellationToken).AsTask();

        await act.Should().ThrowAsync<ZeeKayDaConfigurationException>()
            .WithMessage("*startup_failure*");
    }

    [Fact]
    public async Task GetPrivateKeyMaterialAsync_lets_a_cancelled_secret_download_escape_unmapped()
    {
        var client = new FakeCertificateClient
        {
            OnGetVersion = _ => BuildCertificate(secretId: SecretIdUri),
        };
        var secretClient = new FakeSecretClient
        {
            OnGetSecret = (_, _) => throw new OperationCanceledException(),
        };

        var act = () => BuildReader(client, secretClient)
            .GetPrivateKeyMaterialAsync("v1", TestContext.Current.CancellationToken).AsTask();

        await act.Should().ThrowAsync<OperationCanceledException>();
    }

    // ── ExtractPublicKey: neither RSA nor EC ─────────────────────────────────────────────────────

    /// <summary>
    /// Builds a DER certificate whose SubjectPublicKeyInfo carries an Ed25519 key (OID 1.3.101.112),
    /// signed by a throwaway RSA issuer. .NET's typed <see cref="CertificateRequest"/> constructors
    /// only mint RSA and EC subjects, so the public key is assembled from its raw ASN.1 parts. The
    /// reader inspects nothing but the key's algorithm OID, which is exactly what this shape varies.
    /// </summary>
    private static byte[] CreateCerWithNeitherRsaNorEcPublicKey()
    {
        var ed25519 = new PublicKey(new Oid("1.3.101.112"), parameters: null, keyValue: new AsnEncodedData(new byte[32]));
        var request = new CertificateRequest(new X500DistinguishedName("CN=test"), ed25519, HashAlgorithmName.SHA256);
        using var issuerKey = RSA.Create(2048);
        var generator = X509SignatureGenerator.CreateForRSA(issuerKey, RSASignaturePadding.Pkcs1);
        using var cert = request.Create(
            new X500DistinguishedName("CN=issuer"), generator,
            DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddDays(30), serialNumber: [1, 2, 3, 4]);
        return cert.RawData;
    }

    [Fact]
    public void ExtractPublicKey_rejects_a_certificate_whose_public_key_is_neither_rsa_nor_ec()
    {
        var reader = BuildReader();

        var act = () => InvokeExtractPublicKey(reader, CreateCerWithNeitherRsaNorEcPublicKey());

        act.Should().Throw<ZeeKayDaConfigurationException>()
            .WithMessage("*unsupported_key_type*");
    }

    // ── Private-key import: a handle that fails to import never leaks ────────────────────────────
    //
    // The RSA/ECDsa handles are created and disposed entirely inside the reader, so the disposal
    // arms are observable only through injected factories. Each case runs for both key-bag shapes
    // the PKCS#12 walk supports, since each has its own import method and its own set of arms.

    private static byte[] CreateKeyBagPfx(bool shrouded) =>
        CreatePlainKeyBagPfx(contents => contents.AddSafeBag(
            shrouded ? new Pkcs12ShroudedKeyBag(NotAPrivateKey) : new Pkcs12KeyBag(NotAPrivateKey)));

    private static KeyVaultCertificateReader BuildReader(byte[] pfx, Func<RSA> createRsa, Func<ECDsa> createEcdsa) =>
        new(
            new FakeCertificateClient { OnGetVersion = _ => BuildCertificate(secretId: SecretIdUri) },
            new FakeSecretClient { OnGetSecret = (_, _) => BuildSecret(Convert.ToBase64String(pfx)) },
            CertificateIdentifier,
            createRsa,
            createEcdsa);

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task GetPrivateKeyMaterialAsync_disposes_both_handles_when_neither_rsa_nor_ec_can_import_the_key(bool shrouded)
    {
        var rsa = new ThrowingRsa(new CryptographicException("not an RSA key"));
        var ecdsa = new ThrowingEcdsa(new CryptographicException("not an EC key"));
        var reader = BuildReader(CreateKeyBagPfx(shrouded), () => rsa, () => ecdsa);

        var act = () => reader.GetPrivateKeyMaterialAsync("v1", TestContext.Current.CancellationToken).AsTask();

        await act.Should().ThrowAsync<ZeeKayDaConfigurationException>()
            .WithMessage("*unsupported_key_type*");
        rsa.Disposed.Should().BeTrue("an RSA handle that failed to import must not leak");
        ecdsa.Disposed.Should().BeTrue("an EC handle that failed to import must not leak");
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task GetPrivateKeyMaterialAsync_disposes_the_rsa_handle_and_rethrows_when_the_rsa_import_fails_unexpectedly(bool shrouded)
    {
        // Only a CryptographicException means "not an RSA key, try EC". Anything else escapes the
        // import arm as itself, after the handle is gone; whether the caller's PKCS#12 parser catch
        // then normalises it is that catch's business, and is covered separately below.
        var failure = new PlatformNotSupportedException("RSA PKCS#8 import is unavailable on this platform");
        var rsa = new ThrowingRsa(failure);
        var ecdsaCreated = false;
        var reader = BuildReader(
            CreateKeyBagPfx(shrouded),
            () => rsa,
            () =>
            {
                ecdsaCreated = true;
                return new ThrowingEcdsa(new CryptographicException("must not be reached"));
            });

        var act = () => reader.GetPrivateKeyMaterialAsync("v1", TestContext.Current.CancellationToken).AsTask();

        (await act.Should().ThrowAsync<PlatformNotSupportedException>())
            .Which.Should().BeSameAs(failure, "the original exception is rethrown, not wrapped or replaced");
        rsa.Disposed.Should().BeTrue("an RSA handle that failed to import must not leak");
        ecdsaCreated.Should().BeFalse("an unexpected RSA failure is not a signal to try EC");
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task GetPrivateKeyMaterialAsync_disposes_the_ec_handle_and_rethrows_when_the_ec_import_fails_unexpectedly(bool shrouded)
    {
        var failure = new PlatformNotSupportedException("EC PKCS#8 import is unavailable on this platform");
        var rsa = new ThrowingRsa(new CryptographicException("not an RSA key"));
        var ecdsa = new ThrowingEcdsa(failure);
        var reader = BuildReader(CreateKeyBagPfx(shrouded), () => rsa, () => ecdsa);

        var act = () => reader.GetPrivateKeyMaterialAsync("v1", TestContext.Current.CancellationToken).AsTask();

        (await act.Should().ThrowAsync<PlatformNotSupportedException>())
            .Which.Should().BeSameAs(failure, "the original exception is rethrown, not wrapped or replaced");
        rsa.Disposed.Should().BeTrue("an RSA handle that failed to import must not leak");
        ecdsa.Disposed.Should().BeTrue("an EC handle that failed to import must not leak");
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task GetPrivateKeyMaterialAsync_disposes_the_rsa_handle_before_the_parser_catch_normalises_an_invalid_operation(bool shrouded)
    {
        // InvalidOperationException is the one non-cryptographic failure the outer PKCS#12 catch
        // does normalise, so this proves the import arm still disposes on the way to that mapping.
        var rsa = new ThrowingRsa(new InvalidOperationException("import state fault"));
        var ecdsaCreated = false;
        var reader = BuildReader(
            CreateKeyBagPfx(shrouded),
            () => rsa,
            () =>
            {
                ecdsaCreated = true;
                return new ThrowingEcdsa(new CryptographicException("must not be reached"));
            });

        var act = () => reader.GetPrivateKeyMaterialAsync("v1", TestContext.Current.CancellationToken).AsTask();

        await act.Should().ThrowAsync<ZeeKayDaConfigurationException>()
            .WithMessage("*invalid_certificate_secret*");
        rsa.Disposed.Should().BeTrue("an RSA handle that failed to import must not leak");
        ecdsaCreated.Should().BeFalse("an unexpected RSA failure is not a signal to try EC");
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task GetPrivateKeyMaterialAsync_disposes_the_ec_handle_before_the_parser_catch_normalises_an_invalid_operation(bool shrouded)
    {
        var rsa = new ThrowingRsa(new CryptographicException("not an RSA key"));
        var ecdsa = new ThrowingEcdsa(new InvalidOperationException("import state fault"));
        var reader = BuildReader(CreateKeyBagPfx(shrouded), () => rsa, () => ecdsa);

        var act = () => reader.GetPrivateKeyMaterialAsync("v1", TestContext.Current.CancellationToken).AsTask();

        await act.Should().ThrowAsync<ZeeKayDaConfigurationException>()
            .WithMessage("*invalid_certificate_secret*");
        rsa.Disposed.Should().BeTrue("an RSA handle that failed to import must not leak");
        ecdsa.Disposed.Should().BeTrue("an EC handle that failed to import must not leak");
    }
}
