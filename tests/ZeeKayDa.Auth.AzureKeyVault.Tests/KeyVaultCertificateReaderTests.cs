using System.Reflection;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Azure.Security.KeyVault.Certificates;
using Azure.Security.KeyVault.Secrets;
using Microsoft.Extensions.Options;
using ZeeKayDa.Auth.AzureKeyVault.Tests.Fakes;
using ZeeKayDa.Auth.Tokens;

namespace ZeeKayDa.Auth.AzureKeyVault.Tests;

/// <summary>
/// Exercises <c>KeyVaultCertificateReader.ExtractPrivateKey</c> — the logic flagged as highest-risk
/// for this issue: detecting a non-exportable certificate policy via <c>HasPrivateKey</c> after Key
/// Vault has already returned HTTP 200 (there is no dedicated "forbidden" error for this case),
/// rejecting non-PKCS#12 content types (PEM is explicitly unsupported), and surfacing malformed
/// secret payloads as actionable <see cref="ZeeKayDaConfigurationException"/>s rather than raw SDK
/// or cryptography exceptions.
/// </summary>
/// <remarks>
/// <see cref="KeyVaultCertificateReader"/> constructs real <c>CertificateClient</c>/<c>SecretClient</c>
/// instances directly from options, with no injectable seam — this project's convention (see the
/// documented KNOWN GAP in <c>AzureKeyVaultRemoteSigningIntegrationTests</c>) is to fake at the
/// <c>IKeyVaultCertificateReader</c>/<c>IKeyVaultKeyReader</c> interface level rather than at the
/// HTTP level, since there is no local Key Vault emulator. <c>ExtractPrivateKey</c>'s decision logic
/// is, however, a pure function of an already-downloaded <see cref="KeyVaultSecret"/> and does not
/// touch either SDK client, so it is exercised here directly via reflection against a reader
/// instance whose constructor performs no network I/O.
/// </remarks>
public sealed class KeyVaultCertificateReaderTests
{
    private static readonly Uri VaultUri = new("https://fake-vault.vault.azure.net/");

    private static KeyVaultCertificateReader BuildReader() =>
        new(Options.Create(new AzureKeyVaultCachedSigningOptions
        {
            CertificateIdentifier = new KeyVaultCertificateIdentifier(new Uri(VaultUri, "certificates/fake-cert")),
            Credential = new FakeTokenCredential(),
            Algorithm = SigningAlgorithm.RS256,
            RefreshInterval = TimeSpan.FromMinutes(5),
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
        // HasPrivateKey is the only reliable signal for this, and must be checked explicitly.
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
    public void ExtractPrivateKey_throws_actionable_exception_for_valid_base64_that_is_not_a_pkcs12_payload()
    {
        var reader = BuildReader();
        var secret = BuildSecret(Convert.ToBase64String("not a pkcs12 payload"u8.ToArray()));

        var act = () => InvokeExtractPrivateKey(reader, secret);

        act.Should().Throw<ZeeKayDaConfigurationException>()
            .WithMessage("*invalid_certificate_secret*");
    }
}
