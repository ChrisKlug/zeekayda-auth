// The genuinely Windows-only real-X509Store tests (AC #12). All gated with
// Assert.SkipUnless(OperatingSystem.IsWindows(), ...) so they run only on the windows-latest CI
// leg and skip cleanly (not error) everywhere else. Uses StoreLocation.CurrentUser/StoreName.My —
// the one combination that never requires elevated/admin rights, so it works unattended on a
// Windows CI runner.

using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using ZeeKayDa.Auth.Tokens;
using ZeeKayDa.Auth.Windows.Tests.Fixtures;

namespace ZeeKayDa.Auth.Windows.Tests.Integration;

public sealed class CertificateStoreReaderTests
{
    private static readonly DateTimeOffset T0 = DateTimeOffset.Parse("2026-01-01T00:00:00Z");

    private sealed class InstalledTestCertificate : IDisposable
    {
        private readonly X509Store _store;
        private readonly X509Certificate2 _certificate;

        public InstalledTestCertificate(X509Certificate2 certificate)
        {
            // TestCertificateFactory.CreateRsaSelfSigned's private key is ephemeral (an in-memory
            // CNG key never associated with a persisted key container). On an interactive desktop,
            // X509Store.Add() can silently persist an ephemeral key on the caller's behalf, but on
            // a non-interactive CI session (e.g. GitHub Actions' windows-latest runner) that
            // promotion does not reliably happen: the certificate is still added to the store and
            // found by thumbprint, but re-reading it back reports HasPrivateKey = false. Round-tripping
            // through a PFX export/reimport with PersistKeySet forces the private key into a durable
            // CNG key container before the certificate is added, so it survives being read back by a
            // separate X509Store.Open() call exactly as a real, deployment-installed certificate would.
            const string temporaryPfxPassword = "test-only-not-a-real-secret";
            var pfxBytes = certificate.Export(X509ContentType.Pfx, temporaryPfxPassword);
            certificate.Dispose();
            _certificate = X509CertificateLoader.LoadPkcs12(
                pfxBytes, temporaryPfxPassword, X509KeyStorageFlags.PersistKeySet | X509KeyStorageFlags.Exportable);

            _store = new X509Store(StoreName.My, StoreLocation.CurrentUser);
            _store.Open(OpenFlags.ReadWrite);
            _store.Add(_certificate);
        }

        public string Thumbprint => _certificate.Thumbprint;

        public void Dispose()
        {
            _store.Remove(_certificate);
            _store.Dispose();
            _certificate.Dispose();
        }
    }

    [Fact]
    public void GetCertificate_finds_and_returns_an_installed_certificate_by_thumbprint()
    {
        Assert.SkipUnless(OperatingSystem.IsWindows(), "requires a real Windows Certificate Store");

        using var testCertificate = TestCertificateFactory.CreateRsaSelfSigned("windows-cert-store-test", T0 - TimeSpan.FromDays(1), T0 + TimeSpan.FromDays(365));
        using var installed = new InstalledTestCertificate(testCertificate);
        var reader = new CertificateStoreReader();

        using var found = reader.GetCertificate(ThumbprintFormat.Normalize(installed.Thumbprint), StoreLocation.CurrentUser, StoreName.My);

        found.Thumbprint.Should().Be(installed.Thumbprint);
        found.HasPrivateKey.Should().BeTrue();
    }

    [Fact]
    public void GetCertificate_throws_certificate_not_found_naming_thumbprint_store_and_location_when_absent()
    {
        Assert.SkipUnless(OperatingSystem.IsWindows(), "requires a real Windows Certificate Store");

        var reader = new CertificateStoreReader();
        const string missingThumbprint = "0000000000000000000000000000000000000A";

        var act = () => reader.GetCertificate(missingThumbprint, StoreLocation.CurrentUser, StoreName.My);

        act.Should().Throw<ZeeKayDaConfigurationException>()
            .WithMessage("*certificate_not_found*")
            .WithMessage($"*{missingThumbprint}*")
            .WithMessage("*My*")
            .WithMessage("*CurrentUser*");
    }

    // ── Real store-backed handle-outlives-certificate contract (security review informational #2) ──
    // WindowsCertificateKeyExtractorTests proves the general BCL contract (an extracted handle
    // survives disposing its parent certificate) cross-platform, against in-memory
    // CertificateRequest.CreateSelfSigned certificates. This test proves the same contract holds for
    // the actual production code path this provider depends on: a certificate installed into a real
    // Windows Certificate Store, read back via CertificateStoreReader (which returns an independent
    // copy per GetCertificate's own contract), with its private key extracted and the returned
    // certificate then disposed before the extracted handle is used to sign — exactly the sequence
    // WindowsCertificateStoreSigningJwtSigningService.LoadKeysAsync performs. Running this on the
    // windows-latest CI runner automates the security-critical part of what would otherwise be a
    // manual smoke test.
    [Fact]
    public void GetCertificate_extracted_private_key_handle_signs_correctly_after_the_returned_certificate_is_disposed()
    {
        Assert.SkipUnless(OperatingSystem.IsWindows(), "requires a real Windows Certificate Store");

        // InstalledTestCertificate's constructor disposes the certificate passed into it (as part of
        // its own PFX-round-trip fix), so capture the public key parameters up front rather than
        // holding a reference to that certificate for later verification.
        using var testCertificate = TestCertificateFactory.CreateRsaSelfSigned("windows-cert-store-sign-test", T0 - TimeSpan.FromDays(1), T0 + TimeSpan.FromDays(365));
        var publicParameters = testCertificate.GetRSAPublicKey()!.ExportParameters(includePrivateParameters: false);
        using var installed = new InstalledTestCertificate(testCertificate);
        var reader = new CertificateStoreReader();

        using var found = reader.GetCertificate(ThumbprintFormat.Normalize(installed.Thumbprint), StoreLocation.CurrentUser, StoreName.My);
        var (privateKey, keyType) = WindowsCertificateKeyExtractor.ExtractPrivateKey(found, installed.Thumbprint);

        keyType.Should().Be(SigningKeyType.Rsa);
        var payload = "windows-certificate-store-signing-provider"u8.ToArray();
        var signature = ((RSA)privateKey).SignData(payload, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        privateKey.Dispose();

        using var publicRsa = RSA.Create();
        publicRsa.ImportParameters(publicParameters);
        publicRsa.VerifyData(payload, signature, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1)
            .Should().BeTrue("the signature produced by the handle extracted from a real store-backed certificate, after that certificate was disposed, must verify against the original certificate's public key");
    }

    [Fact]
    public void GetCertificate_normalizes_thumbprint_with_embedded_whitespace()
    {
        Assert.SkipUnless(OperatingSystem.IsWindows(), "requires a real Windows Certificate Store");

        using var testCertificate = TestCertificateFactory.CreateRsaSelfSigned("windows-cert-store-test-2", T0 - TimeSpan.FromDays(1), T0 + TimeSpan.FromDays(365));
        using var installed = new InstalledTestCertificate(testCertificate);
        var reader = new CertificateStoreReader();
        var spacedOut = string.Join(" ", installed.Thumbprint.Chunk(2).Select(c => new string(c)));

        using var found = reader.GetCertificate(ThumbprintFormat.Normalize(spacedOut), StoreLocation.CurrentUser, StoreName.My);

        found.Thumbprint.Should().Be(installed.Thumbprint);
    }
}
