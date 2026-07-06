// The genuinely Windows-only real-X509Store tests (AC #12). All gated with
// Assert.SkipUnless(OperatingSystem.IsWindows(), ...) so they run only on the windows-latest CI
// leg and skip cleanly (not error) everywhere else. Uses StoreLocation.CurrentUser/StoreName.My —
// the one combination that never requires elevated/admin rights, so it works unattended on a
// Windows CI runner.

using System.Security.Cryptography.X509Certificates;
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
