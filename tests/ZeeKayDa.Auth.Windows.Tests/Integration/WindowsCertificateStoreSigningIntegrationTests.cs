// These tests exercise the full DI wiring for AddWindowsCertificateStoreSigning end to end — a real
// ServiceCollection / ZeeKayDaAuthCoreBuilder / ServiceProvider, driven through the host's real startup
// path — with a fake substituted for the ICertificateStoreReader seam. No real Windows Certificate
// Store access is made or required.
//
// AddWindowsCertificateStoreSigning's platform gate fires unconditionally before any DI wiring, so —
// unlike WindowsCertificateStoreSigningKeySourceTests, which constructs the source directly and runs
// on any OS — every test here can only run on Windows. Each test is individually skip-guarded rather
// than the whole class, matching the pattern in
// Extensions/ZeeKayDaAuthCoreBuilderWindowsCertificateStoreSigningExtensionsTests.cs.
//
// KNOWN GAP: a real ACL-denied X509Store.Open() (the store_inaccessible failure) is not practically
// provokable in CI, so it is only simulated here via the fake's ExceptionToThrow. The genuinely
// Windows-only real-store round trip is covered separately by Integration/CertificateStoreReaderTests.cs.
//
// The ring reads the source once, at startup, so nothing that happens to the store afterwards changes
// what this process signs with or publishes — which is itself asserted below, by removing a listed
// certificate from the store after startup and observing that nothing published changes.

using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Time.Testing;
using ZeeKayDa.Auth;
using ZeeKayDa.Auth.StartupVerification;
using ZeeKayDa.Auth.Tokens;
using ZeeKayDa.Auth.Windows.Tests.Fakes;
using ZeeKayDa.Auth.Windows.Tests.Fixtures;

namespace ZeeKayDa.Auth.Windows.Tests.Integration;

public sealed class WindowsCertificateStoreSigningIntegrationTests
{
    private static readonly DateTimeOffset T0 = DateTimeOffset.Parse("2026-01-01T00:00:00Z");
    private const string PreviousThumbprint = "1111111111111111111111111111111111111A";
    private const string CurrentThumbprint = "AABBCCDDEEFF00112233445566778899AABBCCD";
    private const string NextThumbprint = "2222222222222222222222222222222222222B";
    private const string RequiresWindowsReason = "AddWindowsCertificateStoreSigning's platform gate fires unconditionally, before any DI wiring";

    private static (ServiceCollection Services, FakeCertificateStoreReader Reader, FakeTimeProvider TimeProvider) BuildServices(
        DateTimeOffset now, TimeSpan? retirementWindow = null)
    {
        var reader = new FakeCertificateStoreReader();
        var timeProvider = new FakeTimeProvider(now);
        var services = new ServiceCollection();
        services.AddSingleton(typeof(ILogger<>), typeof(NullLogger<>));
        services.AddSingleton<ICertificateStoreReader>(reader);
        services.AddSingleton<TimeProvider>(timeProvider);
        return (services, reader, timeProvider);
    }

    private static CertificateLookup Lookup(string thumbprint) => CertificateLookup.ByThumbprint(thumbprint);

    /// <summary>
    /// Runs the host's real startup path — every registered <see cref="IHostedService"/>, which is
    /// what initializes the signing key ring — so these tests observe exactly what a deployed host
    /// observes, including a startup that fails.
    /// </summary>
    private static async Task StartHostedServicesAsync(ServiceProvider provider, CancellationToken cancellationToken)
    {
        foreach (var hostedService in provider.GetServices<IHostedService>())
            await hostedService.StartAsync(cancellationToken);
    }

    // ── End-to-end through the signing key ring ─────────────────────────────────────────────────

    [Fact]
    public async Task Full_DI_wiring_serves_a_certificate_store_key_through_the_ring_and_signs_a_JWS()
    {
        Assert.SkipUnless(OperatingSystem.IsWindows(), RequiresWindowsReason);

        var ct = TestContext.Current.CancellationToken;
        var (services, reader, _) = BuildServices(T0);
        using var certificate = TestCertificateFactory.CreateRsaSelfSigned("test", T0 - TimeSpan.FromDays(1), T0 + TimeSpan.FromDays(365));
        reader.AddCertificate(CurrentThumbprint, certificate);

        var builder = services.AddZeeKayDaAuthCoreForTesting();
        builder.AddWindowsCertificateStoreSigning(Lookup(CurrentThumbprint), SigningAlgorithm.RS256, StoreLocation.CurrentUser, StoreName.My);

        await using var provider = services.BuildServiceProvider();
        await StartHostedServicesAsync(provider, ct);
        var ring = provider.GetRequiredService<SigningKeyRing>();

        ring.Current.Published.Should().ContainSingle("the single listed certificate's public key must be published");
        ring.Current.SigningKey!.Kid.Should().Be(JwkThumbprint.Compute(certificate.GetRSAPublicKey()!.ExportParameters(false)));
        ring.Current.SigningKey!.Kid.Should().NotContain(CurrentThumbprint,
            "kid must be the RFC 7638 thumbprint, never the certificate's own store thumbprint");
        ring.Current.Algorithm.Should().Be(SigningAlgorithm.RS256);

        var signingInput = "header.payload"u8.ToArray();
        var outcome = await ring.SignAsync(signingInput, static (_, input) => input, ct);

        using var rsa = RSA.Create(ring.Current.SigningKey!.PublicKey.RsaPublicParameters!.Value);
        rsa.VerifyData(outcome.SigningInput.Span, outcome.Signature.Span, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1)
            .Should().BeTrue("the ring must sign with the private key of the published certificate");
    }

    [Fact]
    public async Task Full_DI_wiring_publishes_every_listed_certificate_and_signs_with_the_newer_one_past_the_lead_time()
    {
        Assert.SkipUnless(OperatingSystem.IsWindows(), RequiresWindowsReason);

        var ct = TestContext.Current.CancellationToken;
        var (services, reader, _) = BuildServices(T0);
        using var older = TestCertificateFactory.CreateRsaSelfSigned("older", T0 - TimeSpan.FromDays(400), T0 + TimeSpan.FromDays(30));
        // Just past the one-day lead time, so the newer certificate signs and the older one stays
        // published, still inside its own validity window.
        using var newer = TestCertificateFactory.CreateRsaSelfSigned("newer", T0 - TimeSpan.FromDays(1) - TimeSpan.FromMinutes(1), T0 + TimeSpan.FromDays(365));
        reader.AddCertificate(PreviousThumbprint, older);
        reader.AddCertificate(CurrentThumbprint, newer);

        var builder = services.AddZeeKayDaAuthCoreForTesting();
        builder.AddWindowsCertificateStoreSigning(SigningAlgorithm.RS256, StoreLocation.CurrentUser, StoreName.My, options =>
        {
            options.Certificates.Add(Lookup(PreviousThumbprint));
            options.Certificates.Add(Lookup(CurrentThumbprint));
        });

        await using var provider = services.BuildServiceProvider();
        await StartHostedServicesAsync(provider, ct);
        var ring = provider.GetRequiredService<SigningKeyRing>();

        ring.Current.Published.Should().HaveCount(2, "every listed certificate is published so relying parties can cache it");
        ring.Current.SigningKey!.Kid.Should().Be(JwkThumbprint.Compute(newer.GetRSAPublicKey()!.ExportParameters(false)));
    }

    [Fact]
    public async Task Full_DI_wiring_keeps_publishing_a_certificate_removed_from_the_store_after_startup()
    {
        // The ring reads the source once, at startup, so nothing that happens to the store afterwards
        // changes what this process signs with or publishes until it next reads it.
        Assert.SkipUnless(OperatingSystem.IsWindows(), RequiresWindowsReason);

        var ct = TestContext.Current.CancellationToken;
        var (services, reader, _) = BuildServices(T0);
        using var current = TestCertificateFactory.CreateRsaSelfSigned("current", T0 - TimeSpan.FromDays(1), T0 + TimeSpan.FromDays(365));
        using var next = TestCertificateFactory.CreateRsaSelfSigned("next", T0 + TimeSpan.FromDays(1), T0 + TimeSpan.FromDays(400));
        reader.AddCertificate(CurrentThumbprint, current);
        reader.AddCertificate(NextThumbprint, next);

        var builder = services.AddZeeKayDaAuthCoreForTesting();
        builder.AddWindowsCertificateStoreSigning(SigningAlgorithm.RS256, StoreLocation.CurrentUser, StoreName.My, options =>
        {
            options.Certificates.Add(Lookup(CurrentThumbprint));
            options.Certificates.Add(Lookup(NextThumbprint));
        });

        await using var provider = services.BuildServiceProvider();
        await StartHostedServicesAsync(provider, ct);
        var ring = provider.GetRequiredService<SigningKeyRing>();
        var publishedAtStartup = ring.Current.Published.Select(k => k.Kid).ToArray();

        reader.RemoveCertificate(CurrentThumbprint);
        reader.RemoveCertificate(NextThumbprint);

        ring.Current.Published.Select(k => k.Kid).Should().Equal(publishedAtStartup,
            "the JWKS a relying party sees must not change because a certificate left the store");

        var outcome = await ring.SignAsync("header.payload"u8.ToArray(), static (_, input) => input, ct);
        outcome.Key.Kid.Should().Be(JwkThumbprint.Compute(current.GetRSAPublicKey()!.ExportParameters(false)),
            "the signer was opened at startup and is held for the process lifetime");
    }

    // ── Startup failure propagation ─────────────────────────────────────────────────────────────

    [Fact]
    public async Task Full_DI_wiring_signs_with_the_only_certificate_even_before_its_NotBefore()
    {
        // NotBefore is no validity gate: no relying party can observe it, so a lone certificate dated
        // in the future signs at once rather than failing startup.
        Assert.SkipUnless(OperatingSystem.IsWindows(), RequiresWindowsReason);

        var ct = TestContext.Current.CancellationToken;
        var (services, reader, _) = BuildServices(T0);
        using var certificate = TestCertificateFactory.CreateRsaSelfSigned("future", T0 + TimeSpan.FromDays(1), T0 + TimeSpan.FromDays(400));
        reader.AddCertificate(CurrentThumbprint, certificate);

        var builder = services.AddZeeKayDaAuthCoreForTesting();
        builder.AddWindowsCertificateStoreSigning(Lookup(CurrentThumbprint), SigningAlgorithm.RS256, StoreLocation.CurrentUser, StoreName.My);

        await using var provider = services.BuildServiceProvider();
        await StartHostedServicesAsync(provider, ct);

        provider.GetRequiredService<SigningKeyRing>().Current.SigningKey!.Kid
            .Should().Be(JwkThumbprint.Compute(certificate.GetRSAPublicKey()!.ExportParameters(false)));
    }

    [Fact]
    public async Task Full_DI_wiring_starts_and_signs_on_when_the_only_certificate_has_expired()
    {
        Assert.SkipUnless(OperatingSystem.IsWindows(), RequiresWindowsReason);

        var ct = TestContext.Current.CancellationToken;
        var (services, reader, _) = BuildServices(T0);
        using var certificate = TestCertificateFactory.CreateRsaSelfSigned("expired", T0 - TimeSpan.FromDays(400), T0 - TimeSpan.FromDays(1));
        reader.AddCertificate(CurrentThumbprint, certificate);

        var builder = services.AddZeeKayDaAuthCoreForTesting();
        builder.AddWindowsCertificateStoreSigning(Lookup(CurrentThumbprint), SigningAlgorithm.RS256, StoreLocation.CurrentUser, StoreName.My);

        await using var provider = services.BuildServiceProvider();
        await StartHostedServicesAsync(provider, ct);

        var outcome = await provider.GetRequiredService<SigningKeyRing>()
            .SignAsync("header.payload"u8.ToArray(), static (_, input) => input, ct);
        outcome.Key.Kid.Should().Be(JwkThumbprint.Compute(certificate.GetRSAPublicKey()!.ExportParameters(false)));
        certificate.GetRSAPublicKey()!.VerifyData(
                "header.payload"u8.ToArray(), outcome.Signature.Span, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1)
            .Should().BeTrue();
    }

    [Fact]
    public async Task Full_DI_wiring_fails_startup_when_no_certificate_is_listed()
    {
        Assert.SkipUnless(OperatingSystem.IsWindows(), RequiresWindowsReason);

        var ct = TestContext.Current.CancellationToken;
        var (services, _, _) = BuildServices(T0);

        var builder = services.AddZeeKayDaAuthCoreForTesting();
        builder.AddWindowsCertificateStoreSigning(SigningAlgorithm.RS256, StoreLocation.CurrentUser, StoreName.My, _ => { });

        await using var provider = services.BuildServiceProvider();
        var act = async () => await StartHostedServicesAsync(provider, ct);

        (await act.Should().ThrowAsync<ZeeKayDaConfigurationException>())
            .Which.AggregatedFailures.Should().Contain(f => f.Code == "configuration.windows_certificate_store_signing.certificates.empty");
    }

    [Fact]
    public async Task Full_DI_wiring_fails_startup_when_the_same_certificate_is_listed_twice()
    {
        Assert.SkipUnless(OperatingSystem.IsWindows(), RequiresWindowsReason);

        var ct = TestContext.Current.CancellationToken;
        var (services, reader, _) = BuildServices(T0);
        using var certificate = TestCertificateFactory.CreateRsaSelfSigned("test", T0 - TimeSpan.FromDays(1), T0 + TimeSpan.FromDays(365));
        reader.AddCertificate(CurrentThumbprint, certificate);

        var builder = services.AddZeeKayDaAuthCoreForTesting();
        builder.AddWindowsCertificateStoreSigning(SigningAlgorithm.RS256, StoreLocation.CurrentUser, StoreName.My, options =>
        {
            options.Certificates.Add(Lookup(CurrentThumbprint));
            options.Certificates.Add(Lookup(CurrentThumbprint));
        });

        await using var provider = services.BuildServiceProvider();
        var act = async () => await StartHostedServicesAsync(provider, ct);

        (await act.Should().ThrowAsync<ZeeKayDaConfigurationException>())
            .Which.AggregatedFailures.Should().Contain(f => f.Code == "configuration.windows_certificate_store_signing.certificates.duplicate");
    }

    [Fact]
    public async Task Full_DI_wiring_fails_startup_with_no_keys_when_the_certificate_is_not_in_the_store()
    {
        Assert.SkipUnless(OperatingSystem.IsWindows(), RequiresWindowsReason);

        var ct = TestContext.Current.CancellationToken;
        var (services, _, _) = BuildServices(T0); // No certificate registered -> nothing listed.

        var builder = services.AddZeeKayDaAuthCoreForTesting();
        builder.AddWindowsCertificateStoreSigning(Lookup(CurrentThumbprint), SigningAlgorithm.RS256, StoreLocation.CurrentUser, StoreName.My);

        await using var provider = services.BuildServiceProvider();
        var act = async () => await StartHostedServicesAsync(provider, ct);

        (await act.Should().ThrowAsync<ZeeKayDaConfigurationException>()).WithMessage("*signing.no_keys*");
    }

    [Fact]
    public async Task Full_DI_wiring_surfaces_private_key_not_found_as_ZeeKayDaConfigurationException()
    {
        Assert.SkipUnless(OperatingSystem.IsWindows(), RequiresWindowsReason);

        var ct = TestContext.Current.CancellationToken;
        var (services, reader, _) = BuildServices(T0);
        using var certificate = TestCertificateFactory.CreateRsaSelfSigned(
            "test", T0 - TimeSpan.FromDays(1), T0 + TimeSpan.FromDays(365), withPrivateKey: false);
        reader.AddCertificate(CurrentThumbprint, certificate);

        var builder = services.AddZeeKayDaAuthCoreForTesting();
        builder.AddWindowsCertificateStoreSigning(Lookup(CurrentThumbprint), SigningAlgorithm.RS256, StoreLocation.CurrentUser, StoreName.My);

        await using var provider = services.BuildServiceProvider();

        // A read alone never needs a private key. The ring opens the signer at startup, so the
        // failure now surfaces there rather than on the first signing request.
        var act = async () => await StartHostedServicesAsync(provider, ct);

        (await act.Should().ThrowAsync<ZeeKayDaConfigurationException>()).WithMessage("*private_key_not_found*");
    }

    [Fact]
    public async Task Full_DI_wiring_surfaces_store_inaccessible_as_ZeeKayDaConfigurationException()
    {
        Assert.SkipUnless(OperatingSystem.IsWindows(), RequiresWindowsReason);

        var ct = TestContext.Current.CancellationToken;
        var (services, reader, _) = BuildServices(T0);
        reader.ExceptionToThrow = new ZeeKayDaConfigurationException(new ZeeKayDaConfigurationFailure(
            "signing.windows_certificate_store.store_inaccessible", "Simulated store-access failure."));

        var builder = services.AddZeeKayDaAuthCoreForTesting();
        builder.AddWindowsCertificateStoreSigning(Lookup(CurrentThumbprint), SigningAlgorithm.RS256, StoreLocation.CurrentUser, StoreName.My);

        await using var provider = services.BuildServiceProvider();
        var act = async () => await StartHostedServicesAsync(provider, ct);

        (await act.Should().ThrowAsync<ZeeKayDaConfigurationException>()).WithMessage("*store_inaccessible*");
    }

    // ── Startup verifier wiring ─────────────────────────────────────────────────────────────────

    [Fact]
    public async Task AddWindowsCertificateStoreSigning_registers_the_signing_key_ring_startup_verifier()
    {
        // Pins the wiring every test above depends on: without this verifier, a misconfigured signing
        // certificate would surface on the first request instead of failing the host.
        Assert.SkipUnless(OperatingSystem.IsWindows(), RequiresWindowsReason);

        var (services, reader, _) = BuildServices(T0);
        using var certificate = TestCertificateFactory.CreateRsaSelfSigned("test", T0 - TimeSpan.FromDays(1), T0 + TimeSpan.FromDays(365));
        reader.AddCertificate(CurrentThumbprint, certificate);

        var builder = services.AddZeeKayDaAuthCoreForTesting();
        builder.AddWindowsCertificateStoreSigning(Lookup(CurrentThumbprint), SigningAlgorithm.RS256, StoreLocation.CurrentUser, StoreName.My);

        await using var provider = services.BuildServiceProvider();
        provider.GetServices<IStartupActivator>().Select(v => v.Name).Should().Contain("SigningKeyRing");
    }
}
