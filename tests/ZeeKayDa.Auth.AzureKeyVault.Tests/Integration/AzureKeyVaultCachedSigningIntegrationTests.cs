// These tests exercise the full DI wiring for AddAzureKeyVaultCachedSigning end to end — a real
// ServiceCollection / ZeeKayDaAuthBuilder / ServiceProvider, driven through the host's real startup
// path — with a fake substituted for the IKeyVaultCertificateReader seam. No real network calls are
// made and no live Azure Key Vault access is required or attempted. The same KNOWN GAP note as
// AzureKeyVaultRemoteSigningIntegrationTests applies: recorded-session tests against real Key Vault
// behaviour do not exist yet.
//
// The vault is read exactly once, at startup, and never re-read — asserted below by rotating a new
// version into the fake vault after startup and observing that nothing published changes.

using System.Security.Cryptography;
using Azure.Security.KeyVault.Certificates;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Time.Testing;
using ZeeKayDa.Auth.AzureKeyVault.Tests.Fakes;
using ZeeKayDa.Auth.Tokens;

namespace ZeeKayDa.Auth.AzureKeyVault.Tests.Integration;

public sealed class AzureKeyVaultCachedSigningIntegrationTests
{
    private static readonly Uri CertificateIdentifierUri = new("https://fake-vault.vault.azure.net/certificates/fake-cert");
    private static readonly KeyVaultCertificateIdentifier CertificateIdentifier = new(CertificateIdentifierUri);
    private static readonly DateTimeOffset T0 = DateTimeOffset.Parse("2026-01-01T00:00:00Z");

    private static (ServiceCollection Services, FakeKeyVaultCertificateReader Reader, FakeTimeProvider TimeProvider)
        BuildServices(DateTimeOffset now)
    {
        var reader = new FakeKeyVaultCertificateReader();
        var timeProvider = new FakeTimeProvider(now);
        var services = new ServiceCollection();
        services.AddSingleton(typeof(ILogger<>), typeof(NullLogger<>));
        services.AddSingleton<IKeyVaultCertificateReader>(reader);
        services.AddSingleton<TimeProvider>(timeProvider);
        return (services, reader, timeProvider);
    }

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
    public async Task Full_DI_wiring_serves_a_key_vault_certificate_through_the_ring_and_signs_a_JWS_locally()
    {
        var ct = TestContext.Current.CancellationToken;
        var (services, reader, _) = BuildServices(T0);
        reader.AddRsaVersion("v1", createdOn: T0);

        var builder = new ZeeKayDaAuthBuilder(services);
        builder.AddAzureKeyVaultCachedSigning(CertificateIdentifier, SigningAlgorithm.RS256, new FakeTokenCredential());

        await using var provider = services.BuildServiceProvider();
        await StartHostedServicesAsync(provider, ct);
        var ring = provider.GetRequiredService<ISigningKeyRing>();

        ring.Current.Published.Should().ContainSingle();
        ring.Current.SigningKey.Kid.Should().Be(JwkThumbprint.Compute(reader.GetRsaMaterial("v1")),
            "kid must be the RFC 7638 thumbprint of the public key");
        ring.Current.SigningKey.Kid.Should().NotContain("fake-vault").And.NotContain("fake-cert").And.NotContain("v1",
            "kid must never leak vault, certificate, or version identifiers");
        ring.Current.AdvertisedAlgorithms.Should().Equal(SigningAlgorithm.RS256);

        var signingInput = "header.payload"u8.ToArray();
        var outcome = await ring.SignAsync(signingInput, static (_, input) => input, ct);

        using var rsa = RSA.Create(ring.Current.SigningKey.PublicKey.RsaPublicParameters!.Value);
        rsa.VerifyData(outcome.SigningInput.Span, outcome.Signature.Span, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1)
            .Should().BeTrue("the ring must sign locally with the downloaded private key of the published version");
    }

    [Fact]
    public async Task Full_DI_wiring_downloads_private_material_for_exactly_the_signing_version()
    {
        var ct = TestContext.Current.CancellationToken;
        var now = T0 + TimeSpan.FromDays(30);
        var (services, reader, _) = BuildServices(now);
        reader.AddRsaVersion("v1", createdOn: T0);
        reader.AddRsaVersion("v2", createdOn: T0 + TimeSpan.FromDays(10));
        reader.AddRsaVersion("v3", createdOn: now - TimeSpan.FromHours(1)); // Younger than the delay -> staged.

        var builder = new ZeeKayDaAuthBuilder(services);
        builder.AddAzureKeyVaultCachedSigning(CertificateIdentifier, SigningAlgorithm.RS256, new FakeTokenCredential());

        await using var provider = services.BuildServiceProvider();
        await StartHostedServicesAsync(provider, ct);
        var ring = provider.GetRequiredService<ISigningKeyRing>();

        ring.Current.Published.Should().HaveCount(3,
            "the signing version, one previous version (the default count), and the staged version are all published");
        ring.Current.SigningKey.Kid.Should().Be(JwkThumbprint.Compute(reader.GetRsaMaterial("v2")));
        reader.PrivateKeyMaterialCalls.Should().Equal(["v2"],
            "startup — including the ring's signing self-test — downloads private material for the " +
            "signing version only; published-only versions stay public-key-only");
    }

    [Fact]
    public async Task Full_DI_wiring_keeps_publishing_the_startup_key_set_when_the_vault_rotates_afterwards()
    {
        var ct = TestContext.Current.CancellationToken;
        var (services, reader, timeProvider) = BuildServices(T0);
        reader.AddRsaVersion("v1", createdOn: T0);

        var builder = new ZeeKayDaAuthBuilder(services);
        builder.AddAzureKeyVaultCachedSigning(CertificateIdentifier, SigningAlgorithm.RS256, new FakeTokenCredential());

        await using var provider = services.BuildServiceProvider();
        await StartHostedServicesAsync(provider, ct);
        var ring = provider.GetRequiredService<ISigningKeyRing>();
        var publishedAtStartup = ring.Current.Published.Select(k => k.Kid).ToArray();

        reader.AddRsaVersion("v2", createdOn: T0 + TimeSpan.FromMinutes(1));
        timeProvider.SetUtcNow(T0 + TimeSpan.FromDays(30));

        ring.Current.Published.Select(k => k.Kid).Should().Equal(publishedAtStartup,
            "the vault is read exactly once, at startup — a rotation is only picked up by restarting the host");
    }

    // ── Startup failure propagation ───────────────────────────────────────────────────────────────

    [Fact]
    public async Task Startup_fails_closed_when_the_certificate_has_no_versions()
    {
        var ct = TestContext.Current.CancellationToken;
        var (services, _, _) = BuildServices(T0); // No versions registered.

        var builder = new ZeeKayDaAuthBuilder(services);
        builder.AddAzureKeyVaultCachedSigning(CertificateIdentifier, SigningAlgorithm.RS256, new FakeTokenCredential());

        await using var provider = services.BuildServiceProvider();

        var act = async () => await StartHostedServicesAsync(provider, ct);

        (await act.Should().ThrowAsync<ZeeKayDaConfigurationException>())
            .WithMessage("*no_certificate_versions*");
    }

    [Fact]
    public async Task Startup_fails_closed_when_the_secret_and_the_Cer_diverge()
    {
        // The tamper-evidence cross-check: the private key downloaded from the linked secret must
        // match the public key published from the Cer, and the divergence must reach the startup
        // output NAMED — a configuration failure the ring absorbs verbatim, never a generic
        // signer_unavailable that reads as transient.
        var ct = TestContext.Current.CancellationToken;
        var (services, reader, _) = BuildServices(T0);
        reader.AddRsaVersion("v1", createdOn: T0);
        using var divergedKey = RSA.Create(2048);
        reader.SetMismatchedPrivateKeyMaterial("v1", divergedKey.ExportParameters(includePrivateParameters: true));

        var builder = new ZeeKayDaAuthBuilder(services);
        builder.AddAzureKeyVaultCachedSigning(CertificateIdentifier, SigningAlgorithm.RS256, new FakeTokenCredential());

        await using var provider = services.BuildServiceProvider();

        var act = async () => await StartHostedServicesAsync(provider, ct);

        (await act.Should().ThrowAsync<ZeeKayDaConfigurationException>())
            .WithMessage("*secret_cer_mismatch*does not match*");
    }

    [Fact]
    public async Task Startup_fails_closed_when_the_configured_algorithm_does_not_match_the_key_type()
    {
        // The source itself performs no algorithm/key-type check — SigningKeySetBuilder does, keyed
        // on the source id, so the failure must still name the offending certificate version.
        var ct = TestContext.Current.CancellationToken;
        var (services, reader, _) = BuildServices(T0);
        reader.AddRsaVersion("v1", createdOn: T0);

        var builder = new ZeeKayDaAuthBuilder(services);
        builder.AddAzureKeyVaultCachedSigning(CertificateIdentifier, SigningAlgorithm.ES256, new FakeTokenCredential());

        await using var provider = services.BuildServiceProvider();

        var act = async () => await StartHostedServicesAsync(provider, ct);

        (await act.Should().ThrowAsync<ZeeKayDaConfigurationException>())
            .WithMessage("*v1*");
    }
}
