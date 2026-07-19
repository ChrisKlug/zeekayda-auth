// These tests exercise the full DI wiring for AddAzureKeyVaultCachedSigning end to end — a real
// ServiceCollection / ZeeKayDaAuthBuilder / ServiceProvider — with a fake substituted for the
// IKeyVaultCertificateReader seam. No real network calls are made and no live Azure Key Vault
// access is required or attempted.
//
// KNOWN GAP: real Azure.Core.TestFramework recorded-session tests against actual Key Vault
// behavior (the real KeyVaultCertificateReader's exception-status mapping, real PKCS#12 secret
// download, non-exportable-policy detection against a live vault) do not exist yet — this mirrors
// the equivalent documented gap for AddAzureKeyVaultRemoteSigning and would be a valuable
// follow-up. This file is not equivalent to that coverage, only to the DI-wiring/service-behavior
// slice that a fake reader can exercise. KeyVaultCertificateReaderTests.cs separately exercises the
// real reader's private-key-extraction logic directly (via reflection), without any network access.

using Azure.Security.KeyVault.Certificates;
using Microsoft.Extensions.DependencyInjection;
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

    // ── End-to-end: resolve, list keys (JWKS shape), sign ───────────────────────────────────────

    [Fact]
    public async Task Full_DI_wiring_resolves_IJwtSigningService_and_returns_a_well_formed_signing_key()
    {
        var ct = TestContext.Current.CancellationToken;
        var t0 = DateTimeOffset.Parse("2026-01-01T00:00:00Z");
        var reader = new FakeKeyVaultCertificateReader();
        reader.AddRsaVersion("v1", createdOn: t0);

        var services = new ServiceCollection();
        services.AddSingleton(typeof(ILogger<>), typeof(NullLogger<>));
        services.AddSingleton<IKeyVaultCertificateReader>(reader);
        services.AddSingleton<ISigningKeyRetirementWindowProvider>(new FakeRetirementWindowProvider(TimeSpan.FromHours(1)));
        services.AddSingleton<TimeProvider>(new FakeTimeProvider(t0));

        var builder = new ZeeKayDaAuthBuilder(services);
        builder.AddAzureKeyVaultCachedSigning(CertificateIdentifier, SigningAlgorithm.RS256, new FakeTokenCredential());

        await using var provider = services.BuildServiceProvider();
        var signingService = provider.GetRequiredService<IJwtSigningService>();

        var keys = await signingService.GetSigningKeysAsync(ct);

        keys.Should().ContainSingle();
        keys[0].Kid.Should().NotBeNullOrEmpty();
        keys[0].Kid.Should().NotContain("fake-vault", "kid must be the RFC 7638 thumbprint, never a Key Vault identifier (AC #3)");
        keys[0].Algorithm.Should().Be(SigningAlgorithm.RS256, "the configured algorithm was RS256");
        keys[0].RsaPublicParameters.Should().NotBeNull("the JWKS entry must expose only the public key");
    }

    [Fact]
    public async Task Full_DI_wiring_JWKS_output_includes_both_versions_during_a_rotation_overlap()
    {
        // AC #4: two certificate versions with overlapping validity windows must both be exposed.
        var ct = TestContext.Current.CancellationToken;
        var t0 = DateTimeOffset.Parse("2026-01-01T00:00:00Z");
        var refreshInterval = TimeSpan.FromMinutes(5);
        var reader = new FakeKeyVaultCertificateReader();
        reader.AddRsaVersion("v1", createdOn: t0);

        var timeProvider = new FakeTimeProvider(t0);
        var services = new ServiceCollection();
        services.AddSingleton(typeof(ILogger<>), typeof(NullLogger<>));
        services.AddSingleton<IKeyVaultCertificateReader>(reader);
        services.AddSingleton<ISigningKeyRetirementWindowProvider>(new FakeRetirementWindowProvider(TimeSpan.FromHours(1)));
        services.AddSingleton<TimeProvider>(timeProvider);

        var builder = new ZeeKayDaAuthBuilder(services);
        builder.AddAzureKeyVaultCachedSigning(CertificateIdentifier, SigningAlgorithm.RS256, new FakeTokenCredential(),
            configure: options => options.KeySourceRefreshInterval = refreshInterval);

        await using var provider = services.BuildServiceProvider();
        var signingService = provider.GetRequiredService<IJwtSigningService>();
        await signingService.GetSigningKeysAsync(ct); // Bootstrap.

        var t1 = t0 + TimeSpan.FromDays(1);
        reader.AddRsaVersion("v2", createdOn: t1);
        timeProvider.SetUtcNow(t1); // Cache has expired -> v2 is discovered and published.

        var keys = await signingService.GetSigningKeysAsync(ct);

        keys.Should().HaveCount(2, "both versions must appear in the JWKS output during the overlap window");
    }

    [Fact]
    public async Task Full_DI_wiring_SignAsync_produces_a_well_formed_signing_result()
    {
        var ct = TestContext.Current.CancellationToken;
        var t0 = DateTimeOffset.Parse("2026-01-01T00:00:00Z");
        var reader = new FakeKeyVaultCertificateReader();
        reader.AddRsaVersion("v1", createdOn: t0);

        var services = new ServiceCollection();
        services.AddSingleton(typeof(ILogger<>), typeof(NullLogger<>));
        services.AddSingleton<IKeyVaultCertificateReader>(reader);
        services.AddSingleton<ISigningKeyRetirementWindowProvider>(new FakeRetirementWindowProvider(TimeSpan.FromHours(1)));
        services.AddSingleton<TimeProvider>(new FakeTimeProvider(t0));

        var builder = new ZeeKayDaAuthBuilder(services);
        builder.AddAzureKeyVaultCachedSigning(CertificateIdentifier, SigningAlgorithm.RS256, new FakeTokenCredential());

        await using var provider = services.BuildServiceProvider();
        var signingService = provider.GetRequiredService<IJwtSigningService>();

        var result = await signingService.SignAsync("payload"u8.ToArray(), ct);

        result.Kid.Should().NotBeNullOrEmpty();
        result.Algorithm.Should().Be(SigningAlgorithm.RS256);
        result.SignatureSegment.ToArray().Should().NotBeEmpty();
        result.HeaderSegment.ToArray().Should().NotBeEmpty();
    }

    // ── Startup failure propagation (AC #9: non-exportable, bad credentials) ────────────────────

    [Fact]
    public async Task Full_DI_wiring_surfaces_non_exportable_certificate_failure_as_ZeeKayDaConfigurationException()
    {
        var ct = TestContext.Current.CancellationToken;
        var t0 = DateTimeOffset.Parse("2026-01-01T00:00:00Z");
        var reader = new FakeKeyVaultCertificateReader();
        reader.AddRsaVersion("v1", createdOn: t0);
        reader.SetPrivateKeyException("v1", new ZeeKayDaConfigurationException(
            new ZeeKayDaConfigurationFailure(
                "signing.azure_key_vault.certificate_not_exportable",
                "Simulated non-exportable certificate policy failure.")));

        var services = new ServiceCollection();
        services.AddSingleton(typeof(ILogger<>), typeof(NullLogger<>));
        services.AddSingleton<IKeyVaultCertificateReader>(reader);
        services.AddSingleton<ISigningKeyRetirementWindowProvider>(new FakeRetirementWindowProvider(TimeSpan.FromHours(1)));
        services.AddSingleton<TimeProvider>(new FakeTimeProvider(t0));

        var builder = new ZeeKayDaAuthBuilder(services);
        builder.AddAzureKeyVaultCachedSigning(CertificateIdentifier, SigningAlgorithm.RS256, new FakeTokenCredential());

        await using var provider = services.BuildServiceProvider();
        var signingService = provider.GetRequiredService<IJwtSigningService>();

        var act = async () => await signingService.GetSigningKeysAsync(ct);

        (await act.Should().ThrowAsync<ZeeKayDaConfigurationException>())
            .WithMessage("*certificate_not_exportable*");
    }

    [Fact]
    public async Task Full_DI_wiring_surfaces_bad_credentials_failure_as_ZeeKayDaConfigurationException()
    {
        var ct = TestContext.Current.CancellationToken;
        var t0 = DateTimeOffset.Parse("2026-01-01T00:00:00Z");
        var reader = new FakeKeyVaultCertificateReader
        {
            VersionsException = new ZeeKayDaConfigurationException(
                new ZeeKayDaConfigurationFailure(
                    "signing.azure_key_vault.access_denied",
                    "Simulated bad-credentials failure from the Key Vault certificate reader seam.")),
        };

        var services = new ServiceCollection();
        services.AddSingleton(typeof(ILogger<>), typeof(NullLogger<>));
        services.AddSingleton<IKeyVaultCertificateReader>(reader);
        services.AddSingleton<ISigningKeyRetirementWindowProvider>(new FakeRetirementWindowProvider(TimeSpan.FromHours(1)));
        services.AddSingleton<TimeProvider>(new FakeTimeProvider(t0));

        var builder = new ZeeKayDaAuthBuilder(services);
        builder.AddAzureKeyVaultCachedSigning(CertificateIdentifier, SigningAlgorithm.RS256, new FakeTokenCredential());

        await using var provider = services.BuildServiceProvider();
        var signingService = provider.GetRequiredService<IJwtSigningService>();

        var act = async () => await signingService.GetSigningKeysAsync(ct);

        (await act.Should().ThrowAsync<ZeeKayDaConfigurationException>())
            .WithMessage("*access_denied*");
    }

    [Fact]
    public async Task Full_DI_wiring_surfaces_certificate_not_found_failure_as_ZeeKayDaConfigurationException()
    {
        var ct = TestContext.Current.CancellationToken;
        var t0 = DateTimeOffset.Parse("2026-01-01T00:00:00Z");
        var reader = new FakeKeyVaultCertificateReader
        {
            VersionsException = new ZeeKayDaConfigurationException(
                new ZeeKayDaConfigurationFailure(
                    "signing.azure_key_vault.certificate_not_found",
                    "Simulated missing-certificate failure from the Key Vault certificate reader seam.")),
        };

        var services = new ServiceCollection();
        services.AddSingleton(typeof(ILogger<>), typeof(NullLogger<>));
        services.AddSingleton<IKeyVaultCertificateReader>(reader);
        services.AddSingleton<ISigningKeyRetirementWindowProvider>(new FakeRetirementWindowProvider(TimeSpan.FromHours(1)));
        services.AddSingleton<TimeProvider>(new FakeTimeProvider(t0));

        var builder = new ZeeKayDaAuthBuilder(services);
        builder.AddAzureKeyVaultCachedSigning(CertificateIdentifier, SigningAlgorithm.RS256, new FakeTokenCredential());

        await using var provider = services.BuildServiceProvider();
        var signingService = provider.GetRequiredService<IJwtSigningService>();

        var act = async () => await signingService.GetSigningKeysAsync(ct);

        (await act.Should().ThrowAsync<ZeeKayDaConfigurationException>())
            .WithMessage("*certificate_not_found*");
    }

    // ── Startup service: pre-warm + informational log (AC #1, #2) ───────────────────────────────

    [Fact]
    public async Task StartupService_StartAsync_forces_key_loading_and_propagates_configuration_failure()
    {
        var ct = TestContext.Current.CancellationToken;
        var t0 = DateTimeOffset.Parse("2026-01-01T00:00:00Z");
        var reader = new FakeKeyVaultCertificateReader(); // No versions registered -> no_certificate_versions.

        var services = new ServiceCollection();
        services.AddSingleton(typeof(ILogger<>), typeof(NullLogger<>));
        services.AddSingleton<IKeyVaultCertificateReader>(reader);
        services.AddSingleton<ISigningKeyRetirementWindowProvider>(new FakeRetirementWindowProvider(TimeSpan.FromHours(1)));
        services.AddSingleton<TimeProvider>(new FakeTimeProvider(t0));

        var builder = new ZeeKayDaAuthBuilder(services);
        builder.AddAzureKeyVaultCachedSigning(CertificateIdentifier, SigningAlgorithm.RS256, new FakeTokenCredential());

        await using var provider = services.BuildServiceProvider();
        var hostedServices = provider.GetServices<Microsoft.Extensions.Hosting.IHostedService>().ToList();
        var startupService = hostedServices.OfType<AzureKeyVaultCachedSigningStartupService>().Single();

        var act = async () => await startupService.StartAsync(ct);

        (await act.Should().ThrowAsync<ZeeKayDaConfigurationException>())
            .WithMessage("*no_certificate_versions*");
    }

    [Fact]
    public async Task StartupService_StartAsync_succeeds_when_certificate_loads_without_error()
    {
        var ct = TestContext.Current.CancellationToken;
        var t0 = DateTimeOffset.Parse("2026-01-01T00:00:00Z");
        var reader = new FakeKeyVaultCertificateReader();
        reader.AddRsaVersion("v1", createdOn: t0);

        var services = new ServiceCollection();
        services.AddSingleton(typeof(ILogger<>), typeof(NullLogger<>));
        services.AddSingleton<IKeyVaultCertificateReader>(reader);
        services.AddSingleton<ISigningKeyRetirementWindowProvider>(new FakeRetirementWindowProvider(TimeSpan.FromHours(1)));
        services.AddSingleton<TimeProvider>(new FakeTimeProvider(t0));

        var builder = new ZeeKayDaAuthBuilder(services);
        builder.AddAzureKeyVaultCachedSigning(CertificateIdentifier, SigningAlgorithm.RS256, new FakeTokenCredential());

        await using var provider = services.BuildServiceProvider();
        var hostedServices = provider.GetServices<Microsoft.Extensions.Hosting.IHostedService>().ToList();
        var startupService = hostedServices.OfType<AzureKeyVaultCachedSigningStartupService>().Single();

        var act = async () => await startupService.StartAsync(ct);

        await act.Should().NotThrowAsync();
    }
}
