// These tests exercise the full DI wiring for AddAzureKeyVaultRemoteSigning end to end — a real
// ServiceCollection / ZeeKayDaAuthBuilder / ServiceProvider, driven through the host's real startup
// path — with fakes substituted for the two Key Vault seams (IKeyVaultKeyReader / IKeyVaultSigner).
// No real network calls are made and no live Azure Key Vault access is required or attempted.
//
// KNOWN GAP: real Azure.Core.TestFramework recorded-session tests against actual Key Vault
// behavior (exception-status mapping in KeyVaultKeyReader/KeyVaultSigner, real EC signature
// format, real CryptographyClient throttling responses) do not exist yet and would be a valuable
// follow-up — this file is not equivalent to that coverage, only to the DI-wiring/ring-behavior
// slice that fakes can exercise.
//
// The vault is read exactly once, at startup, and never re-read, so there is no reload or
// change-detection surface here — which is itself asserted below, by rotating a new version into
// the fake vault after startup and observing that nothing published changes.

using System.Security.Cryptography;
using Azure.Security.KeyVault.Keys;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Time.Testing;
using ZeeKayDa.Auth.AzureKeyVault.Tests.Fakes;
using ZeeKayDa.Auth.Tokens;

namespace ZeeKayDa.Auth.AzureKeyVault.Tests.Integration;

public sealed class AzureKeyVaultRemoteSigningIntegrationTests
{
    private static readonly Uri KeyIdentifierUri = new("https://fake-vault.vault.azure.net/keys/fake-key");
    private static readonly KeyVaultKeyIdentifier KeyIdentifier = new(KeyIdentifierUri);
    private static readonly DateTimeOffset T0 = DateTimeOffset.Parse("2026-01-01T00:00:00Z");

    private static (ServiceCollection Services, FakeKeyVaultKeyReader Reader, FakeKeyVaultSigner Signer, FakeTimeProvider TimeProvider)
        BuildServices(DateTimeOffset now)
    {
        var reader = new FakeKeyVaultKeyReader();
        var timeProvider = new FakeTimeProvider(now);
        // The ring's startup self-test verifies a real signature against the published public key,
        // so the fake seam must produce a genuinely verifiable signature rather than a placeholder.
        var signer = new FakeKeyVaultSigner
        {
            SignFunc = (uri, _, _, signingInput) =>
            {
                var version = uri.Segments[^1];
                using var rsa = reader.CreateRsaPrivateKey(version);
                return rsa.SignData(signingInput, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
            },
        };

        var services = new ServiceCollection();
        services.AddSingleton(typeof(ILogger<>), typeof(NullLogger<>));
        services.AddSingleton<IKeyVaultKeyReader>(reader);
        services.AddSingleton<IKeyVaultSigner>(signer);
        services.AddSingleton<TimeProvider>(timeProvider);
        return (services, reader, signer, timeProvider);
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
    public async Task Full_DI_wiring_serves_a_key_vault_key_through_the_ring_and_signs_a_JWS_remotely()
    {
        var ct = TestContext.Current.CancellationToken;
        var (services, reader, signer, _) = BuildServices(T0);
        reader.AddRsaVersion("v1", createdOn: T0);

        var builder = new ZeeKayDaAuthBuilder(services);
        builder.AddAzureKeyVaultRemoteSigning(KeyIdentifier, SigningAlgorithm.RS256, new FakeTokenCredential());

        await using var provider = services.BuildServiceProvider();
        await StartHostedServicesAsync(provider, ct);
        var ring = provider.GetRequiredService<ISigningKeyRing>();

        ring.Current.Published.Should().ContainSingle();
        ring.Current.SigningKey.Kid.Should().Be(JwkThumbprint.Compute(reader.GetRsaMaterial("v1")),
            "kid must be the RFC 7638 thumbprint of the public key");
        ring.Current.SigningKey.Kid.Should().NotContain("fake-vault").And.NotContain("fake-key").And.NotContain("v1",
            "kid must never leak vault, key, or version identifiers");
        ring.Current.AdvertisedAlgorithms.Should().Equal(SigningAlgorithm.RS256);

        var signingInput = "header.payload"u8.ToArray();
        var outcome = await ring.SignAsync(signingInput, static (_, input) => input, ct);

        using var rsa = RSA.Create(ring.Current.SigningKey.PublicKey.RsaPublicParameters!.Value);
        rsa.VerifyData(outcome.SigningInput.Span, outcome.Signature.Span, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1)
            .Should().BeTrue("the ring must sign via the remote Key Vault seam with the published key");
        signer.Calls.Should().NotBeEmpty("every signature is a remote Key Vault round trip — nothing signs locally");
    }

    [Fact]
    public async Task Full_DI_wiring_publishes_previous_and_staged_versions_alongside_the_signing_one()
    {
        var ct = TestContext.Current.CancellationToken;
        var now = T0 + TimeSpan.FromDays(30);
        var (services, reader, _, _) = BuildServices(now);
        reader.AddRsaVersion("v1", createdOn: T0);
        reader.AddRsaVersion("v2", createdOn: T0 + TimeSpan.FromDays(10));
        reader.AddRsaVersion("v3", createdOn: now - TimeSpan.FromHours(1)); // Younger than the delay -> staged.

        var builder = new ZeeKayDaAuthBuilder(services);
        builder.AddAzureKeyVaultRemoteSigning(KeyIdentifier, SigningAlgorithm.RS256, new FakeTokenCredential());

        await using var provider = services.BuildServiceProvider();
        await StartHostedServicesAsync(provider, ct);
        var ring = provider.GetRequiredService<ISigningKeyRing>();

        ring.Current.Published.Should().HaveCount(3,
            "the signing version, one previous version (the default count), and the staged version are all published");
        ring.Current.SigningKey.Kid.Should().Be(JwkThumbprint.Compute(reader.GetRsaMaterial("v2")),
            "v2 is the newest version older than the pre-activation delay");
    }

    [Fact]
    public async Task Full_DI_wiring_keeps_publishing_the_startup_key_set_when_the_vault_rotates_afterwards()
    {
        var ct = TestContext.Current.CancellationToken;
        var (services, reader, _, timeProvider) = BuildServices(T0);
        reader.AddRsaVersion("v1", createdOn: T0);

        var builder = new ZeeKayDaAuthBuilder(services);
        builder.AddAzureKeyVaultRemoteSigning(KeyIdentifier, SigningAlgorithm.RS256, new FakeTokenCredential());

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
    public async Task Startup_fails_closed_when_the_key_has_no_versions()
    {
        var ct = TestContext.Current.CancellationToken;
        var (services, _, _, _) = BuildServices(T0); // No versions registered.

        var builder = new ZeeKayDaAuthBuilder(services);
        builder.AddAzureKeyVaultRemoteSigning(KeyIdentifier, SigningAlgorithm.RS256, new FakeTokenCredential());

        await using var provider = services.BuildServiceProvider();

        var act = async () => await StartHostedServicesAsync(provider, ct);

        (await act.Should().ThrowAsync<ZeeKayDaConfigurationException>())
            .WithMessage("*no_key_versions*");
    }

    [Fact]
    public async Task Startup_fails_closed_when_a_reader_fault_occurs_rather_than_serving_a_partial_key_set()
    {
        // The fake IKeyVaultKeyReader does NOT perform its own status-code-to-exception-code
        // mapping — only the real KeyVaultKeyReader does that. This test verifies that a failure
        // from the reader seam propagates through the ring's startup read unmodified, never as a
        // smaller published set.
        var ct = TestContext.Current.CancellationToken;
        var (services, reader, _, _) = BuildServices(T0);
        reader.AddRsaVersion("v1", createdOn: T0);
        reader.VersionsException = new ZeeKayDaConfigurationException(
            new ZeeKayDaConfigurationFailure(
                "signing.azure_key_vault.access_denied",
                "Simulated bad-credentials failure from the Key Vault reader seam."));

        var builder = new ZeeKayDaAuthBuilder(services);
        builder.AddAzureKeyVaultRemoteSigning(KeyIdentifier, SigningAlgorithm.RS256, new FakeTokenCredential());

        await using var provider = services.BuildServiceProvider();

        var act = async () => await StartHostedServicesAsync(provider, ct);

        (await act.Should().ThrowAsync<ZeeKayDaConfigurationException>())
            .WithMessage("*access_denied*");
    }

    [Fact]
    public async Task Startup_fails_closed_when_the_configured_algorithm_does_not_match_the_key_type()
    {
        // The source itself performs no algorithm/key-type check — SigningKeySetBuilder does, keyed
        // on the source id, so the failure must still name the offending Key Vault version.
        var ct = TestContext.Current.CancellationToken;
        var (services, reader, _, _) = BuildServices(T0);
        reader.AddRsaVersion("v1", createdOn: T0);

        var builder = new ZeeKayDaAuthBuilder(services);
        builder.AddAzureKeyVaultRemoteSigning(KeyIdentifier, SigningAlgorithm.ES256, new FakeTokenCredential());

        await using var provider = services.BuildServiceProvider();

        var act = async () => await StartHostedServicesAsync(provider, ct);

        (await act.Should().ThrowAsync<ZeeKayDaConfigurationException>())
            .WithMessage("*v1*");
    }
}
