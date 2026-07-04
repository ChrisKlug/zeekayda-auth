// These tests exercise the full DI wiring for AddAzureKeyVaultRemoteSigning end to end — a real
// ServiceCollection / ZeeKayDaAuthBuilder / ServiceProvider — with fakes substituted for the two
// Key Vault seams (IKeyVaultKeyReader / IKeyVaultSigner). No real network calls are made and no
// live Azure Key Vault access is required or attempted.
//
// KNOWN GAP: real Azure.Core.TestFramework recorded-session tests against actual Key Vault
// behavior (exception-status mapping in KeyVaultKeyReader/KeyVaultSigner, real EC signature
// format, real CryptographyClient throttling responses) do not exist yet and would be a valuable
// follow-up — this file is not equivalent to that coverage, only to the DI-wiring/service-behavior
// slice that fakes can exercise.

using Azure.Security.KeyVault.Keys;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using Microsoft.Extensions.Time.Testing;
using ZeeKayDa.Auth.AzureKeyVault.Tests.Fakes;
using ZeeKayDa.Auth.Tokens;

namespace ZeeKayDa.Auth.AzureKeyVault.Tests.Integration;

public sealed class AzureKeyVaultRemoteSigningIntegrationTests
{
    private static readonly Uri KeyIdentifierUri = new("https://fake-vault.vault.azure.net/keys/fake-key");
    private static readonly KeyVaultKeyIdentifier KeyIdentifier = new(KeyIdentifierUri);

    // ── End-to-end: resolve, list keys, sign ─────────────────────────────────────────────────────

    [Fact]
    public async Task Full_DI_wiring_resolves_IJwtSigningService_and_returns_a_well_formed_signing_key()
    {
        var ct = TestContext.Current.CancellationToken;
        var t0 = DateTimeOffset.Parse("2026-01-01T00:00:00Z");
        var reader = new FakeKeyVaultKeyReader();
        reader.AddRsaVersion("v1", createdOn: t0);

        var services = new ServiceCollection();
        services.AddSingleton(typeof(ILogger<>), typeof(NullLogger<>));
        services.AddSingleton<IKeyVaultKeyReader>(reader);
        services.AddSingleton<IKeyVaultSigner>(new FakeKeyVaultSigner());
        services.AddSingleton<ISigningKeyRetirementWindowProvider>(new FakeRetirementWindowProvider(TimeSpan.FromHours(1)));
        services.AddSingleton<TimeProvider>(new FakeTimeProvider(t0));

        var builder = new ZeeKayDaAuthBuilder(services);
        builder.AddAzureKeyVaultRemoteSigning(KeyIdentifier, new FakeTokenCredential());

        await using var provider = services.BuildServiceProvider();
        var signingService = provider.GetRequiredService<IJwtSigningService>();

        var keys = await signingService.GetSigningKeysAsync(ct);

        keys.Should().ContainSingle();
        keys[0].Kid.Should().NotBeNullOrEmpty();
        keys[0].Algorithm.Should().Be(SigningAlgorithm.RS256, "the default AzureKeyVaultRemoteSigningOptions.Algorithm is RS256");
        keys[0].RsaPublicParameters.Should().NotBeNull("no private key material should be reachable anywhere from the descriptor");
    }

    [Fact]
    public async Task Full_DI_wiring_SignAsync_produces_a_well_formed_signing_result()
    {
        var ct = TestContext.Current.CancellationToken;
        var t0 = DateTimeOffset.Parse("2026-01-01T00:00:00Z");
        var reader = new FakeKeyVaultKeyReader();
        reader.AddRsaVersion("v1", createdOn: t0);

        var services = new ServiceCollection();
        services.AddSingleton(typeof(ILogger<>), typeof(NullLogger<>));
        services.AddSingleton<IKeyVaultKeyReader>(reader);
        services.AddSingleton<IKeyVaultSigner>(new FakeKeyVaultSigner());
        services.AddSingleton<ISigningKeyRetirementWindowProvider>(new FakeRetirementWindowProvider(TimeSpan.FromHours(1)));
        services.AddSingleton<TimeProvider>(new FakeTimeProvider(t0));

        var builder = new ZeeKayDaAuthBuilder(services);
        builder.AddAzureKeyVaultRemoteSigning(KeyIdentifier, new FakeTokenCredential());

        await using var provider = services.BuildServiceProvider();
        var signingService = provider.GetRequiredService<IJwtSigningService>();

        var result = await signingService.SignAsync("payload"u8.ToArray(), ct);

        result.Kid.Should().NotBeNullOrEmpty();
        result.Algorithm.Should().Be(SigningAlgorithm.RS256);
        result.SignatureSegment.ToArray().Should().NotBeEmpty();
        result.HeaderSegment.ToArray().Should().NotBeEmpty();
    }

    // ── Startup failure propagation ───────────────────────────────────────────────────────────────

    [Fact]
    public async Task Full_DI_wiring_surfaces_key_reader_failure_as_ZeeKayDaConfigurationException()
    {
        // The fake IKeyVaultKeyReader does NOT perform its own status-code-to-exception-code
        // mapping — only the real KeyVaultKeyReader does that (see the known-gap note in
        // KeyVaultKeyReader.cs). This test verifies that a failure from the reader seam propagates
        // through LoadKeysAsync/GetSigningKeysAsync as a ZeeKayDaConfigurationException (wiring),
        // not that any particular status code maps to any particular failure code.
        var ct = TestContext.Current.CancellationToken;
        var t0 = DateTimeOffset.Parse("2026-01-01T00:00:00Z");
        var reader = new FakeKeyVaultKeyReader();
        // No versions registered — the real service throws its own "no_key_versions"
        // ZeeKayDaConfigurationException in this situation, exercising the same propagation path a
        // real bad-credentials/missing-key condition from KeyVaultKeyReader would take.

        var services = new ServiceCollection();
        services.AddSingleton(typeof(ILogger<>), typeof(NullLogger<>));
        services.AddSingleton<IKeyVaultKeyReader>(reader);
        services.AddSingleton<IKeyVaultSigner>(new FakeKeyVaultSigner());
        services.AddSingleton<ISigningKeyRetirementWindowProvider>(new FakeRetirementWindowProvider(TimeSpan.FromHours(1)));
        services.AddSingleton<TimeProvider>(new FakeTimeProvider(t0));

        var builder = new ZeeKayDaAuthBuilder(services);
        builder.AddAzureKeyVaultRemoteSigning(KeyIdentifier, new FakeTokenCredential());

        await using var provider = services.BuildServiceProvider();
        var signingService = provider.GetRequiredService<IJwtSigningService>();

        var act = async () => await signingService.GetSigningKeysAsync(ct);

        (await act.Should().ThrowAsync<ZeeKayDaConfigurationException>())
            .WithMessage("*no_key_versions*");
    }

    [Fact]
    public async Task Full_DI_wiring_surfaces_an_arbitrary_reader_fault_as_ZeeKayDaConfigurationException()
    {
        // Simulates a bad-credentials/missing-key condition surfacing from the reader seam. Since
        // the fake does not do its own exception mapping, we configure it to throw the SAME
        // exception type LoadKeysAsync itself would throw for a real configuration problem, to
        // prove the failure reaches the caller unmodified through the full DI-resolved service —
        // not to assert on a mapped error code the fake cannot produce.
        var ct = TestContext.Current.CancellationToken;
        var t0 = DateTimeOffset.Parse("2026-01-01T00:00:00Z");
        var reader = new FakeKeyVaultKeyReader
        {
            VersionsException = new ZeeKayDaConfigurationException(
                new ZeeKayDaConfigurationFailure(
                    "signing.azure_key_vault.access_denied",
                    "Simulated bad-credentials failure from the Key Vault reader seam.")),
        };

        var services = new ServiceCollection();
        services.AddSingleton(typeof(ILogger<>), typeof(NullLogger<>));
        services.AddSingleton<IKeyVaultKeyReader>(reader);
        services.AddSingleton<IKeyVaultSigner>(new FakeKeyVaultSigner());
        services.AddSingleton<ISigningKeyRetirementWindowProvider>(new FakeRetirementWindowProvider(TimeSpan.FromHours(1)));
        services.AddSingleton<TimeProvider>(new FakeTimeProvider(t0));

        var builder = new ZeeKayDaAuthBuilder(services);
        builder.AddAzureKeyVaultRemoteSigning(KeyIdentifier, new FakeTokenCredential());

        await using var provider = services.BuildServiceProvider();
        var signingService = provider.GetRequiredService<IJwtSigningService>();

        var act = async () => await signingService.GetSigningKeysAsync(ct);

        (await act.Should().ThrowAsync<ZeeKayDaConfigurationException>())
            .WithMessage("*access_denied*");
    }

    // ── Startup activator ─────────────────────────────────────────────────────────────────────────
    // A full Microsoft.Extensions.Hosting generic host was considered here (per the plan) but adds
    // disproportionate scaffolding (a new package reference just for this test project) for the
    // value it provides over exercising AzureKeyVaultSigningStartupActivator.StartAsync directly,
    // which is exactly what the generic host would end up calling anyway. Constructing and calling
    // the activator directly, with a signing service that fails to load its keys, is a simpler and
    // equally faithful way to prove that a configuration fault aborts "startup" (StartAsync).

    [Fact]
    public async Task StartupActivator_StartAsync_forces_key_loading_and_propagates_configuration_failure()
    {
        var ct = TestContext.Current.CancellationToken;
        var t0 = DateTimeOffset.Parse("2026-01-01T00:00:00Z");
        var reader = new FakeKeyVaultKeyReader(); // No versions registered -> no_key_versions.

        var options = Options.Create(new AzureKeyVaultRemoteSigningOptions
        {
            KeyIdentifier = KeyIdentifier,
            Credential = new FakeTokenCredential(),
            Algorithm = SigningAlgorithm.RS256,
            RefreshInterval = TimeSpan.FromMinutes(5),
        });

        await using var signingService = new AzureKeyVaultRemoteSigningJwtSigningService(
            options,
            new FakeTimeProvider(t0),
            reader,
            new FakeKeyVaultSigner(),
            new FakeRetirementWindowProvider(TimeSpan.FromHours(1)),
            NullSanitizingLogger<AzureKeyVaultRemoteSigningJwtSigningService>.Instance);

        var activator = new AzureKeyVaultSigningStartupActivator(signingService);

        var act = async () => await activator.StartAsync(ct);

        (await act.Should().ThrowAsync<ZeeKayDaConfigurationException>())
            .WithMessage("*no_key_versions*");
    }

    [Fact]
    public async Task StartupActivator_StartAsync_succeeds_when_signing_keys_load_without_error()
    {
        var ct = TestContext.Current.CancellationToken;
        var t0 = DateTimeOffset.Parse("2026-01-01T00:00:00Z");
        var reader = new FakeKeyVaultKeyReader();
        reader.AddRsaVersion("v1", createdOn: t0);

        var options = Options.Create(new AzureKeyVaultRemoteSigningOptions
        {
            KeyIdentifier = KeyIdentifier,
            Credential = new FakeTokenCredential(),
            Algorithm = SigningAlgorithm.RS256,
            RefreshInterval = TimeSpan.FromMinutes(5),
        });

        await using var signingService = new AzureKeyVaultRemoteSigningJwtSigningService(
            options,
            new FakeTimeProvider(t0),
            reader,
            new FakeKeyVaultSigner(),
            new FakeRetirementWindowProvider(TimeSpan.FromHours(1)),
            NullSanitizingLogger<AzureKeyVaultRemoteSigningJwtSigningService>.Instance);

        var activator = new AzureKeyVaultSigningStartupActivator(signingService);

        var act = async () => await activator.StartAsync(ct);

        await act.Should().NotThrowAsync();
    }
}
