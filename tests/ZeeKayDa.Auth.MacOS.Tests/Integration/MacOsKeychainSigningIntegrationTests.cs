// These tests exercise the full DI wiring for AddMacOsKeychainSigning end to end — a real
// ServiceCollection / ZeeKayDaAuthBuilder / ServiceProvider — with a fake substituted for the
// IKeychainItemReader seam. No real macOS Keychain access is made or required.
//
// AddMacOsKeychainSigning's platform gate (AC #11) fires unconditionally before any DI wiring, so —
// unlike the rotation-timeline/descriptor-factory unit tests, which are pure functions and run on any
// OS — every test here that calls the real extension method can only run on macOS. Each test is
// individually skip-guarded rather than the whole class, matching the pattern already established in
// Extensions/ZeeKayDaAuthBuilderMacOsKeychainSigningExtensionsTests.cs.

using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Time.Testing;
using ZeeKayDa.Auth.Logging;
using ZeeKayDa.Auth.MacOS.Tests.Fakes;
using ZeeKayDa.Auth.MacOS.Tests.Fixtures;
using ZeeKayDa.Auth.Tokens;

namespace ZeeKayDa.Auth.MacOS.Tests.Integration;

public sealed class MacOsKeychainSigningIntegrationTests
{
    private static readonly DateTimeOffset T0 = DateTimeOffset.Parse("2026-01-01T00:00:00Z");
    private const string RequiresMacOsReason = "AddMacOsKeychainSigning's platform gate fires unconditionally, before any DI wiring";

    private static (ServiceCollection Services, FakeKeychainItemReader Reader, FakeTimeProvider TimeProvider) BuildServices(
        DateTimeOffset now, TimeSpan? retirementWindow = null)
    {
        var reader = new FakeKeychainItemReader();
        var timeProvider = new FakeTimeProvider(now);
        var services = new ServiceCollection();
        services.AddSingleton(typeof(ILogger<>), typeof(NullLogger<>));
        services.AddSingleton<IKeychainItemReader>(reader);
        services.AddSingleton<ISigningKeyRetirementWindowProvider>(new FakeRetirementWindowProvider(retirementWindow ?? TimeSpan.FromHours(1)));
        services.AddSingleton<TimeProvider>(timeProvider);
        return (services, reader, timeProvider);
    }

    [Fact]
    public async Task Full_DI_wiring_resolves_and_returns_a_well_formed_signing_key_for_one_certificate()
    {
        Assert.SkipUnless(OperatingSystem.IsMacOS(), RequiresMacOsReason);

        var ct = TestContext.Current.CancellationToken;
        var (services, reader, _) = BuildServices(T0);
        using var certificate = TestKeyFactory.CreateRsaSelfSigned("test", T0 + TimeSpan.FromDays(1), T0 + TimeSpan.FromDays(365));
        reader.AddCertificate("primary", certificate);

        var builder = new ZeeKayDaAuthBuilder(services);
        builder.AddMacOsKeychainSigning("primary");

        await using var provider = services.BuildServiceProvider();
        var signingService = provider.GetRequiredService<IJwtSigningService>();

        var keys = await signingService.GetSigningKeysAsync(ct);

        keys.Should().ContainSingle("the single registered item activates immediately regardless of NotBefore (AC #6)");
        keys[0].Kid.Should().NotBeNullOrEmpty();
        keys[0].Kid.Should().NotContain("primary", "kid must be the RFC 7638 thumbprint, never the Keychain label (AC #3)");
        keys[0].Algorithm.Should().Be(SigningAlgorithm.RS256);
        keys[0].RsaPublicParameters.Should().NotBeNull();
    }

    [Fact]
    public async Task Full_DI_wiring_JWKS_output_includes_both_keys_during_a_rotation_overlap()
    {
        Assert.SkipUnless(OperatingSystem.IsMacOS(), RequiresMacOsReason);

        var ct = TestContext.Current.CancellationToken;
        var (services, reader, _) = BuildServices(T0);
        using var primary = TestKeyFactory.CreateRsaSelfSigned("primary", T0 - TimeSpan.FromDays(30), T0 + TimeSpan.FromDays(365));
        using var secondary = TestKeyFactory.CreateRsaSelfSigned("secondary", T0 + TimeSpan.FromDays(1), T0 + TimeSpan.FromDays(400));
        reader.AddCertificate("primary", primary);
        reader.AddCertificate("secondary", secondary);

        var builder = new ZeeKayDaAuthBuilder(services);
        builder.AddMacOsKeychainSigning("primary", configure: options => options.AddKey("secondary"));

        await using var provider = services.BuildServiceProvider();
        var signingService = provider.GetRequiredService<IJwtSigningService>();

        var keys = await signingService.GetSigningKeysAsync(ct);

        keys.Should().HaveCount(2, "AC #4: both keys must be exposed during the overlap window");
    }

    [Fact]
    public async Task Full_DI_wiring_surfaces_item_not_found_as_ZeeKayDaConfigurationException()
    {
        Assert.SkipUnless(OperatingSystem.IsMacOS(), RequiresMacOsReason);

        var ct = TestContext.Current.CancellationToken;
        var (services, _, _) = BuildServices(T0); // Nothing registered.

        var builder = new ZeeKayDaAuthBuilder(services);
        builder.AddMacOsKeychainSigning("primary");

        await using var provider = services.BuildServiceProvider();
        var signingService = provider.GetRequiredService<IJwtSigningService>();

        var act = async () => await signingService.GetSigningKeysAsync(ct);

        (await act.Should().ThrowAsync<ZeeKayDaConfigurationException>()).WithMessage("*item_not_found*");
    }

    [Fact]
    public async Task StartupService_StartAsync_forces_key_loading_and_propagates_configuration_failure()
    {
        Assert.SkipUnless(OperatingSystem.IsMacOS(), RequiresMacOsReason);

        var ct = TestContext.Current.CancellationToken;
        var (services, _, _) = BuildServices(T0); // Nothing registered.

        var builder = new ZeeKayDaAuthBuilder(services);
        builder.AddMacOsKeychainSigning("primary");

        await using var provider = services.BuildServiceProvider();
        var startupService = provider.GetServices<IHostedService>().OfType<MacOsKeychainSigningStartupService>().Single();

        var act = async () => await startupService.StartAsync(ct);

        (await act.Should().ThrowAsync<ZeeKayDaConfigurationException>()).WithMessage("*item_not_found*");
    }

    [Fact]
    public async Task StartupService_StartAsync_succeeds_when_item_loads_without_error()
    {
        Assert.SkipUnless(OperatingSystem.IsMacOS(), RequiresMacOsReason);

        var ct = TestContext.Current.CancellationToken;
        var (services, reader, _) = BuildServices(T0);
        using var certificate = TestKeyFactory.CreateRsaSelfSigned("test", T0 - TimeSpan.FromDays(1), T0 + TimeSpan.FromDays(365));
        reader.AddCertificate("primary", certificate);

        var builder = new ZeeKayDaAuthBuilder(services);
        builder.AddMacOsKeychainSigning("primary");

        await using var provider = services.BuildServiceProvider();
        var startupService = provider.GetServices<IHostedService>().OfType<MacOsKeychainSigningStartupService>().Single();

        var act = async () => await startupService.StartAsync(ct);

        await act.Should().NotThrowAsync();
    }
}
