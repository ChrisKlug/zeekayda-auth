using Microsoft.Extensions.DependencyInjection;
using ZeeKayDa.Auth.Logging;

namespace ZeeKayDa.Auth.AspNetCore.Tests;

public sealed class SanitizingLoggerClosedOverrideScannerTests
{
    [Fact]
    public void FindClosedGenericOverrides_returns_empty_when_only_the_open_generic_is_registered()
    {
        var services = new ServiceCollection();
        services.AddSingleton(typeof(ISanitizingLogger<>), typeof(SecretSanitizingLogger<>));

        var sut = new SanitizingLoggerClosedOverrideScanner(services);

        sut.FindClosedGenericOverrides().Should().BeEmpty();
    }

    [Fact]
    public void FindClosedGenericOverrides_returns_empty_for_an_empty_collection()
    {
        var sut = new SanitizingLoggerClosedOverrideScanner(new ServiceCollection());

        sut.FindClosedGenericOverrides().Should().BeEmpty();
    }

    [Fact]
    public void FindClosedGenericOverrides_finds_a_closed_generic_registration()
    {
        var services = new ServiceCollection();
        services.AddSingleton<ISanitizingLogger<SomeService>>(
            NullSanitizingLogger<SomeService>.Instance);

        var sut = new SanitizingLoggerClosedOverrideScanner(services);

        sut.FindClosedGenericOverrides().Should().ContainSingle()
            .Which.Should().Be(typeof(ISanitizingLogger<SomeService>));
    }

    [Fact]
    public void FindClosedGenericOverrides_deduplicates_multiple_registrations_for_the_same_closed_type()
    {
        var services = new ServiceCollection();
        services.AddSingleton<ISanitizingLogger<SomeService>>(
            NullSanitizingLogger<SomeService>.Instance);
        services.AddSingleton<ISanitizingLogger<SomeService>>(
            NullSanitizingLogger<SomeService>.Instance);

        var sut = new SanitizingLoggerClosedOverrideScanner(services);

        sut.FindClosedGenericOverrides().Should().ContainSingle();
    }

    [Fact]
    public void FindClosedGenericOverrides_reflects_registrations_added_after_construction()
    {
        // The scanner captures the IServiceCollection reference itself, not a snapshot, so it must
        // see registrations added after the scanner was constructed but before the collection is
        // built — the same way a host registering after AddZeeKayDaAuth() is still visible.
        var services = new ServiceCollection();
        var sut = new SanitizingLoggerClosedOverrideScanner(services);

        services.AddSingleton<ISanitizingLogger<SomeService>>(
            NullSanitizingLogger<SomeService>.Instance);

        sut.FindClosedGenericOverrides().Should().ContainSingle()
            .Which.Should().Be(typeof(ISanitizingLogger<SomeService>));
    }

    [Fact]
    public void FindClosedGenericOverrides_ignores_unrelated_generic_registrations()
    {
        var services = new ServiceCollection();
        services.AddSingleton<IReadOnlyList<SomeService>>([]);

        var sut = new SanitizingLoggerClosedOverrideScanner(services);

        sut.FindClosedGenericOverrides().Should().BeEmpty();
    }

    private sealed class SomeService;
}
