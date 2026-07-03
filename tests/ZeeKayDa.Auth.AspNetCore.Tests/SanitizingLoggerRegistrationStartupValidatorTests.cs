using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using ZeeKayDa.Auth.Logging;

namespace ZeeKayDa.Auth.AspNetCore.Tests;

public sealed class SanitizingLoggerRegistrationStartupValidatorTests
{
    [Fact]
    public async Task StartAsync_does_not_throw_when_resolved_logger_is_genuine_and_no_closed_overrides_exist()
    {
        var logger = new SecretSanitizingLogger<SanitizingLoggerRegistrationStartupValidator>(
            NullLogger<SanitizingLoggerRegistrationStartupValidator>.Instance,
            Options.Create(new AuthorizationServerOptions()));
        var scanner = new SanitizingLoggerClosedOverrideScanner(new ServiceCollection());

        var sut = new SanitizingLoggerRegistrationStartupValidator(logger, scanner);

        await sut.Awaiting(s => s.StartAsync(CancellationToken.None)).Should().NotThrowAsync();
    }

    [Fact]
    public async Task StartAsync_throws_when_ISanitizingLogger_has_been_shadowed_at_the_open_generic_level()
    {
        var shadowingLogger =
            NullSanitizingLogger<SanitizingLoggerRegistrationStartupValidator>.Instance;
        var scanner = new SanitizingLoggerClosedOverrideScanner(new ServiceCollection());

        var sut = new SanitizingLoggerRegistrationStartupValidator(shadowingLogger, scanner);

        var exception = await sut
            .Awaiting(s => s.StartAsync(CancellationToken.None))
            .Should().ThrowAsync<ZeeKayDaConfigurationException>();

        exception.Which.AggregatedFailures.Should().ContainSingle()
            .Which.Code.Should().Be("logging.sanitizing_logger_shadowed");
    }

    [Fact]
    public async Task StartAsync_throws_when_a_closed_generic_ISanitizingLogger_override_exists()
    {
        var logger = new SecretSanitizingLogger<SanitizingLoggerRegistrationStartupValidator>(
            NullLogger<SanitizingLoggerRegistrationStartupValidator>.Instance,
            Options.Create(new AuthorizationServerOptions()));

        var services = new ServiceCollection();
        services.AddSingleton<ISanitizingLogger<SomeShadowedService>>(
            NullSanitizingLogger<SomeShadowedService>.Instance);
        var scanner = new SanitizingLoggerClosedOverrideScanner(services);

        var sut = new SanitizingLoggerRegistrationStartupValidator(logger, scanner);

        var exception = await sut
            .Awaiting(s => s.StartAsync(CancellationToken.None))
            .Should().ThrowAsync<ZeeKayDaConfigurationException>();

        exception.Which.AggregatedFailures.Should().ContainSingle()
            .Which.Code.Should().Be("logging.sanitizing_logger_closed_override");
        exception.Which.Message.Should().Contain(typeof(SomeShadowedService).FullName);
    }

    [Fact]
    public async Task StartAsync_aggregates_both_failures_when_both_kinds_of_shadowing_exist()
    {
        var shadowingLogger =
            NullSanitizingLogger<SanitizingLoggerRegistrationStartupValidator>.Instance;

        var services = new ServiceCollection();
        services.AddSingleton<ISanitizingLogger<SomeShadowedService>>(
            NullSanitizingLogger<SomeShadowedService>.Instance);
        var scanner = new SanitizingLoggerClosedOverrideScanner(services);

        var sut = new SanitizingLoggerRegistrationStartupValidator(shadowingLogger, scanner);

        var exception = await sut
            .Awaiting(s => s.StartAsync(CancellationToken.None))
            .Should().ThrowAsync<ZeeKayDaConfigurationException>();

        exception.Which.AggregatedFailures.Select(f => f.Code).Should().BeEquivalentTo(
            "logging.sanitizing_logger_shadowed",
            "logging.sanitizing_logger_closed_override");
    }

    [Fact]
    public void Constructor_throws_ArgumentNullException_for_null_logger()
    {
        var scanner = new SanitizingLoggerClosedOverrideScanner(new ServiceCollection());

        var act = () => new SanitizingLoggerRegistrationStartupValidator(null!, scanner);

        act.Should().Throw<ArgumentNullException>();
    }

    [Fact]
    public void Constructor_throws_ArgumentNullException_for_null_closedOverrideScanner()
    {
        var logger = NullSanitizingLogger<SanitizingLoggerRegistrationStartupValidator>.Instance;

        var act = () => new SanitizingLoggerRegistrationStartupValidator(logger, null!);

        act.Should().Throw<ArgumentNullException>();
    }

    private sealed class SomeShadowedService;
}
