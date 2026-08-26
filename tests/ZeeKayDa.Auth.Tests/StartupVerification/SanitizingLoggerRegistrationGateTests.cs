using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using ZeeKayDa.Auth.Logging;

namespace ZeeKayDa.Auth.Tests.StartupVerification;

public sealed class SanitizingLoggerRegistrationGateTests
{
    [Fact]
    public async Task VerifyAsync_records_no_failures_when_resolved_logger_is_genuine_and_no_closed_overrides_exist()
    {
        var logger = new SecretSanitizingLogger<SanitizingLoggerRegistrationGate>(
            NullLogger<SanitizingLoggerRegistrationGate>.Instance,
            Options.Create(new AuthorizationServerOptions()));
        var scanner = new SanitizingLoggerClosedOverrideScanner(new ServiceCollection());
        var sut = new SanitizingLoggerRegistrationGate(logger, scanner);
        var context = new StartupVerificationContext();

        await sut.VerifyAsync(context, new ServiceCollection().BuildServiceProvider(), TestContext.Current.CancellationToken);

        context.Failures.Should().BeEmpty();
    }

    [Fact]
    public async Task VerifyAsync_records_a_failure_when_ISanitizingLogger_has_been_shadowed_at_the_open_generic_level()
    {
        var shadowingLogger = NullSanitizingLogger<SanitizingLoggerRegistrationGate>.Instance;
        var scanner = new SanitizingLoggerClosedOverrideScanner(new ServiceCollection());
        var sut = new SanitizingLoggerRegistrationGate(shadowingLogger, scanner);
        var context = new StartupVerificationContext();

        await sut.VerifyAsync(context, new ServiceCollection().BuildServiceProvider(), TestContext.Current.CancellationToken);

        context.Failures.Should().ContainSingle()
            .Which.Code.Should().Be("logging.sanitizing_logger_shadowed");
    }

    [Fact]
    public async Task VerifyAsync_records_a_failure_when_a_closed_generic_ISanitizingLogger_override_exists()
    {
        var logger = new SecretSanitizingLogger<SanitizingLoggerRegistrationGate>(
            NullLogger<SanitizingLoggerRegistrationGate>.Instance,
            Options.Create(new AuthorizationServerOptions()));

        var services = new ServiceCollection();
        services.AddSingleton<ISanitizingLogger<SomeShadowedService>>(
            NullSanitizingLogger<SomeShadowedService>.Instance);
        var scanner = new SanitizingLoggerClosedOverrideScanner(services);

        var sut = new SanitizingLoggerRegistrationGate(logger, scanner);
        var context = new StartupVerificationContext();

        await sut.VerifyAsync(context, new ServiceCollection().BuildServiceProvider(), TestContext.Current.CancellationToken);

        context.Failures.Should().ContainSingle()
            .Which.Code.Should().Be("logging.sanitizing_logger_closed_override");
        context.Failures.Single().Message.Should().Contain(typeof(SomeShadowedService).FullName);
    }

    [Fact]
    public async Task VerifyAsync_aggregates_both_failures_when_both_kinds_of_shadowing_exist()
    {
        var shadowingLogger = NullSanitizingLogger<SanitizingLoggerRegistrationGate>.Instance;

        var services = new ServiceCollection();
        services.AddSingleton<ISanitizingLogger<SomeShadowedService>>(
            NullSanitizingLogger<SomeShadowedService>.Instance);
        var scanner = new SanitizingLoggerClosedOverrideScanner(services);

        var sut = new SanitizingLoggerRegistrationGate(shadowingLogger, scanner);
        var context = new StartupVerificationContext();

        await sut.VerifyAsync(context, new ServiceCollection().BuildServiceProvider(), TestContext.Current.CancellationToken);

        context.Failures.Select(f => f.Code).Should().BeEquivalentTo(
            "logging.sanitizing_logger_shadowed",
            "logging.sanitizing_logger_closed_override");
    }

    private sealed class SomeShadowedService;
}
