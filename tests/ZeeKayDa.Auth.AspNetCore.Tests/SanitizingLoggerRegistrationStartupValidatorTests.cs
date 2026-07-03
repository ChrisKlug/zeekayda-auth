using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using ZeeKayDa.Auth.Logging;

namespace ZeeKayDa.Auth.AspNetCore.Tests;

public sealed class SanitizingLoggerRegistrationStartupValidatorTests
{
    [Fact]
    public async Task StartAsync_does_not_throw_when_the_frameworks_own_SecretSanitizingLogger_is_resolved()
    {
        var logger = new SecretSanitizingLogger<SanitizingLoggerRegistrationStartupValidator>(
            NullLogger<SanitizingLoggerRegistrationStartupValidator>.Instance,
            Options.Create(new AuthorizationServerOptions()));

        var sut = new SanitizingLoggerRegistrationStartupValidator(logger);

        await sut.Awaiting(s => s.StartAsync(CancellationToken.None)).Should().NotThrowAsync();
    }

    [Fact]
    public async Task StartAsync_throws_ZeeKayDaConfigurationException_when_ISanitizingLogger_has_been_shadowed()
    {
        var shadowingLogger =
            NullSanitizingLogger<SanitizingLoggerRegistrationStartupValidator>.Instance;

        var sut = new SanitizingLoggerRegistrationStartupValidator(shadowingLogger);

        var exception = await sut
            .Awaiting(s => s.StartAsync(CancellationToken.None))
            .Should().ThrowAsync<ZeeKayDaConfigurationException>();

        exception.Which.AggregatedFailures.Should().ContainSingle()
            .Which.Code.Should().Be("logging.sanitizing_logger_shadowed");
    }

    [Fact]
    public void Constructor_throws_ArgumentNullException_for_null_logger()
    {
        var act = () => new SanitizingLoggerRegistrationStartupValidator(null!);

        act.Should().Throw<ArgumentNullException>();
    }
}
