using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.FileProviders;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using ZeeKayDa.Auth;
using ZeeKayDa.Auth.Logging;
using ZeeKayDa.Auth.StartupVerification;

namespace ZeeKayDa.Auth.Tests.Logging;

/// <summary>
/// The startup record of disabled exception sanitizing: absent unless the host opted in, and louder
/// outside the environment where opting in is the expected thing to do.
/// </summary>
public sealed class ExceptionSanitizingDisabledVerifierTests
{
    private static readonly IServiceProvider EmptyProvider = new ServiceCollection().BuildServiceProvider();

    private sealed class FakeHostEnvironment(string environmentName) : IHostEnvironment
    {
        public string EnvironmentName { get; set; } = environmentName;
        public string ApplicationName { get; set; } = "TestApp";
        public string ContentRootPath { get; set; } = "/";
        public IFileProvider ContentRootFileProvider { get; set; } = new NullFileProvider();
    }

    private static async Task<StartupVerificationContext> VerifyAsync(string environment, bool disableExceptionSanitizing)
    {
        var options = new AuthorizationServerOptions();
        options.Development.DisableExceptionSanitizing = disableExceptionSanitizing;
        var sut = new ExceptionSanitizingDisabledVerifier(Options.Create(options), new FakeHostEnvironment(environment));
        var context = new StartupVerificationContext();

        await sut.VerifyAsync(context, EmptyProvider, TestContext.Current.CancellationToken);

        return context;
    }

    [Fact]
    public async Task Disabled_sanitizing_in_Development_logs_at_Information()
    {
        var context = await VerifyAsync(Environments.Development, disableExceptionSanitizing: true);

        var warning = context.Warnings.Should().ContainSingle().Which;
        warning.Code.Should().Be("logging.exception_sanitizing_disabled");
        warning.Level.Should().Be(LogLevel.Information);
        warning.MessageTemplate.Should().Be(ExceptionSanitizingDisabledVerifier.ActiveMessage);
    }

    [Theory]
    [InlineData("Production")]
    [InlineData("Staging")]
    public async Task Disabled_sanitizing_outside_Development_logs_at_Critical(string environment)
    {
        var context = await VerifyAsync(environment, disableExceptionSanitizing: true);

        var warning = context.Warnings.Should().ContainSingle().Which;
        warning.Code.Should().Be("logging.exception_sanitizing_disabled_outside_development");
        warning.Level.Should().Be(LogLevel.Critical);
        warning.MessageTemplate.Should().Be(ExceptionSanitizingDisabledVerifier.NonDevelopmentCriticalMessage);
    }

    [Theory]
    [InlineData("Development")]
    [InlineData("Production")]
    public async Task Disabled_sanitizing_never_fails_startup(string environment)
    {
        var context = await VerifyAsync(environment, disableExceptionSanitizing: true);

        context.Failures.Should().BeEmpty();
    }

    [Theory]
    [InlineData("Development")]
    [InlineData("Production")]
    public async Task With_sanitizing_on_nothing_is_recorded(string environment)
    {
        var context = await VerifyAsync(environment, disableExceptionSanitizing: false);

        context.Warnings.Should().BeEmpty();
        context.Failures.Should().BeEmpty();
    }
}
