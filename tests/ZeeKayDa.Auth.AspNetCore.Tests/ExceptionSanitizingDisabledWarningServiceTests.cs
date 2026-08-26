using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;
using ZeeKayDa.Auth;
using ZeeKayDa.Auth.AspNetCore;

namespace ZeeKayDa.Auth.AspNetCore.Tests;

public sealed class ExceptionSanitizingDisabledWarningServiceTests
{
    private static readonly IServiceProvider EmptyProvider = new ServiceCollection().BuildServiceProvider();

    private static ExceptionSanitizingDisabledWarningService CreateSut(bool disableExceptionSanitizing)
    {
        var opts = new AuthorizationServerOptions();
        opts.Logging.DisableExceptionSanitizing = disableExceptionSanitizing;
        return new(Options.Create(opts));
    }

    [Fact]
    public async Task VerifyAsync_adds_a_warning_when_exception_sanitizing_is_disabled()
    {
        var sut = CreateSut(disableExceptionSanitizing: true);
        var context = new StartupVerificationContext();

        await sut.VerifyAsync(context, EmptyProvider, TestContext.Current.CancellationToken);

        context.Warnings.Should().ContainSingle();
    }

    [Fact]
    public async Task VerifyAsync_does_not_add_a_warning_when_exception_sanitizing_is_enabled()
    {
        var sut = CreateSut(disableExceptionSanitizing: false);
        var context = new StartupVerificationContext();

        await sut.VerifyAsync(context, EmptyProvider, TestContext.Current.CancellationToken);

        context.Warnings.Should().BeEmpty();
    }

    [Fact]
    public async Task VerifyAsync_adds_the_expected_warning_message_when_disabled()
    {
        var sut = CreateSut(disableExceptionSanitizing: true);
        var context = new StartupVerificationContext();

        await sut.VerifyAsync(context, EmptyProvider, TestContext.Current.CancellationToken);

        context.Warnings.Should().ContainSingle()
            .Which.MessageTemplate.Should().Be(ExceptionSanitizingDisabledWarningService.WarningMessage);
    }

}
