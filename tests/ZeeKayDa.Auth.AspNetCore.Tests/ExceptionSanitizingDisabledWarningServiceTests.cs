using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using ZeeKayDa.Auth;
using ZeeKayDa.Auth.AspNetCore;
using ZeeKayDa.Auth.Logging;

namespace ZeeKayDa.Auth.AspNetCore.Tests;

public sealed class ExceptionSanitizingDisabledWarningServiceTests
{
    // ── Fake infrastructure ───────────────────────────────────────────────────────────────────────

    private sealed class CapturingLogger<T> : ISanitizingLogger<T>
    {
        public List<(LogLevel Level, string Message)> Entries { get; } = [];

        public IDisposable? BeginScope<TState>(TState state) where TState : notnull => null;

        public bool IsEnabled(LogLevel logLevel) => true;

        public void Log<TState>(
            LogLevel logLevel,
            EventId eventId,
            TState state,
            Exception? exception,
            Func<TState, Exception?, string> formatter)
        {
            Entries.Add((logLevel, formatter(state, exception)));
        }
    }

    private static ExceptionSanitizingDisabledWarningService CreateSut(
        bool disableExceptionSanitizing,
        CapturingLogger<ExceptionSanitizingDisabledWarningService> logger)
    {
        var opts = new AuthorizationServerOptions();
        opts.Logging.DisableExceptionSanitizing = disableExceptionSanitizing;
        return new(Options.Create(opts), logger);
    }

    // ── Tests ────────────────────────────────────────────────────────────────────────────────────

    [Fact]
    public async Task StartAsync_logs_Warning_when_exception_sanitizing_is_disabled()
    {
        var logger = new CapturingLogger<ExceptionSanitizingDisabledWarningService>();
        var sut = CreateSut(disableExceptionSanitizing: true, logger);

        await sut.StartAsync(CancellationToken.None);

        logger.Entries.Should().ContainSingle()
            .Which.Level.Should().Be(LogLevel.Warning);
    }

    [Fact]
    public async Task StartAsync_does_not_log_when_exception_sanitizing_is_enabled()
    {
        var logger = new CapturingLogger<ExceptionSanitizingDisabledWarningService>();
        var sut = CreateSut(disableExceptionSanitizing: false, logger);

        await sut.StartAsync(CancellationToken.None);

        logger.Entries.Should().BeEmpty();
    }

    [Fact]
    public async Task StartAsync_logs_exactly_once_when_disabled()
    {
        var logger = new CapturingLogger<ExceptionSanitizingDisabledWarningService>();
        var sut = CreateSut(disableExceptionSanitizing: true, logger);

        await sut.StartAsync(CancellationToken.None);

        logger.Entries.Should().HaveCount(1);
    }

    [Fact]
    public async Task StartAsync_logs_the_expected_warning_message()
    {
        var logger = new CapturingLogger<ExceptionSanitizingDisabledWarningService>();
        var sut = CreateSut(disableExceptionSanitizing: true, logger);

        await sut.StartAsync(CancellationToken.None);

        logger.Entries.Should().ContainSingle()
            .Which.Message.Should().Be(ExceptionSanitizingDisabledWarningService.WarningMessage);
    }

    [Fact]
    public async Task StopAsync_does_not_throw()
    {
        var sut = CreateSut(
            disableExceptionSanitizing: false,
            new CapturingLogger<ExceptionSanitizingDisabledWarningService>());

        await sut.Awaiting(s => s.StopAsync(CancellationToken.None)).Should().NotThrowAsync();
    }

    [Fact]
    public void Constructor_throws_ArgumentNullException_when_options_is_null()
    {
        var act = () => new ExceptionSanitizingDisabledWarningService(
            null!,
            new CapturingLogger<ExceptionSanitizingDisabledWarningService>());

        act.Should().Throw<ArgumentNullException>().WithParameterName("options");
    }

    [Fact]
    public void Constructor_throws_ArgumentNullException_when_logger_is_null()
    {
        var act = () => new ExceptionSanitizingDisabledWarningService(
            Options.Create(new AuthorizationServerOptions()),
            null!);

        act.Should().Throw<ArgumentNullException>().WithParameterName("logger");
    }
}
