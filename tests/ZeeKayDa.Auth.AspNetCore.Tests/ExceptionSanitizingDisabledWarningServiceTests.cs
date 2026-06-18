using Microsoft.Extensions.FileProviders;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using ZeeKayDa.Auth.AspNetCore;
using ZeeKayDa.Auth.Logging;

namespace ZeeKayDa.Auth.AspNetCore.Tests;

public sealed class ExceptionSanitizingDisabledWarningServiceTests
{
    // ── Fake infrastructure ───────────────────────────────────────────────────────────────────────

    private sealed class FakeHostEnvironment : IHostEnvironment
    {
        public string ApplicationName { get; set; } = "TestApp";
        public IFileProvider ContentRootFileProvider { get; set; } = new NullFileProvider();
        public string ContentRootPath { get; set; } = AppContext.BaseDirectory;
        public string EnvironmentName { get; set; } = Environments.Development;
    }

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
        string environmentName,
        CapturingLogger<ExceptionSanitizingDisabledWarningService> logger)
        => new(new FakeHostEnvironment { EnvironmentName = environmentName }, logger);

    // ── Tests ────────────────────────────────────────────────────────────────────────────────────

    [Fact]
    public async Task StartAsync_logs_Warning_in_development_environment()
    {
        var logger = new CapturingLogger<ExceptionSanitizingDisabledWarningService>();
        var sut = CreateSut(Environments.Development, logger);

        await sut.StartAsync(CancellationToken.None);

        logger.Entries.Should().ContainSingle()
            .Which.Level.Should().Be(LogLevel.Warning);
    }

    [Fact]
    public async Task StartAsync_logs_Error_in_production_environment()
    {
        var logger = new CapturingLogger<ExceptionSanitizingDisabledWarningService>();
        var sut = CreateSut(Environments.Production, logger);

        await sut.StartAsync(CancellationToken.None);

        logger.Entries.Should().ContainSingle()
            .Which.Level.Should().Be(LogLevel.Error);
    }

    [Fact]
    public async Task StartAsync_logs_exactly_once_in_development()
    {
        var logger = new CapturingLogger<ExceptionSanitizingDisabledWarningService>();
        var sut = CreateSut(Environments.Development, logger);

        await sut.StartAsync(CancellationToken.None);

        logger.Entries.Should().HaveCount(1);
    }

    [Fact]
    public async Task StartAsync_logs_exactly_once_in_production()
    {
        var logger = new CapturingLogger<ExceptionSanitizingDisabledWarningService>();
        var sut = CreateSut(Environments.Production, logger);

        await sut.StartAsync(CancellationToken.None);

        logger.Entries.Should().HaveCount(1);
    }

    [Fact]
    public async Task StartAsync_logs_the_expected_warning_message()
    {
        var logger = new CapturingLogger<ExceptionSanitizingDisabledWarningService>();
        var sut = CreateSut(Environments.Development, logger);

        await sut.StartAsync(CancellationToken.None);

        logger.Entries.Should().ContainSingle()
            .Which.Message.Should().Be(ExceptionSanitizingDisabledWarningService.WarningMessage);
    }

    [Fact]
    public async Task StopAsync_does_not_throw()
    {
        var sut = CreateSut(
            Environments.Development,
            new CapturingLogger<ExceptionSanitizingDisabledWarningService>());

        await sut.Awaiting(s => s.StopAsync(CancellationToken.None)).Should().NotThrowAsync();
    }
}
