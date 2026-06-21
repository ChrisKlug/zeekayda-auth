using Microsoft.Extensions.Logging;
using ZeeKayDa.Auth.AspNetCore;
using ZeeKayDa.Auth.Logging;

namespace ZeeKayDa.Auth.AspNetCore.Tests;

public sealed class InMemoryStoreWarningServiceTests
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

    // ── Constructor: argument validation ─────────────────────────────────────────────────────────

    [Fact]
    public void Constructor_throws_ArgumentNullException_when_logger_is_null()
    {
        var act = () => new InMemoryStoreWarningService(null!);

        act.Should().Throw<ArgumentNullException>().WithParameterName("logger");
    }

    // ── StartAsync: always logs ───────────────────────────────────────────────────────────────────

    [Fact]
    public async Task StartAsync_always_logs_at_Warning_level()
    {
        var logger = new CapturingLogger<InMemoryStoreWarningService>();
        var sut = new InMemoryStoreWarningService(logger);

        await sut.StartAsync(CancellationToken.None);

        logger.Entries.Should().ContainSingle()
            .Which.Level.Should().Be(LogLevel.Warning);
    }

    [Fact]
    public async Task StartAsync_logs_exactly_once()
    {
        var logger = new CapturingLogger<InMemoryStoreWarningService>();
        var sut = new InMemoryStoreWarningService(logger);

        await sut.StartAsync(CancellationToken.None);

        logger.Entries.Should().HaveCount(1);
    }

    [Fact]
    public async Task StartAsync_logs_the_exact_WarningMessage_text()
    {
        var logger = new CapturingLogger<InMemoryStoreWarningService>();
        var sut = new InMemoryStoreWarningService(logger);

        await sut.StartAsync(CancellationToken.None);

        logger.Entries.Should().ContainSingle()
            .Which.Message.Should().Be(InMemoryStoreWarningService.WarningMessage);
    }

    // ── StopAsync: no side effects ────────────────────────────────────────────────────────────────

    [Fact]
    public async Task StopAsync_completes_without_logging()
    {
        var logger = new CapturingLogger<InMemoryStoreWarningService>();
        var sut = new InMemoryStoreWarningService(logger);

        await sut.StopAsync(CancellationToken.None);

        logger.Entries.Should().BeEmpty("StopAsync must not emit any log entries");
    }

    [Fact]
    public async Task StopAsync_does_not_throw()
    {
        var sut = new InMemoryStoreWarningService(
            NullSanitizingLogger<InMemoryStoreWarningService>.Instance);

        await sut.Awaiting(s => s.StopAsync(CancellationToken.None)).Should().NotThrowAsync();
    }
}
