using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using ZeeKayDa.Auth.Logging;

namespace ZeeKayDa.Auth.AspNetCore.Tests;

/// <summary>
/// Tests for <see cref="AbsoluteFamilyLifetimeUnboundedWarningService"/> (ADR 0014 §5): the
/// startup-time warning emitted when <c>TokenEndpoint.AbsoluteFamilyLifetime</c> is left at the
/// <see cref="TimeSpan.MaxValue"/> unbounded escape-hatch sentinel.
/// </summary>
public sealed class AbsoluteFamilyLifetimeUnboundedWarningServiceTests
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

    private static AbsoluteFamilyLifetimeUnboundedWarningService BuildSut(
        TimeSpan absoluteFamilyLifetime,
        CapturingLogger<AbsoluteFamilyLifetimeUnboundedWarningService>? logger = null)
    {
        var options = new AuthorizationServerOptions
        {
            TokenEndpoint = { AbsoluteFamilyLifetime = absoluteFamilyLifetime },
        };

        return new AbsoluteFamilyLifetimeUnboundedWarningService(
            new OptionsWrapper<AuthorizationServerOptions>(options),
            logger ?? new CapturingLogger<AbsoluteFamilyLifetimeUnboundedWarningService>());
    }

    // ── Constructor: argument validation ─────────────────────────────────────────────────────────

    [Fact]
    public void Constructor_throws_ArgumentNullException_when_options_is_null()
    {
        var act = () => new AbsoluteFamilyLifetimeUnboundedWarningService(
            null!,
            NullSanitizingLogger<AbsoluteFamilyLifetimeUnboundedWarningService>.Instance);

        act.Should().Throw<ArgumentNullException>().WithParameterName("options");
    }

    [Fact]
    public void Constructor_throws_ArgumentNullException_when_logger_is_null()
    {
        var act = () => new AbsoluteFamilyLifetimeUnboundedWarningService(
            new OptionsWrapper<AuthorizationServerOptions>(new AuthorizationServerOptions()),
            null!);

        act.Should().Throw<ArgumentNullException>().WithParameterName("logger");
    }

    // ── StartAsync: unbounded sentinel — warns ────────────────────────────────────────────────────

    [Fact]
    public async Task StartAsync_logs_a_Warning_when_AbsoluteFamilyLifetime_is_TimeSpanMaxValue()
    {
        var logger = new CapturingLogger<AbsoluteFamilyLifetimeUnboundedWarningService>();
        var sut = BuildSut(TimeSpan.MaxValue, logger);

        await sut.StartAsync(CancellationToken.None);

        logger.Entries.Should().ContainSingle()
            .Which.Level.Should().Be(LogLevel.Warning);
    }

    [Fact]
    public async Task StartAsync_logs_exactly_once_when_AbsoluteFamilyLifetime_is_TimeSpanMaxValue()
    {
        var logger = new CapturingLogger<AbsoluteFamilyLifetimeUnboundedWarningService>();
        var sut = BuildSut(TimeSpan.MaxValue, logger);

        await sut.StartAsync(CancellationToken.None);

        logger.Entries.Should().HaveCount(1);
    }

    [Fact]
    public async Task StartAsync_warning_message_mentions_AbsoluteFamilyLifetime_when_unbounded()
    {
        var logger = new CapturingLogger<AbsoluteFamilyLifetimeUnboundedWarningService>();
        var sut = BuildSut(TimeSpan.MaxValue, logger);

        await sut.StartAsync(CancellationToken.None);

        logger.Entries.Should().ContainSingle()
            .Which.Message.Should().Contain("AbsoluteFamilyLifetime");
    }

    [Fact]
    public async Task StartAsync_does_not_throw_when_AbsoluteFamilyLifetime_is_TimeSpanMaxValue()
    {
        var sut = BuildSut(TimeSpan.MaxValue);

        await sut.Awaiting(s => s.StartAsync(CancellationToken.None)).Should().NotThrowAsync();
    }

    // ── StartAsync: finite lifetime — no-op ───────────────────────────────────────────────────────

    [Theory]
    [InlineData(90)]
    [InlineData(1)]
    [InlineData(3650)]
    public async Task StartAsync_does_not_log_when_AbsoluteFamilyLifetime_is_finite(int days)
    {
        var logger = new CapturingLogger<AbsoluteFamilyLifetimeUnboundedWarningService>();
        var sut = BuildSut(TimeSpan.FromDays(days), logger);

        await sut.StartAsync(CancellationToken.None);

        logger.Entries.Should().BeEmpty();
    }

    [Fact]
    public async Task StartAsync_does_not_throw_when_AbsoluteFamilyLifetime_is_finite()
    {
        var sut = BuildSut(TimeSpan.FromDays(90));

        await sut.Awaiting(s => s.StartAsync(CancellationToken.None)).Should().NotThrowAsync();
    }

    // ── StopAsync: no side effects ────────────────────────────────────────────────────────────────

    [Fact]
    public async Task StopAsync_completes_without_logging()
    {
        var logger = new CapturingLogger<AbsoluteFamilyLifetimeUnboundedWarningService>();
        var sut = BuildSut(TimeSpan.MaxValue, logger);

        await sut.StopAsync(CancellationToken.None);

        logger.Entries.Should().BeEmpty("StopAsync must not emit any log entries");
    }

    [Fact]
    public async Task StopAsync_does_not_throw()
    {
        var sut = BuildSut(TimeSpan.MaxValue);

        await sut.Awaiting(s => s.StopAsync(CancellationToken.None)).Should().NotThrowAsync();
    }
}
