using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using ZeeKayDa.Auth;
using ZeeKayDa.Auth.AspNetCore;
using ZeeKayDa.Auth.Logging;

namespace ZeeKayDa.Auth.AspNetCore.Tests;

public sealed class InsecureIssuerWarningServiceTests
{
    [Fact]
    public async Task StartAsync_logs_warning_when_AllowInsecureIssuer_is_true()
    {
        var logger = new CapturingLogger<InsecureIssuerWarningService>();
        var sut = new InsecureIssuerWarningService(
            Options.Create(new AuthorizationServerOptions
            {
                Issuer = "http://localhost:5000",
                AllowInsecureIssuer = true,
            }),
            logger);

        await sut.StartAsync(CancellationToken.None);

        logger.Entries.Should().ContainSingle()
            .Which.Level.Should().Be(LogLevel.Warning);
    }

    [Fact]
    public async Task StartAsync_does_not_log_warning_when_AllowInsecureIssuer_is_false()
    {
        var sut = new InsecureIssuerWarningService(
            Options.Create(new AuthorizationServerOptions { Issuer = "https://auth.example.com" }),
            NullSanitizingLogger<InsecureIssuerWarningService>.Instance);

        // Should complete without any exception; nothing to assert on the null logger.
        await sut.Awaiting(s => s.StartAsync(CancellationToken.None)).Should().NotThrowAsync();
    }

    [Fact]
    public async Task StopAsync_does_not_throw()
    {
        var sut = new InsecureIssuerWarningService(
            Options.Create(new AuthorizationServerOptions { Issuer = "https://auth.example.com" }),
            NullSanitizingLogger<InsecureIssuerWarningService>.Instance);

        await sut.Awaiting(s => s.StopAsync(CancellationToken.None)).Should().NotThrowAsync();
    }

    /// <summary>
    /// Minimal logger that captures log entries for assertion in tests.
    /// </summary>
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
}
