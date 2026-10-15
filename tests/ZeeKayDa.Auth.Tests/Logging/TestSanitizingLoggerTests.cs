using Microsoft.Extensions.Logging;
using ZeeKayDa.Auth.Logging;
using ZeeKayDa.Auth.TestKit.Logging;

namespace ZeeKayDa.Auth.Tests.Logging;

public sealed class TestSanitizingLoggerTests
{
    [Fact]
    public void Create_redacts_a_sensitive_value_before_it_reaches_the_inner_logger()
    {
        var inner = new CapturingLogger<object>();

        TestSanitizingLogger.Create(inner).LogInformation("Auth {client_secret} received", "s3cr3t");

        inner.Entries.Should().ContainSingle().Which.Message.Should().NotContain("s3cr3t");
    }

    [Fact]
    public void Create_sanitizes_exceptions_as_production_does()
    {
        var inner = new CapturingLogger<object>();

        TestSanitizingLogger.Create(inner).LogInformation(new InvalidOperationException("secret"), "failed");

        inner.Entries.Should().ContainSingle().Which.Exception.Should().BeOfType<RedactedExceptionWrapper>();
    }

    [Fact]
    public void Create_refuses_a_null_inner_logger()
    {
        var act = () => TestSanitizingLogger.Create<object>(null!);

        act.Should().Throw<ArgumentNullException>();
    }

    private sealed class CapturingLogger<T> : ILogger<T>
    {
        public List<(string Message, Exception? Exception)> Entries { get; } = [];

        public IDisposable? BeginScope<TState>(TState state) where TState : notnull => null;
        public bool IsEnabled(LogLevel logLevel) => true;
        public void Log<TState>(LogLevel logLevel, EventId eventId, TState state,
            Exception? exception, Func<TState, Exception?, string> formatter)
            => Entries.Add((formatter(state, exception), exception));
    }
}
