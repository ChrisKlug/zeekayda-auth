using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using ZeeKayDa.Auth.Logging;
using ZeeKayDa.Auth.Tokens;

namespace ZeeKayDa.Auth.Tests.Tokens;

/// <summary>
/// Exercises <see cref="SigningStartupSelfTestHostedService"/> in isolation: delegation to a
/// registered <see cref="ISigningStartupSelfTest"/>, the silent no-op when nothing is registered at
/// all, and the <see cref="LogLevel.Warning"/>-logging no-op when something is registered that does
/// not implement the self-test interface — none of which are allowed to silently disable the ADR
/// 0015 self-test without a trace (issue #437 security review, finding F2).
/// </summary>
public sealed class SigningStartupSelfTestHostedServiceTests
{
    /// <summary>Captures every log call so tests can assert on the missing-interface warning.</summary>
    private sealed class CapturingLogger<T> : ISanitizingLogger<T>
    {
        public List<(LogLevel Level, string Message)> Entries { get; } = [];

        public IDisposable? BeginScope<TState>(TState state) where TState : notnull => null;

        public bool IsEnabled(LogLevel logLevel) => true;

        public void Log<TState>(
            LogLevel logLevel, EventId eventId, TState state, Exception? exception, Func<TState, Exception?, string> formatter)
            => Entries.Add((logLevel, formatter(state, exception)));
    }

    private sealed class FakeSelfTestSigningService : IJwtSigningService, ISigningStartupSelfTest
    {
        public int VerifyActiveSignerAsyncCallCount { get; private set; }

        public Exception? ThrowOnVerify { get; set; }

        public ValueTask VerifyActiveSignerAsync(CancellationToken cancellationToken = default)
        {
            VerifyActiveSignerAsyncCallCount++;
            if (ThrowOnVerify is not null)
                throw ThrowOnVerify;

            return ValueTask.CompletedTask;
        }

        public ValueTask<IReadOnlyList<SigningKeyDescriptor>> GetSigningKeysAsync(CancellationToken cancellationToken = default)
            => throw new NotImplementedException();

        public ValueTask<SigningResult> SignAsync(ReadOnlyMemory<byte> payloadSegment, CancellationToken cancellationToken = default)
            => throw new NotImplementedException();
    }

    /// <summary>
    /// Models an external, out-of-tree <see cref="IJwtSigningService"/> implementation written
    /// before <see cref="ISigningStartupSelfTest"/> existed — it implements only the required
    /// interface, never the optional self-test one.
    /// </summary>
    private sealed class PlainSigningService : IJwtSigningService
    {
        public ValueTask<IReadOnlyList<SigningKeyDescriptor>> GetSigningKeysAsync(CancellationToken cancellationToken = default)
            => throw new NotImplementedException();

        public ValueTask<SigningResult> SignAsync(ReadOnlyMemory<byte> payloadSegment, CancellationToken cancellationToken = default)
            => throw new NotImplementedException();
    }

    private static ServiceProvider BuildProvider(IJwtSigningService? signingService)
    {
        var services = new ServiceCollection();
        if (signingService is not null)
            services.AddSingleton(signingService);

        return services.BuildServiceProvider();
    }

    [Fact]
    public void Constructor_throws_ArgumentNullException_when_serviceProvider_is_null()
    {
        var act = () => new SigningStartupSelfTestHostedService(null!, new CapturingLogger<SigningStartupSelfTestHostedService>());

        act.Should().Throw<ArgumentNullException>().WithParameterName("serviceProvider");
    }

    [Fact]
    public void Constructor_throws_ArgumentNullException_when_logger_is_null()
    {
        using var provider = BuildProvider(signingService: null);

        var act = () => new SigningStartupSelfTestHostedService(provider, null!);

        act.Should().Throw<ArgumentNullException>().WithParameterName("logger");
    }

    [Fact]
    public async Task StartAsync_delegates_to_the_registered_ISigningStartupSelfTest()
    {
        var signingService = new FakeSelfTestSigningService();
        using var provider = BuildProvider(signingService);
        var sut = new SigningStartupSelfTestHostedService(provider, new CapturingLogger<SigningStartupSelfTestHostedService>());

        await sut.StartAsync(TestContext.Current.CancellationToken);

        signingService.VerifyActiveSignerAsyncCallCount.Should().Be(1);
    }

    [Fact]
    public async Task StartAsync_propagates_a_failure_from_the_self_test_unmodified()
    {
        var signingService = new FakeSelfTestSigningService
        {
            ThrowOnVerify = new ZeeKayDaConfigurationException(
                new ZeeKayDaConfigurationFailure("signing.self_test_failed", "Simulated failure.")),
        };
        using var provider = BuildProvider(signingService);
        var sut = new SigningStartupSelfTestHostedService(provider, new CapturingLogger<SigningStartupSelfTestHostedService>());

        var act = async () => await sut.StartAsync(TestContext.Current.CancellationToken);

        (await act.Should().ThrowAsync<ZeeKayDaConfigurationException>())
            .WithMessage("*self_test_failed*");
    }

    [Fact]
    public async Task StartAsync_is_a_no_op_when_no_IJwtSigningService_is_registered()
    {
        using var provider = BuildProvider(signingService: null);
        var logger = new CapturingLogger<SigningStartupSelfTestHostedService>();
        var sut = new SigningStartupSelfTestHostedService(provider, logger);

        var act = async () => await sut.StartAsync(TestContext.Current.CancellationToken);

        await act.Should().NotThrowAsync();
        logger.Entries.Should().BeEmpty(
            "a host that has not configured any signing provider at all is the expected shape, not a control gap worth warning about");
    }

    [Fact]
    public async Task StartAsync_logs_a_warning_naming_the_resolved_type_when_the_registered_IJwtSigningService_does_not_implement_the_self_test_interface()
    {
        using var provider = BuildProvider(new PlainSigningService());
        var logger = new CapturingLogger<SigningStartupSelfTestHostedService>();
        var sut = new SigningStartupSelfTestHostedService(provider, logger);

        var act = async () => await sut.StartAsync(TestContext.Current.CancellationToken);

        await act.Should().NotThrowAsync(
            "an external IJwtSigningService written before ISigningStartupSelfTest existed must not be forced to implement it");
        logger.Entries.Should().ContainSingle(e =>
            e.Level == LogLevel.Warning &&
            e.Message.Contains(nameof(PlainSigningService)) &&
            e.Message.Contains("ISigningStartupSelfTest"),
            "a registered IJwtSigningService that silently drops ISigningStartupSelfTest (e.g. a decorator " +
            "registered over a real provider) must never disable the ADR 0015 self-test without a trace " +
            "naming the concrete type that was resolved");
    }

    [Fact]
    public async Task StopAsync_does_not_throw()
    {
        using var provider = BuildProvider(signingService: null);
        var sut = new SigningStartupSelfTestHostedService(provider, new CapturingLogger<SigningStartupSelfTestHostedService>());

        await sut.Awaiting(s => s.StopAsync(TestContext.Current.CancellationToken)).Should().NotThrowAsync();
    }
}
