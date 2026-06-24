using Microsoft.Extensions.FileProviders;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using ZeeKayDa.Auth;
using ZeeKayDa.Auth.AspNetCore;
using ZeeKayDa.Auth.Logging;
using ZeeKayDa.Auth.Tokens;

namespace ZeeKayDa.Auth.AspNetCore.Tests;

public sealed class DevelopmentSigningKeyWarningServiceTests
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
            => Entries.Add((logLevel, formatter(state, exception)));
    }

    private sealed class FakeHostEnvironment(string environmentName) : IHostEnvironment
    {
        public string EnvironmentName { get; set; } = environmentName;
        public string ApplicationName { get; set; } = "TestApp";
        public string ContentRootPath { get; set; } = "/";
        public IFileProvider ContentRootFileProvider { get; set; } = new NullFileProvider();
    }

    private sealed class FakeSigningService : IJwtSigningService
    {
        public int GetSigningKeysCallCount { get; private set; }

        public ValueTask<IReadOnlyList<SigningKeyDescriptor>> GetSigningKeysAsync(
            CancellationToken cancellationToken = default)
        {
            GetSigningKeysCallCount++;
            return ValueTask.FromResult<IReadOnlyList<SigningKeyDescriptor>>([]);
        }

        public ValueTask<SigningResult> SignAsync(
            ReadOnlyMemory<byte> payloadSegment,
            CancellationToken cancellationToken = default)
            => throw new NotImplementedException();
    }

    private static DevelopmentSigningKeyWarningService BuildSut(
        string environmentName,
        bool allowOutsideDevelopment = false,
        CapturingLogger<DevelopmentSigningKeyWarningService>? logger = null,
        FakeSigningService? signingService = null)
    {
        return new DevelopmentSigningKeyWarningService(
            new FakeHostEnvironment(environmentName),
            Options.Create(new AuthorizationServerOptions
            {
                AllowDevelopmentJwtSigningKeysOutsideDevelopment = allowOutsideDevelopment,
            }),
            signingService ?? new FakeSigningService(),
            logger ?? new CapturingLogger<DevelopmentSigningKeyWarningService>());
    }

    // ── Constructor: argument validation ─────────────────────────────────────────────────────────

    [Fact]
    public void Constructor_throws_ArgumentNullException_when_environment_is_null()
    {
        var act = () => new DevelopmentSigningKeyWarningService(
            null!,
            Options.Create(new AuthorizationServerOptions()),
            new FakeSigningService(),
            NullSanitizingLogger<DevelopmentSigningKeyWarningService>.Instance);

        act.Should().Throw<ArgumentNullException>().WithParameterName("environment");
    }

    [Fact]
    public void Constructor_throws_ArgumentNullException_when_options_is_null()
    {
        var act = () => new DevelopmentSigningKeyWarningService(
            new FakeHostEnvironment(Environments.Development),
            null!,
            new FakeSigningService(),
            NullSanitizingLogger<DevelopmentSigningKeyWarningService>.Instance);

        act.Should().Throw<ArgumentNullException>().WithParameterName("serverOptions");
    }

    [Fact]
    public void Constructor_throws_ArgumentNullException_when_signingService_is_null()
    {
        var act = () => new DevelopmentSigningKeyWarningService(
            new FakeHostEnvironment(Environments.Development),
            Options.Create(new AuthorizationServerOptions()),
            null!,
            NullSanitizingLogger<DevelopmentSigningKeyWarningService>.Instance);

        act.Should().Throw<ArgumentNullException>().WithParameterName("signingService");
    }

    [Fact]
    public void Constructor_throws_ArgumentNullException_when_logger_is_null()
    {
        var act = () => new DevelopmentSigningKeyWarningService(
            new FakeHostEnvironment(Environments.Development),
            Options.Create(new AuthorizationServerOptions()),
            new FakeSigningService(),
            null!);

        act.Should().Throw<ArgumentNullException>().WithParameterName("logger");
    }

    // ── StartAsync: Development environment — warning only ───────────────────────────────────────

    [Fact]
    public async Task StartAsync_logs_Warning_in_Development_environment()
    {
        var logger = new CapturingLogger<DevelopmentSigningKeyWarningService>();
        var sut = BuildSut(Environments.Development, logger: logger);

        await sut.StartAsync(CancellationToken.None);

        logger.Entries.Should().ContainSingle()
            .Which.Level.Should().Be(LogLevel.Warning);
    }

    [Fact]
    public async Task StartAsync_logs_WarningMessage_text_in_Development_environment()
    {
        var logger = new CapturingLogger<DevelopmentSigningKeyWarningService>();
        var sut = BuildSut(Environments.Development, logger: logger);

        await sut.StartAsync(CancellationToken.None);

        logger.Entries.Should().ContainSingle()
            .Which.Message.Should().Be(DevelopmentSigningKeyWarningService.WarningMessage);
    }

    [Fact]
    public async Task StartAsync_does_not_throw_in_Development_environment()
    {
        var sut = BuildSut(Environments.Development);

        await sut.Awaiting(s => s.StartAsync(CancellationToken.None)).Should().NotThrowAsync();
    }

    // ── StartAsync: non-Development, flag false — hard failure ───────────────────────────────────

    [Theory]
    [InlineData("Production")]
    [InlineData("Staging")]
    [InlineData("Custom")]
    public async Task StartAsync_throws_ZeeKayDaConfigurationException_outside_Development_when_flag_is_false(
        string environmentName)
    {
        var sut = BuildSut(environmentName, allowOutsideDevelopment: false);

        await sut.Awaiting(s => s.StartAsync(CancellationToken.None))
            .Should().ThrowAsync<ZeeKayDaConfigurationException>();
    }

    [Fact]
    public async Task StartAsync_throws_with_code_signing_dev_keys_non_development_when_flag_is_false()
    {
        var sut = BuildSut(Environments.Production, allowOutsideDevelopment: false);

        var ex = await sut.Awaiting(s => s.StartAsync(CancellationToken.None))
            .Should().ThrowAsync<ZeeKayDaConfigurationException>();

        ex.Which.AggregatedFailures.Should().ContainSingle()
            .Which.Code.Should().Be("signing.dev_keys.non_development");
    }

    [Fact]
    public async Task StartAsync_does_not_log_before_throwing_when_flag_is_false()
    {
        var logger = new CapturingLogger<DevelopmentSigningKeyWarningService>();
        var sut = BuildSut(Environments.Production, allowOutsideDevelopment: false, logger: logger);

        await sut.Awaiting(s => s.StartAsync(CancellationToken.None))
            .Should().ThrowAsync<ZeeKayDaConfigurationException>();

        logger.Entries.Should().BeEmpty("exception is thrown before any log entry is written");
    }

    // ── StartAsync: non-Development, flag true — Critical log, no exception ──────────────────────

    [Theory]
    [InlineData("Production")]
    [InlineData("Staging")]
    [InlineData("Custom")]
    public async Task StartAsync_does_not_throw_outside_Development_when_flag_is_true(
        string environmentName)
    {
        var sut = BuildSut(environmentName, allowOutsideDevelopment: true);

        await sut.Awaiting(s => s.StartAsync(CancellationToken.None)).Should().NotThrowAsync();
    }

    [Theory]
    [InlineData("Production")]
    [InlineData("Staging")]
    public async Task StartAsync_logs_Critical_outside_Development_when_flag_is_true(
        string environmentName)
    {
        var logger = new CapturingLogger<DevelopmentSigningKeyWarningService>();
        var sut = BuildSut(environmentName, allowOutsideDevelopment: true, logger: logger);

        await sut.StartAsync(CancellationToken.None);

        logger.Entries.Should().ContainSingle()
            .Which.Level.Should().Be(LogLevel.Critical);
    }

    [Fact]
    public async Task StartAsync_logs_NonDevelopmentCriticalMessage_outside_Development_when_flag_is_true()
    {
        var logger = new CapturingLogger<DevelopmentSigningKeyWarningService>();
        var sut = BuildSut(Environments.Production, allowOutsideDevelopment: true, logger: logger);

        await sut.StartAsync(CancellationToken.None);

        logger.Entries.Should().ContainSingle()
            .Which.Message.Should().Be(DevelopmentSigningKeyWarningService.NonDevelopmentCriticalMessage);
    }

    // ── StartAsync: pre-warms the signing key cache ───────────────────────────────────────────────

    [Fact]
    public async Task StartAsync_calls_GetSigningKeysAsync_to_pre_warm_cache()
    {
        var signingService = new FakeSigningService();
        var sut = BuildSut(Environments.Development, signingService: signingService);

        await sut.StartAsync(CancellationToken.None);

        signingService.GetSigningKeysCallCount.Should().Be(1, "the cache must be pre-warmed at startup");
    }

    // ── StopAsync: no side effects ────────────────────────────────────────────────────────────────

    [Fact]
    public async Task StopAsync_does_not_throw()
    {
        var sut = BuildSut(Environments.Development);
        await sut.StartAsync(CancellationToken.None);

        await sut.Awaiting(s => s.StopAsync(CancellationToken.None)).Should().NotThrowAsync();
    }
}
