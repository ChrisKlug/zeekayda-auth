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
        IReadOnlyList<string>? allowedEnvironments = null,
        CapturingLogger<DevelopmentSigningKeyWarningService>? logger = null,
        FakeSigningService? signingService = null)
    {
        var options = new AuthorizationServerOptions();
        if (allowedEnvironments is not null)
            options.AllowedDevelopmentJwtSigningKeysEnvironments = allowedEnvironments;

        return new DevelopmentSigningKeyWarningService(
            new FakeHostEnvironment(environmentName),
            Options.Create(options),
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

    // ── StartAsync: non-Development, not in allowed list — hard failure ─────────────────────────

    [Theory]
    [InlineData("Production")]
    [InlineData("Staging")]
    [InlineData("Custom")]
    public async Task StartAsync_throws_ZeeKayDaConfigurationException_when_environment_not_in_allowed_list(
        string environmentName)
    {
        // Default list is ["Development"] — any other environment must fail.
        var sut = BuildSut(environmentName);

        await sut.Awaiting(s => s.StartAsync(CancellationToken.None))
            .Should().ThrowAsync<ZeeKayDaConfigurationException>();
    }

    [Fact]
    public async Task StartAsync_throws_with_code_signing_dev_keys_non_development_when_environment_not_in_list()
    {
        var sut = BuildSut(Environments.Production);

        var ex = await sut.Awaiting(s => s.StartAsync(CancellationToken.None))
            .Should().ThrowAsync<ZeeKayDaConfigurationException>();

        ex.Which.AggregatedFailures.Should().ContainSingle()
            .Which.Code.Should().Be("signing.dev_keys.non_development");
    }

    [Fact]
    public async Task StartAsync_does_not_log_before_throwing_when_environment_not_in_allowed_list()
    {
        var logger = new CapturingLogger<DevelopmentSigningKeyWarningService>();
        var sut = BuildSut(Environments.Production, logger: logger);

        await sut.Awaiting(s => s.StartAsync(CancellationToken.None))
            .Should().ThrowAsync<ZeeKayDaConfigurationException>();

        logger.Entries.Should().BeEmpty("exception is thrown before any log entry is written");
    }

    [Fact]
    public async Task StartAsync_allows_when_environment_added_to_allowed_list()
    {
        var sut = BuildSut("IntegrationTesting",
            allowedEnvironments: ["Development", "IntegrationTesting"]);

        await sut.Awaiting(s => s.StartAsync(CancellationToken.None)).Should().NotThrowAsync();
    }

    [Fact]
    public async Task StartAsync_allowed_list_comparison_is_case_insensitive()
    {
        // "development" (lowercase) should match the default allowed entry "Development".
        var sut = BuildSut("development");

        await sut.Awaiting(s => s.StartAsync(CancellationToken.None)).Should().NotThrowAsync();
    }

    // ── StartAsync: non-Development, in allowed list — Critical log, no exception ──────────────

    [Theory]
    [InlineData("Production")]
    [InlineData("Staging")]
    [InlineData("Custom")]
    public async Task StartAsync_does_not_throw_when_environment_explicitly_added_to_allowed_list(
        string environmentName)
    {
        var sut = BuildSut(environmentName, allowedEnvironments: ["Development", environmentName]);

        await sut.Awaiting(s => s.StartAsync(CancellationToken.None)).Should().NotThrowAsync();
    }

    [Theory]
    [InlineData("Production")]
    [InlineData("Staging")]
    public async Task StartAsync_logs_Critical_when_non_Development_environment_is_in_allowed_list(
        string environmentName)
    {
        var logger = new CapturingLogger<DevelopmentSigningKeyWarningService>();
        var sut = BuildSut(environmentName,
            allowedEnvironments: ["Development", environmentName],
            logger: logger);

        await sut.StartAsync(CancellationToken.None);

        logger.Entries.Should().ContainSingle()
            .Which.Level.Should().Be(LogLevel.Critical);
    }

    [Fact]
    public async Task StartAsync_logs_NonDevelopmentCriticalMessage_when_non_Development_environment_is_in_allowed_list()
    {
        var logger = new CapturingLogger<DevelopmentSigningKeyWarningService>();
        var sut = BuildSut(Environments.Production,
            allowedEnvironments: ["Development", Environments.Production],
            logger: logger);

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
