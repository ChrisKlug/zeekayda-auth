using Microsoft.Extensions.FileProviders;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
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

    private sealed class FakeHostEnvironment(string environmentName) : IHostEnvironment
    {
        public string EnvironmentName { get; set; } = environmentName;
        public string ApplicationName { get; set; } = "TestApp";
        public string ContentRootPath { get; set; } = "/";
        public IFileProvider ContentRootFileProvider { get; set; } = new NullFileProvider();
    }

    private static InMemoryStoreWarningService BuildSut(
        string environmentName,
        bool allowOutsideDevelopment = false,
        CapturingLogger<InMemoryStoreWarningService>? logger = null)
    {
        return new InMemoryStoreWarningService(
            new FakeHostEnvironment(environmentName),
            Options.Create(new AuthorizationServerOptions
            {
                AllowInMemoryStoresOutsideDevelopment = allowOutsideDevelopment,
            }),
            logger ?? new CapturingLogger<InMemoryStoreWarningService>());
    }

    // ── Constructor: argument validation ─────────────────────────────────────────────────────────

    [Fact]
    public void Constructor_throws_ArgumentNullException_when_environment_is_null()
    {
        var act = () => new InMemoryStoreWarningService(
            null!,
            Options.Create(new AuthorizationServerOptions()),
            NullSanitizingLogger<InMemoryStoreWarningService>.Instance);

        act.Should().Throw<ArgumentNullException>().WithParameterName("environment");
    }

    [Fact]
    public void Constructor_throws_ArgumentNullException_when_options_is_null()
    {
        var act = () => new InMemoryStoreWarningService(
            new FakeHostEnvironment(Environments.Development),
            null!,
            NullSanitizingLogger<InMemoryStoreWarningService>.Instance);

        act.Should().Throw<ArgumentNullException>().WithParameterName("options");
    }

    [Fact]
    public void Constructor_throws_ArgumentNullException_when_logger_is_null()
    {
        var act = () => new InMemoryStoreWarningService(
            new FakeHostEnvironment(Environments.Development),
            Options.Create(new AuthorizationServerOptions()),
            null!);

        act.Should().Throw<ArgumentNullException>().WithParameterName("logger");
    }

    // ── StartAsync: Development environment — warning only ───────────────────────────────────────

    [Fact]
    public async Task StartAsync_logs_Warning_in_Development_environment()
    {
        var logger = new CapturingLogger<InMemoryStoreWarningService>();
        var sut = BuildSut(Environments.Development, logger: logger);

        await sut.StartAsync(CancellationToken.None);

        logger.Entries.Should().ContainSingle()
            .Which.Level.Should().Be(LogLevel.Warning);
    }

    [Fact]
    public async Task StartAsync_logs_exactly_once_in_Development_environment()
    {
        var logger = new CapturingLogger<InMemoryStoreWarningService>();
        var sut = BuildSut(Environments.Development, logger: logger);

        await sut.StartAsync(CancellationToken.None);

        logger.Entries.Should().HaveCount(1);
    }

    [Fact]
    public async Task StartAsync_logs_the_exact_WarningMessage_text_in_Development_environment()
    {
        var logger = new CapturingLogger<InMemoryStoreWarningService>();
        var sut = BuildSut(Environments.Development, logger: logger);

        await sut.StartAsync(CancellationToken.None);

        logger.Entries.Should().ContainSingle()
            .Which.Message.Should().Be(InMemoryStoreWarningService.WarningMessage);
    }

    [Fact]
    public async Task StartAsync_does_not_throw_in_Development_environment_regardless_of_flag()
    {
        var sut = BuildSut(Environments.Development, allowOutsideDevelopment: false);

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

    [Theory]
    [InlineData("Production")]
    [InlineData("Staging")]
    public async Task StartAsync_throws_with_code_stores_inmemory_non_development_outside_Development_when_flag_is_false(
        string environmentName)
    {
        var sut = BuildSut(environmentName, allowOutsideDevelopment: false);

        var ex = await sut.Awaiting(s => s.StartAsync(CancellationToken.None))
            .Should().ThrowAsync<ZeeKayDaConfigurationException>();

        ex.Which.AggregatedFailures.Should().ContainSingle()
            .Which.Code.Should().Be("stores.inmemory.non_development");
    }

    [Fact]
    public async Task StartAsync_throws_with_message_mentioning_AllowInMemoryStoresOutsideDevelopment_when_flag_is_false()
    {
        var sut = BuildSut(Environments.Production, allowOutsideDevelopment: false);

        var ex = await sut.Awaiting(s => s.StartAsync(CancellationToken.None))
            .Should().ThrowAsync<ZeeKayDaConfigurationException>();

        ex.Which.Message.Should().Contain("AllowInMemoryStoresOutsideDevelopment");
    }

    [Fact]
    public async Task StartAsync_does_not_log_before_throwing_outside_Development_when_flag_is_false()
    {
        var logger = new CapturingLogger<InMemoryStoreWarningService>();
        var sut = BuildSut(Environments.Production, allowOutsideDevelopment: false, logger: logger);

        await sut.Awaiting(s => s.StartAsync(CancellationToken.None))
            .Should().ThrowAsync<ZeeKayDaConfigurationException>();

        logger.Entries.Should().BeEmpty("exception is thrown before any log entry is written");
    }

    // ── StartAsync: non-Development, flag true — warning, no exception ───────────────────────────

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
    public async Task StartAsync_logs_Warning_outside_Development_when_flag_is_true(
        string environmentName)
    {
        var logger = new CapturingLogger<InMemoryStoreWarningService>();
        var sut = BuildSut(environmentName, allowOutsideDevelopment: true, logger: logger);

        await sut.StartAsync(CancellationToken.None);

        logger.Entries.Should().ContainSingle()
            .Which.Level.Should().Be(LogLevel.Warning);
    }

    [Fact]
    public async Task StartAsync_logs_NonDevelopmentOverrideWarningMessage_outside_Development_when_flag_is_true()
    {
        var logger = new CapturingLogger<InMemoryStoreWarningService>();
        var sut = BuildSut(Environments.Production, allowOutsideDevelopment: true, logger: logger);

        await sut.StartAsync(CancellationToken.None);

        logger.Entries.Should().ContainSingle()
            .Which.Message.Should().Be(InMemoryStoreWarningService.NonDevelopmentOverrideWarningMessage);
    }

    [Fact]
    public async Task StartAsync_logs_exactly_once_outside_Development_when_flag_is_true()
    {
        var logger = new CapturingLogger<InMemoryStoreWarningService>();
        var sut = BuildSut(Environments.Production, allowOutsideDevelopment: true, logger: logger);

        await sut.StartAsync(CancellationToken.None);

        logger.Entries.Should().HaveCount(1);
    }

    // ── StopAsync: no side effects ────────────────────────────────────────────────────────────────

    [Fact]
    public async Task StopAsync_completes_without_logging()
    {
        var logger = new CapturingLogger<InMemoryStoreWarningService>();
        var sut = BuildSut(Environments.Development, logger: logger);

        await sut.StopAsync(CancellationToken.None);

        logger.Entries.Should().BeEmpty("StopAsync must not emit any log entries");
    }

    [Fact]
    public async Task StopAsync_does_not_throw()
    {
        var sut = BuildSut(Environments.Development);

        await sut.Awaiting(s => s.StopAsync(CancellationToken.None)).Should().NotThrowAsync();
    }
}
