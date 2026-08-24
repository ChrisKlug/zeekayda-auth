using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.FileProviders;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using ZeeKayDa.Auth;
using ZeeKayDa.Auth.AspNetCore;
using ZeeKayDa.Auth.Tokens;

namespace ZeeKayDa.Auth.AspNetCore.Tests;

public sealed class DevelopmentSigningKeyWarningServiceTests
{
    // ── Fake infrastructure ───────────────────────────────────────────────────────────────────────

    private sealed class FakeHostEnvironment(string environmentName) : IHostEnvironment
    {
        public string EnvironmentName { get; set; } = environmentName;
        public string ApplicationName { get; set; } = "TestApp";
        public string ContentRootPath { get; set; } = "/";
        public IFileProvider ContentRootFileProvider { get; set; } = new NullFileProvider();
    }

    private static readonly IServiceProvider EmptyProvider = new ServiceCollection().BuildServiceProvider();

    private static DevelopmentSigningKeyWarningService BuildSut(
        string environmentName,
        IReadOnlyList<string>? allowedEnvironments = null)
    {
        var devOptions = new DevelopmentSigningKeyOptions();
        if (allowedEnvironments is not null)
            devOptions.AllowedDevelopmentJwtSigningKeysEnvironments = allowedEnvironments;

        return new DevelopmentSigningKeyWarningService(
            new FakeHostEnvironment(environmentName),
            Options.Create(devOptions));
    }

    // ── Constructor: argument validation ─────────────────────────────────────────────────────────

    [Fact]
    public void Constructor_throws_ArgumentNullException_when_environment_is_null()
    {
        var act = () => new DevelopmentSigningKeyWarningService(
            null!,
            Options.Create(new DevelopmentSigningKeyOptions()));

        act.Should().Throw<ArgumentNullException>().WithParameterName("environment");
    }

    [Fact]
    public void Constructor_throws_ArgumentNullException_when_options_is_null()
    {
        var act = () => new DevelopmentSigningKeyWarningService(
            new FakeHostEnvironment(Environments.Development),
            null!);

        act.Should().Throw<ArgumentNullException>().WithParameterName("devOptions");
    }

    // ── VerifyAsync: Development environment — warning only ──────────────────────────────────────

    [Fact]
    public async Task VerifyAsync_adds_a_Warning_in_Development_environment()
    {
        var sut = BuildSut(Environments.Development);
        var context = new StartupVerificationContext();

        await sut.VerifyAsync(context, EmptyProvider, TestContext.Current.CancellationToken);

        context.Warnings.Should().ContainSingle()
            .Which.Level.Should().Be(LogLevel.Warning);
    }

    [Fact]
    public async Task VerifyAsync_adds_the_WarningMessage_template_in_Development_environment()
    {
        var sut = BuildSut(Environments.Development);
        var context = new StartupVerificationContext();

        await sut.VerifyAsync(context, EmptyProvider, TestContext.Current.CancellationToken);

        context.Warnings.Should().ContainSingle()
            .Which.MessageTemplate.Should().Be(DevelopmentSigningKeyWarningService.WarningMessage);
    }

    [Fact]
    public async Task VerifyAsync_does_not_throw_in_Development_environment()
    {
        var sut = BuildSut(Environments.Development);
        var context = new StartupVerificationContext();

        await sut.Awaiting(s => s.VerifyAsync(context, EmptyProvider, TestContext.Current.CancellationToken).AsTask())
            .Should().NotThrowAsync();
    }

    // ── VerifyAsync: Production environment — always a hard failure ─────────────────────────────

    [Fact]
    public async Task VerifyAsync_throws_ZeeKayDaConfigurationException_in_Production_environment()
    {
        // Production is always rejected, regardless of AllowedDevelopmentJwtSigningKeysEnvironments.
        var sut = BuildSut(Environments.Production);
        var context = new StartupVerificationContext();

        await sut.Awaiting(s => s.VerifyAsync(context, EmptyProvider, TestContext.Current.CancellationToken).AsTask())
            .Should().ThrowAsync<ZeeKayDaConfigurationException>();
    }

    [Fact]
    public async Task VerifyAsync_throws_with_production_environment_code_when_environment_is_Production()
    {
        var sut = BuildSut(Environments.Production);
        var context = new StartupVerificationContext();

        var ex = await sut.Awaiting(s => s.VerifyAsync(context, EmptyProvider, TestContext.Current.CancellationToken).AsTask())
            .Should().ThrowAsync<ZeeKayDaConfigurationException>();

        ex.Which.AggregatedFailures.Should().ContainSingle()
            .Which.Code.Should().Be(DevelopmentSigningKeyGate.ProductionFailureCode);
    }

    [Fact]
    public async Task VerifyAsync_throws_in_Production_even_when_Production_is_in_allowed_list()
    {
        // The escape hatch must not apply to Production. AllowedDevelopmentJwtSigningKeysEnvironments
        // cannot override the Production guard.
        var sut = BuildSut(Environments.Production,
            allowedEnvironments: ["Development", Environments.Production]);
        var context = new StartupVerificationContext();

        await sut.Awaiting(s => s.VerifyAsync(context, EmptyProvider, TestContext.Current.CancellationToken).AsTask())
            .Should().ThrowAsync<ZeeKayDaConfigurationException>()
            .WithMessage("*production*");
    }

    [Fact]
    public async Task VerifyAsync_does_not_add_a_warning_before_throwing_in_Production_environment()
    {
        var sut = BuildSut(Environments.Production);
        var context = new StartupVerificationContext();

        await sut.Awaiting(s => s.VerifyAsync(context, EmptyProvider, TestContext.Current.CancellationToken).AsTask())
            .Should().ThrowAsync<ZeeKayDaConfigurationException>();

        context.Warnings.Should().BeEmpty("exception is thrown before any warning is recorded");
    }

    // ── VerifyAsync: non-Development, non-Production, not in allowed list — hard failure ───────

    [Theory]
    [InlineData("Staging")]
    [InlineData("Custom")]
    public async Task VerifyAsync_throws_ZeeKayDaConfigurationException_when_environment_not_in_allowed_list(
        string environmentName)
    {
        // Default list is ["Development"] — any non-Production, non-Development environment must fail.
        var sut = BuildSut(environmentName);
        var context = new StartupVerificationContext();

        await sut.Awaiting(s => s.VerifyAsync(context, EmptyProvider, TestContext.Current.CancellationToken).AsTask())
            .Should().ThrowAsync<ZeeKayDaConfigurationException>();
    }

    [Fact]
    public async Task VerifyAsync_throws_with_code_signing_dev_keys_non_development_when_staging_not_in_list()
    {
        var sut = BuildSut("Staging");
        var context = new StartupVerificationContext();

        var ex = await sut.Awaiting(s => s.VerifyAsync(context, EmptyProvider, TestContext.Current.CancellationToken).AsTask())
            .Should().ThrowAsync<ZeeKayDaConfigurationException>();

        ex.Which.AggregatedFailures.Should().ContainSingle()
            .Which.Code.Should().Be("signing.dev_keys.non_development");
    }

    [Fact]
    public async Task VerifyAsync_allows_when_environment_added_to_allowed_list()
    {
        var sut = BuildSut("IntegrationTesting",
            allowedEnvironments: ["Development", "IntegrationTesting"]);
        var context = new StartupVerificationContext();

        await sut.Awaiting(s => s.VerifyAsync(context, EmptyProvider, TestContext.Current.CancellationToken).AsTask())
            .Should().NotThrowAsync();
    }

    [Fact]
    public async Task VerifyAsync_allowed_list_comparison_is_case_insensitive()
    {
        // "development" (lowercase) should match the default allowed entry "Development".
        var sut = BuildSut("development");
        var context = new StartupVerificationContext();

        await sut.Awaiting(s => s.VerifyAsync(context, EmptyProvider, TestContext.Current.CancellationToken).AsTask())
            .Should().NotThrowAsync();
    }

    // ── VerifyAsync: non-Development, non-Production, in allowed list — Critical warning, no throw

    [Theory]
    [InlineData("Staging")]
    [InlineData("Custom")]
    public async Task VerifyAsync_does_not_throw_when_non_production_environment_added_to_allowed_list(
        string environmentName)
    {
        var sut = BuildSut(environmentName, allowedEnvironments: ["Development", environmentName]);
        var context = new StartupVerificationContext();

        await sut.Awaiting(s => s.VerifyAsync(context, EmptyProvider, TestContext.Current.CancellationToken).AsTask())
            .Should().NotThrowAsync();
    }

    [Theory]
    [InlineData("Staging")]
    [InlineData("Custom")]
    public async Task VerifyAsync_adds_a_Critical_warning_when_non_Development_non_Production_environment_is_in_allowed_list(
        string environmentName)
    {
        var sut = BuildSut(environmentName, allowedEnvironments: ["Development", environmentName]);
        var context = new StartupVerificationContext();

        await sut.VerifyAsync(context, EmptyProvider, TestContext.Current.CancellationToken);

        context.Warnings.Should().ContainSingle()
            .Which.Level.Should().Be(LogLevel.Critical);
    }

    [Fact]
    public async Task VerifyAsync_adds_the_NonDevelopmentCriticalMessage_template_when_Staging_is_in_allowed_list()
    {
        var sut = BuildSut("Staging", allowedEnvironments: ["Development", "Staging"]);
        var context = new StartupVerificationContext();

        await sut.VerifyAsync(context, EmptyProvider, TestContext.Current.CancellationToken);

        context.Warnings.Should().ContainSingle()
            .Which.MessageTemplate.Should().Be(DevelopmentSigningKeyWarningService.NonDevelopmentCriticalMessage);
    }

    [Fact]
    public void Name_is_DevelopmentSigningKey()
    {
        var sut = BuildSut(Environments.Development);

        sut.Name.Should().Be("DevelopmentSigningKey");
    }
}
