using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.FileProviders;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

namespace ZeeKayDa.Auth.AspNetCore.Tests;

/// <summary>
/// The startup record of an insecure issuer: absent unless the host opted in, and louder outside
/// the environment where opting in is the expected thing to do.
/// </summary>
public sealed class InsecureIssuerWarningServiceTests
{
    private static readonly IServiceProvider EmptyProvider = new ServiceCollection().BuildServiceProvider();

    private sealed class FakeHostEnvironment(string environmentName) : IHostEnvironment
    {
        public string EnvironmentName { get; set; } = environmentName;
        public string ApplicationName { get; set; } = "TestApp";
        public string ContentRootPath { get; set; } = "/";
        public IFileProvider ContentRootFileProvider { get; set; } = new NullFileProvider();
    }

    private static async Task<StartupVerificationContext> VerifyAsync(string environment, bool allowInsecureIssuer)
    {
        var sut = new InsecureIssuerWarningService(
            Options.Create(new AuthorizationServerOptions
            {
                Issuer = allowInsecureIssuer ? "http://localhost:5000" : "https://auth.example.com",
                AllowInsecureIssuer = allowInsecureIssuer,
            }),
            new FakeHostEnvironment(environment));
        var context = new StartupVerificationContext();

        await sut.VerifyAsync(context, EmptyProvider, TestContext.Current.CancellationToken);

        return context;
    }

    [Fact]
    public async Task An_insecure_issuer_in_Development_logs_at_Information_on_every_start()
    {
        var context = await VerifyAsync(Environments.Development, allowInsecureIssuer: true);

        var warning = context.Warnings.Should().ContainSingle().Which;
        warning.Code.Should().Be("issuer.insecure_allowed");
        warning.Level.Should().Be(LogLevel.Information);
    }

    [Theory]
    [InlineData("Production")]
    [InlineData("Staging")]
    public async Task An_insecure_issuer_outside_Development_logs_at_Critical_on_every_start(string environment)
    {
        // The gap this issue closes: the same Warning was logged in every environment, so an
        // http issuer that reached Production said no more about itself than it did on a laptop.
        var context = await VerifyAsync(environment, allowInsecureIssuer: true);

        var warning = context.Warnings.Should().ContainSingle().Which;
        warning.Code.Should().Be("issuer.insecure_allowed_outside_development");
        warning.Level.Should().Be(LogLevel.Critical);
    }

    [Theory]
    [InlineData("Development")]
    [InlineData("Production")]
    public async Task An_insecure_issuer_outside_Development_does_not_fail_startup(string environment)
    {
        // AllowInsecureIssuer is itself the opt-out, and IssuerValidator.ValidateScheme already
        // fails startup for a non-loopback http issuer, so what remains here can only be
        // http://localhost. Failing would break an intentional non-Development test host and buy
        // no security the scheme rule has not already bought.
        var context = await VerifyAsync(environment, allowInsecureIssuer: true);

        context.Failures.Should().BeEmpty();
    }

    [Theory]
    [InlineData("Development")]
    [InlineData("Production")]
    public async Task A_secure_issuer_records_nothing(string environment)
    {
        var context = await VerifyAsync(environment, allowInsecureIssuer: false);

        context.Warnings.Should().BeEmpty();
        context.Failures.Should().BeEmpty();
    }
}
