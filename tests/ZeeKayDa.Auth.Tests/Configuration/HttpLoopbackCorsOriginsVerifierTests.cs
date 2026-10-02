using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.FileProviders;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using ZeeKayDa.Auth.Configuration;
using ZeeKayDa.Auth.StartupVerification;

namespace ZeeKayDa.Auth.Tests.Configuration;

/// <summary>
/// The startup record of HTTP loopback CORS origins: absent unless the host opted in, and louder
/// outside the environment where opting in is the expected thing to do.
/// </summary>
public sealed class HttpLoopbackCorsOriginsVerifierTests
{
    private sealed class FakeHostEnvironment(string environmentName) : IHostEnvironment
    {
        public string EnvironmentName { get; set; } = environmentName;
        public string ApplicationName { get; set; } = "TestApp";
        public string ContentRootPath { get; set; } = "/";
        public IFileProvider ContentRootFileProvider { get; set; } = new NullFileProvider();
    }

    private static async Task<StartupVerificationContext> VerifyAsync(string environment, bool allowHttpLoopbackCorsOrigins)
    {
        var sut = new HttpLoopbackCorsOriginsVerifier(
            Options.Create(new AuthorizationServerOptions
            {
                Issuer = "https://auth.example.com",
                Development = { AllowHttpLoopbackCorsOrigins = allowHttpLoopbackCorsOrigins },
            }),
            new FakeHostEnvironment(environment));
        var context = new StartupVerificationContext();

        await sut.VerifyAsync(context, TestContext.Current.CancellationToken);

        return context;
    }

    [Fact]
    public async Task The_flag_in_Development_logs_at_Information()
    {
        var context = await VerifyAsync(Environments.Development, allowHttpLoopbackCorsOrigins: true);

        var warning = context.Warnings.Should().ContainSingle().Which;
        warning.Code.Should().Be("cors_origins.http_loopback_allowed");
        warning.Level.Should().Be(LogLevel.Information);
    }

    [Theory]
    [InlineData("Production")]
    [InlineData("Staging")]
    public async Task The_flag_outside_Development_logs_at_Critical(string environment)
    {
        var context = await VerifyAsync(environment, allowHttpLoopbackCorsOrigins: true);

        var warning = context.Warnings.Should().ContainSingle().Which;
        warning.Code.Should().Be("cors_origins.http_loopback_allowed_outside_development");
        warning.Level.Should().Be(LogLevel.Critical);
    }

    [Theory]
    [InlineData("Development")]
    [InlineData("Production")]
    public async Task The_flag_never_fails_startup(string environment)
    {
        var context = await VerifyAsync(environment, allowHttpLoopbackCorsOrigins: true);

        context.Failures.Should().BeEmpty();
    }

    [Theory]
    [InlineData("Development")]
    [InlineData("Production")]
    public async Task Without_the_flag_nothing_is_recorded(string environment)
    {
        var context = await VerifyAsync(environment, allowHttpLoopbackCorsOrigins: false);

        context.Warnings.Should().BeEmpty();
        context.Failures.Should().BeEmpty();
    }
}
