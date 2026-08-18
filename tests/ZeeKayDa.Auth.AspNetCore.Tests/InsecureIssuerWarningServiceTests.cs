using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;
using ZeeKayDa.Auth;
using ZeeKayDa.Auth.AspNetCore;

namespace ZeeKayDa.Auth.AspNetCore.Tests;

public sealed class InsecureIssuerWarningServiceTests
{
    private static readonly IServiceProvider EmptyProvider = new ServiceCollection().BuildServiceProvider();

    [Fact]
    public async Task VerifyAsync_adds_a_warning_when_AllowInsecureIssuer_is_true()
    {
        var sut = new InsecureIssuerWarningService(
            Options.Create(new AuthorizationServerOptions
            {
                Issuer = "http://localhost:5000",
                AllowInsecureIssuer = true,
            }));
        var context = new StartupVerificationContext();

        await sut.VerifyAsync(context, EmptyProvider, TestContext.Current.CancellationToken);

        context.Warnings.Should().ContainSingle();
    }

    [Fact]
    public async Task VerifyAsync_adds_a_warning_with_code_issuer_insecure_allowed()
    {
        var sut = new InsecureIssuerWarningService(
            Options.Create(new AuthorizationServerOptions
            {
                Issuer = "http://localhost:5000",
                AllowInsecureIssuer = true,
            }));
        var context = new StartupVerificationContext();

        await sut.VerifyAsync(context, EmptyProvider, TestContext.Current.CancellationToken);

        context.Warnings.Should().ContainSingle()
            .Which.Code.Should().Be("issuer.insecure_allowed");
    }

    [Fact]
    public async Task VerifyAsync_does_not_add_a_warning_when_AllowInsecureIssuer_is_false()
    {
        var sut = new InsecureIssuerWarningService(
            Options.Create(new AuthorizationServerOptions { Issuer = "https://auth.example.com" }));
        var context = new StartupVerificationContext();

        await sut.VerifyAsync(context, EmptyProvider, TestContext.Current.CancellationToken);

        context.Warnings.Should().BeEmpty();
    }

    [Fact]
    public void Name_is_InsecureIssuer()
    {
        var sut = new InsecureIssuerWarningService(
            Options.Create(new AuthorizationServerOptions { Issuer = "https://auth.example.com" }));

        sut.Name.Should().Be("InsecureIssuer");
    }

    [Fact]
    public void Constructor_throws_ArgumentNullException_when_options_is_null()
    {
        var act = () => new InsecureIssuerWarningService(null!);

        act.Should().Throw<ArgumentNullException>().WithParameterName("options");
    }
}
