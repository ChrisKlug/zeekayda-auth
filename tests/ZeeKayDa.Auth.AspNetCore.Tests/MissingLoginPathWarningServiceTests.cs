using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;

namespace ZeeKayDa.Auth.AspNetCore.Tests;

public sealed class MissingLoginPathWarningServiceTests
{
    private static readonly IServiceProvider EmptyProvider = new ServiceCollection().BuildServiceProvider();

    private static async Task<StartupVerificationContext> VerifyAsync(string? loginPath)
    {
        var options = new AuthorizationServerOptions { Issuer = "https://auth.example.com" };
        options.AuthorizationEndpoint.Interaction.LoginPath = loginPath;

        var context = new StartupVerificationContext();
        await new MissingLoginPathWarningService(Options.Create(options))
            .VerifyAsync(context, EmptyProvider, TestContext.Current.CancellationToken);

        return context;
    }

    [Fact]
    public async Task An_unconfigured_login_path_warns_at_startup()
    {
        var context = await VerifyAsync(loginPath: null);

        context.Warnings.Should().ContainSingle()
            .Which.Code.Should().Be("interaction.no_login_path");
    }

    [Fact]
    public async Task A_configured_login_path_warns_about_nothing()
    {
        (await VerifyAsync("/account/login")).Warnings.Should().BeEmpty();
    }
}
