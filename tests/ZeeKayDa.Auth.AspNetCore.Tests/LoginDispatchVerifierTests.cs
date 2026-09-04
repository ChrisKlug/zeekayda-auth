using Microsoft.AspNetCore.Authentication.OAuth;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;
using ZeeKayDa.Auth.AspNetCore.Providers;

namespace ZeeKayDa.Auth.AspNetCore.Tests;

/// <summary>
/// The login dispatch rules, applied at startup: local sign-in is a flag, the login page's
/// presence is the override, and the checks fire only for a host that does the authorization
/// code grant at all.
/// </summary>
public sealed class LoginDispatchVerifierTests
{
    private static readonly IServiceProvider EmptyProvider = new ServiceCollection().BuildServiceProvider();

    private static async Task<StartupVerificationContext> VerifyAsync(
        string? loginPath,
        bool supportsLocalSignIn = true,
        int providerCount = 0,
        bool authorizationCode = true)
    {
        var options = new AuthorizationServerOptions { Issuer = "https://auth.example.com" };
        options.AuthorizationEndpoint.Interaction.LoginPath = loginPath;
        options.AuthorizationEndpoint.Interaction.SupportsLocalSignIn = supportsLocalSignIn;
        options.GrantTypesSupported = authorizationCode ? [GrantType.AuthorizationCode] : [GrantType.ClientCredentials];

        var registry = ProviderRegistry.Empty.Add(
            Enumerable.Range(1, providerCount)
                .Select(index => new ProviderRegistration($"provider-{index}", null, typeof(OAuthHandler<OAuthOptions>))));

        var context = new StartupVerificationContext();
        await new LoginDispatchVerifier(Options.Create(options), registry)
            .VerifyAsync(context, EmptyProvider, TestContext.Current.CancellationToken);

        return context;
    }

    [Fact]
    public async Task An_unconfigured_login_path_warns_at_startup()
    {
        var context = await VerifyAsync(loginPath: null);

        context.Warnings.Should().ContainSingle()
            .Which.Code.Should().Be("interaction.no_login_path");
        context.Failures.Should().BeEmpty();
    }

    [Fact]
    public async Task A_configured_login_path_warns_about_nothing()
    {
        var context = await VerifyAsync("/account/login");

        context.Warnings.Should().BeEmpty();
        context.Failures.Should().BeEmpty();
    }

    [Fact]
    public async Task Two_providers_and_no_login_page_warns_because_the_framework_never_chooses()
    {
        var context = await VerifyAsync(loginPath: null, supportsLocalSignIn: false, providerCount: 2);

        context.Warnings.Should().ContainSingle()
            .Which.Code.Should().Be("interaction.no_login_path");
    }

    [Fact]
    public async Task One_provider_with_local_sign_in_off_and_no_login_page_is_silent()
    {
        // Rule 2: the framework can choose, so the request goes straight to the provider.
        var context = await VerifyAsync(loginPath: null, supportsLocalSignIn: false, providerCount: 1);

        context.Warnings.Should().BeEmpty();
        context.Failures.Should().BeEmpty();
    }

    [Fact]
    public async Task One_provider_with_local_sign_in_on_and_no_login_page_still_warns()
    {
        // The page is needed to offer the choice between the credential form and the provider.
        var context = await VerifyAsync(loginPath: null, supportsLocalSignIn: true, providerCount: 1);

        context.Warnings.Should().ContainSingle()
            .Which.Code.Should().Be("interaction.no_login_path");
    }

    [Theory]
    [InlineData(null)]
    [InlineData("/account/login")]
    public async Task Local_sign_in_off_with_no_providers_fails_startup_whatever_the_login_path(string? loginPath)
    {
        var context = await VerifyAsync(loginPath, supportsLocalSignIn: false, providerCount: 0);

        context.Failures.Should().ContainSingle()
            .Which.Code.Should().Be("interaction.no_sign_in_method");
        context.Warnings.Should().BeEmpty();
    }

    [Fact]
    public async Task The_failure_names_all_three_exits()
    {
        var context = await VerifyAsync(loginPath: null, supportsLocalSignIn: false, providerCount: 0);

        context.Failures.Single().Message.Should()
            .Contain("WithProviders")
            .And.Contain("SupportsLocalSignIn")
            .And.Contain("GrantTypesSupported");
    }

    [Fact]
    public async Task A_host_without_the_authorization_code_grant_is_checked_for_nothing()
    {
        // A client_credentials-only host has no login dispatch: nothing can be wrong with it.
        var context = await VerifyAsync(loginPath: null, supportsLocalSignIn: false, providerCount: 0, authorizationCode: false);

        context.Warnings.Should().BeEmpty();
        context.Failures.Should().BeEmpty();
    }

    [Fact]
    public void A_real_host_with_no_way_to_sign_anyone_in_does_not_start()
    {
        // Control-presence: the verifier above is only a control if AddZeeKayDaAuth registers it.
        using var factory = new TestWebAppFactory(
            configureOptions: options => options.AuthorizationEndpoint.Interaction.SupportsLocalSignIn = false);

        var start = () => factory.CreateClient();

        start.Should().Throw<Exception>()
            .Where(ex => ExceptionChain.FindInChain<ZeeKayDaConfigurationException>(ex)!
                .AggregatedFailures.Any(failure => failure.Code == "interaction.no_sign_in_method"));
    }
}
