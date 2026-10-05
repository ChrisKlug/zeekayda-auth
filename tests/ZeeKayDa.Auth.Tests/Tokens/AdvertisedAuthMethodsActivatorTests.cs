using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;
using ZeeKayDa.Auth.StartupVerification;
using ZeeKayDa.Auth.Tokens;

namespace ZeeKayDa.Auth.Tests.Tokens;

public sealed class AdvertisedAuthMethodsActivatorTests
{
    private static readonly string[] _clientSecretBasic = [TokenEndpointAuthMethods.ClientSecretBasic];

    /// <summary>Runs the check for a server whose authenticators perform <paramref name="performable"/>.</summary>
    private static async Task<StartupVerificationContext> VerifyAsync(
        string[] performable, string[]? filter, params GrantType[] grants)
    {
        var options = new AuthorizationServerOptions
        {
            GrantTypesSupported = grants.Length > 0 ? [.. grants] : [GrantType.AuthorizationCode],
        };
        options.TokenEndpoint.AdvertisedAuthMethods = filter;

        var services = new ServiceCollection();
        services.AddSingleton(new AdvertisedAuthMethods(performable, filter));
        await using var provider = services.BuildServiceProvider();
        var context = new StartupVerificationContext();

        await new AdvertisedAuthMethodsActivator(Options.Create(options), provider)
            .VerifyAsync(context, TestContext.Current.CancellationToken);

        return context;
    }

    // ── Filter against what the server performs ───────────────────────────────────────────────────

    [Fact]
    public async Task Verify_succeeds_and_does_not_warn_when_no_filter_is_configured()
    {
        var context = await VerifyAsync(_clientSecretBasic, filter: null);

        context.Failures.Should().BeEmpty();
        context.Warnings.Should().BeEmpty();
    }

    [Fact]
    public async Task Verify_warns_when_the_filter_names_a_method_no_authenticator_performs()
    {
        var context = await VerifyAsync(_clientSecretBasic, [TokenEndpointAuthMethods.ClientSecretBasic, "private_key_jwt"]);

        context.Failures.Should().BeEmpty("an unperformable entry is a no-op, not a misstatement");
        context.Warnings.Should().ContainSingle()
            .Which.Should().Match<StartupVerificationWarning>(warning =>
                warning.Code == "token_endpoint.advertised_auth_methods.unperformable" &&
                warning.Args.Contains("private_key_jwt"));
    }

    [Fact]
    public async Task Verify_fails_when_the_filter_names_a_performable_method_in_different_casing()
    {
        var context = await VerifyAsync(_clientSecretBasic, ["Client_Secret_Basic", TokenEndpointAuthMethods.None]);

        context.Failures.Should().ContainSingle()
            .Which.Code.Should().Be("token_endpoint.advertised_auth_methods.casing");
        context.Warnings.Should().BeEmpty("the entry is reported once, as the typo it is");
    }

    [Fact]
    public async Task Verify_fails_when_the_filter_leaves_no_method_the_server_performs()
    {
        var context = await VerifyAsync(_clientSecretBasic, ["private_key_jwt"]);

        context.Failures.Should().ContainSingle()
            .Which.Code.Should().Be("token_endpoint.advertised_auth_methods.none_performable");
    }

    [Fact]
    public async Task Verify_succeeds_when_the_filter_withholds_a_method_an_authenticator_performs()
    {
        var context = await VerifyAsync(
            [TokenEndpointAuthMethods.ClientSecretBasic, TokenEndpointAuthMethods.ClientSecretPost],
            _clientSecretBasic);

        context.Failures.Should().BeEmpty();
    }

    // ── The client credentials grant needs a credential (RFC 6749 §4.4) ──────────────────────────

    [Fact]
    public async Task Verify_fails_when_client_credentials_is_served_and_the_filter_leaves_only_none()
    {
        var context = await VerifyAsync(_clientSecretBasic, [TokenEndpointAuthMethods.None], GrantType.ClientCredentials);

        context.Failures.Should().ContainSingle()
            .Which.Code.Should().Be("token_endpoint.advertised_auth_methods.only_none_with_client_credentials");
    }

    [Fact]
    public async Task Verify_fails_when_client_credentials_is_served_and_no_authenticator_is_registered()
    {
        // Also the core-only host: without the HTTP layer nothing but 'none' is performed.
        var context = await VerifyAsync([], filter: null, GrantType.AuthorizationCode, GrantType.ClientCredentials);

        context.Failures.Should().ContainSingle()
            .Which.Code.Should().Be("token_endpoint.advertised_auth_methods.only_none_with_client_credentials");
    }

    [Fact]
    public async Task Verify_succeeds_when_client_credentials_is_served_and_a_credential_method_is_advertised()
    {
        var context = await VerifyAsync(_clientSecretBasic, filter: null, GrantType.ClientCredentials);

        context.Failures.Should().BeEmpty();
    }

    [Fact]
    public async Task Verify_succeeds_with_only_none_advertised_when_client_credentials_is_not_served()
    {
        var context = await VerifyAsync([], filter: null);

        context.Failures.Should().BeEmpty("a server with only public clients serves the code grant with PKCE");
    }

    // ── Registration ──────────────────────────────────────────────────────────────────────────────

    [Fact]
    public void AddZeeKayDaAuthCore_registers_the_check_so_a_core_only_host_is_held_to_it()
    {
        var services = new ServiceCollection();

        services.AddZeeKayDaAuthCore(options => options.Issuer = "https://auth.example.com");

        services.Should().ContainSingle(descriptor =>
            descriptor.ImplementationType == typeof(AdvertisedAuthMethodsActivator))
            .Which.ServiceType.Should().Be(typeof(IStartupActivator));
    }
}
