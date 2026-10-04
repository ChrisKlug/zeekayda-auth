using System.Text;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using ZeeKayDa.Auth.Authorization;
using ZeeKayDa.Auth.Clients;
using ZeeKayDa.Auth.Tokens;

namespace ZeeKayDa.Auth.AspNetCore.Tests.Extensions;

public sealed class ZeeKayDaAuthClientConfigurationBindingTests
{
    private const string Web = "Confidential:web:";
    private const string Spa = "Public:spa:";

    // One key per ConfidentialClientOptions member, each off its default, so a member the binder
    // cannot reach stays at its default and fails the comparison.
    private static readonly Dictionary<string, string?> EveryConfidentialSetting = new()
    {
        [Web + "Secret"] = "web-secret",
        [Web + "SecretHash"] = "$2b$12$hash",
        [Web + "RedirectUris:0"] = "https://app.example.com/cb",
        [Web + "PostLogoutRedirectUris:0"] = "https://app.example.com/signed-out",
        [Web + "AllowedScopes:0"] = "openid",
        [Web + "AllowedScopes:1"] = "profile",
        [Web + "DisplayName"] = "Our app",
        [Web + "InitiateLoginUri"] = "https://app.example.com/login",
        [Web + "RequireConsent"] = "false",
        [Web + "SkipLogoutConfirmation"] = "true",
        [Web + "EnableZkdErrorCodes"] = "true",
        [Web + "AllowedGrantTypes:0"] = "AuthorizationCode",
        [Web + "AllowedGrantTypes:1"] = "RefreshToken",
        [Web + "AllowedResponseTypes:0"] = "Code",
        [Web + "AllowedResponseModes:0"] = "Query",
        [Web + "AllowedPromptValues:0"] = "Login",
        [Web + "AllowedSigningAlgorithms:0"] = "ES256",
        [Web + "AccessTokenLifetime"] = "00:05:00",
        [Web + "IdTokenLifetime"] = "00:02:00",
        [Web + "AdditionalIdTokenClaims:0"] = "department",
        [Web + "AdditionalUserInfoClaims:0"] = "cost_center",
        [Web + "AdditionalAccessTokenClaims:0"] = "tenant",
        [Web + "RequirePkce"] = "false",
        [Web + "AllowedTokenEndpointAuthMethods:0"] = "client_secret_post",
    };

    [Fact]
    public void Every_confidential_client_option_has_a_key_in_the_binding_test()
    {
        var keyed = EveryConfidentialSetting.Keys.Select(key => key[Web.Length..].Split(':')[0]).Distinct();

        keyed.Should().BeEquivalentTo(typeof(ConfidentialClientOptions).GetProperties().Select(p => p.Name));
    }

    [Fact]
    public void A_confidential_client_binds_every_setting_from_its_section()
    {
        var pending = Bind(EveryConfidentialSetting).Pending.Should().ContainSingle().Subject;

        pending.PlaintextSecret.Should().Be("web-secret");
        pending.SecretHash.Should().Be("$2b$12$hash");
        var client = pending.Registration;
        client.ClientId.Should().Be("web");
        client.IsPublic.Should().BeFalse();
        client.RedirectUris.Should().Equal("https://app.example.com/cb");
        client.PostLogoutRedirectUris.Should().Equal("https://app.example.com/signed-out");
        client.AllowedScopes.Should().BeEquivalentTo(["openid", "profile"]);
        client.DisplayName.Should().Be("Our app");
        client.InitiateLoginUri.Should().Be("https://app.example.com/login");
        client.RequireConsent.Should().BeFalse();
        client.SkipLogoutConfirmation.Should().BeTrue();
        client.EnableZkdErrorCodes.Should().BeTrue();
        client.AllowedGrantTypes.Should().BeEquivalentTo([GrantType.AuthorizationCode, GrantType.RefreshToken]);
        client.AllowedResponseTypes.Should().Equal(ResponseType.Code);
        client.AllowedResponseModes.Should().Equal(ResponseMode.Query);
        client.AllowedPromptValues.Should().Equal(PromptValue.Login);
        client.AllowedSigningAlgorithms.Should().Equal(SigningAlgorithm.ES256);
        client.AccessTokenLifetime.Should().Be(TimeSpan.FromMinutes(5));
        client.IdTokenLifetime.Should().Be(TimeSpan.FromMinutes(2));
        client.AdditionalIdTokenClaims.Should().Equal("department");
        client.AdditionalUserInfoClaims.Should().Equal("cost_center");
        client.AdditionalAccessTokenClaims.Should().Equal("tenant");
        client.RequirePkce.Should().BeFalse();
        client.AllowedTokenEndpointAuthMethods.Should().Equal("client_secret_post");
    }

    [Fact]
    public void A_public_client_binds_from_its_section_and_stays_public()
    {
        var client = Bind(new Dictionary<string, string?>
        {
            [Spa + "RedirectUris:0"] = "https://spa.example.com/cb",
            [Spa + "AllowedScopes:0"] = "openid",
            [Spa + "RequireConsent"] = "false",
        }).PreBuilt.Should().ContainSingle().Subject;

        client.ClientId.Should().Be("spa");
        client.IsPublic.Should().BeTrue();
        client.Secrets.Should().BeEmpty();
        client.AllowedTokenEndpointAuthMethods.Should().Equal(TokenEndpointAuthMethods.None);
        client.RedirectUris.Should().Equal("https://spa.example.com/cb");
        client.RequireConsent.Should().BeFalse();
    }

    [Fact]
    public void A_secret_from_a_later_configuration_source_reaches_the_client_by_its_client_id_path()
    {
        var configuration = new ConfigurationBuilder()
            .AddInMemoryCollection(new Dictionary<string, string?> { [Web + "AllowedScopes:0"] = "openid" })
            .AddInMemoryCollection(new Dictionary<string, string?> { [Web + "Secret"] = "from-user-secrets" })
            .Build();

        Bind(configuration).Pending.Should().ContainSingle().Which.PlaintextSecret.Should().Be("from-user-secrets");
    }

    [Fact]
    public void An_empty_json_array_leaves_a_defaulted_collection_on_its_default()
    {
        var configuration = new ConfigurationBuilder()
            .AddJsonStream(new MemoryStream(Encoding.UTF8.GetBytes(
                """{ "Public": { "spa": { "AllowedScopes": [ "openid" ], "AllowedGrantTypes": [] } } }""")))
            .Build();

        Bind(configuration).PreBuilt.Should().ContainSingle().Which.AllowedGrantTypes.Should().Equal(GrantType.AuthorizationCode);
    }

    [Fact]
    public void A_child_other_than_confidential_or_public_is_rejected()
    {
        var act = () => Bind(new Dictionary<string, string?> { ["Confidental:web:Secret"] = "web-secret" });

        act.Should().Throw<InvalidOperationException>().WithMessage("*'Confidental'*");
    }

    [Theory]
    [InlineData("CONFIDENTIAL", "PUBLIC")]
    [InlineData("confidential", "public")]
    public void The_confidential_and_public_children_match_whatever_their_case(string confidential, string @public)
    {
        var registrations = Bind(new Dictionary<string, string?>
        {
            [confidential + ":web:Secret"] = "web-secret",
            [@public + ":spa:AllowedScopes:0"] = "openid",
        });

        registrations.Pending.Should().ContainSingle().Which.Registration.ClientId.Should().Be("web");
        registrations.PreBuilt.Should().ContainSingle().Which.ClientId.Should().Be("spa");
    }

    [Fact]
    public void A_missing_clients_section_is_rejected()
    {
        var configuration = new ConfigurationBuilder()
            .AddInMemoryCollection(new Dictionary<string, string?> { ["Clients:Confidential:web:Secret"] = "web-secret" })
            .Build();

        var act = () => Bind(configuration.GetSection("Cleints"));

        act.Should().Throw<InvalidOperationException>().WithMessage("*missing or empty*");
    }

    [Fact]
    public void A_misspelt_client_key_is_rejected_instead_of_leaving_the_setting_on_its_default()
    {
        var act = () => Bind(new Dictionary<string, string?> { [Web + "RequireConsnet"] = "false" });

        act.Should().Throw<InvalidOperationException>().WithMessage("*RequireConsnet*");
    }

    [Fact]
    public void A_public_client_with_a_secret_is_rejected()
    {
        var act = () => Bind(new Dictionary<string, string?> { [Spa + "Secret"] = "spa-secret" });

        act.Should().Throw<InvalidOperationException>().WithMessage("*Secret*");
    }

    [Fact]
    public void Clients_from_configuration_add_to_clients_registered_in_code()
    {
        var configuration = new ConfigurationBuilder()
            .AddInMemoryCollection(new Dictionary<string, string?> { [Spa + "AllowedScopes:0"] = "openid" })
            .Build();
        var services = new ServiceCollection();

        services.AddZeeKayDaAuth("https://auth.example.com")
            .AddInMemoryClients(clients => clients.AddPublic("in-code", client => client.AllowedScopes.Add("openid")))
            .AddInMemoryClients(configuration);

        Registrations(services).PreBuilt.Select(client => client.ClientId).Should().Equal("in-code", "spa");
    }

    private static InMemoryClientRegistrationOptions Bind(Dictionary<string, string?> values) =>
        Bind(new ConfigurationBuilder().AddInMemoryCollection(values).Build());

    private static InMemoryClientRegistrationOptions Bind(IConfiguration section)
    {
        var services = new ServiceCollection();
        services.AddZeeKayDaAuth("https://auth.example.com").AddInMemoryClients(section);
        return Registrations(services);
    }

    private static InMemoryClientRegistrationOptions Registrations(IServiceCollection services) =>
        (InMemoryClientRegistrationOptions)services
            .Single(descriptor => descriptor.ServiceType == typeof(InMemoryClientRegistrationOptions))
            .ImplementationInstance!;
}
