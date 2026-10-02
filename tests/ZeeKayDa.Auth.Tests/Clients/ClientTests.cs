using ZeeKayDa.Auth;
using ZeeKayDa.Auth.Authorization;
using ZeeKayDa.Auth.Clients;
using ZeeKayDa.Auth.Tokens;

namespace ZeeKayDa.Auth.Tests.Clients;

public sealed class ClientTests
{
    private static ClientSecret FakeSecret() => new("$fake$x");

    private sealed class MinimalPublicClient : IClientWithCredentials
    {
        public string ClientId => "minimal";
        public IReadOnlyList<ClientSecret> Secrets => [];
        public bool IsPublic => true;
        public IReadOnlySet<string> RedirectUris => new HashSet<string>();
        public IReadOnlySet<string> PostLogoutRedirectUris => new HashSet<string>();
        public IReadOnlySet<string> AllowedScopes => new HashSet<string>();
        public IReadOnlySet<GrantType> AllowedGrantTypes => new HashSet<GrantType>();
        public IReadOnlySet<ResponseType> AllowedResponseTypes => new HashSet<ResponseType>();
        public IReadOnlySet<ResponseMode> AllowedResponseModes => new HashSet<ResponseMode>();
        public IReadOnlySet<string> AllowedTokenEndpointAuthMethods => new HashSet<string>();
        public bool EnableZkdErrorCodes => false;
    }

    [Fact]
    public void CreateConfidential_sets_IsPublic_to_false_and_provides_non_empty_Secrets()
    {
        var client = Client.CreateConfidential(
            clientId: "my-client",
            secret: FakeSecret(),
            redirectUris: ["https://app/callback"],
            postLogoutRedirectUris: [],
            allowedScopes: ["openid"]);

        client.IsPublic.Should().BeFalse();
        client.Secrets.Should().NotBeEmpty();
    }

    [Fact]
    public void CreatePublic_sets_IsPublic_to_true_and_Secrets_to_empty()
    {
        var client = Client.CreatePublic(
            clientId: "spa-client",
            redirectUris: ["https://app/callback"],
            postLogoutRedirectUris: [],
            allowedScopes: ["openid"]);

        client.IsPublic.Should().BeTrue();
        client.Secrets.Should().BeEmpty();
    }

    [Fact]
    public void CreatePublic_sets_AllowedTokenEndpointAuthMethods_to_none()
    {
        var client = Client.CreatePublic(
            clientId: "spa-client",
            redirectUris: ["https://app/callback"],
            postLogoutRedirectUris: [],
            allowedScopes: ["openid"]);

        client.AllowedTokenEndpointAuthMethods
            .Should().BeEquivalentTo(new[] { TokenEndpointAuthMethods.None });
    }

    [Fact]
    public void RequireConsent_defaults_to_true_and_DisplayName_to_null()
    {
        var client = Client.CreatePublic("app", ["https://app.example.com/cb"], [], ["openid"]);

        client.RequireConsent.Should().BeTrue();
        client.DisplayName.Should().BeNull();
    }

    [Fact]
    public void SkipLogoutConfirmation_defaults_to_false()
    {
        var client = Client.CreatePublic("app", ["https://app.example.com/cb"], [], ["openid"]);

        client.SkipLogoutConfirmation.Should().BeFalse();
    }

    [Fact]
    public void AllowedSigningAlgorithms_defaults_to_null()
    {
        var client = new Client
        {
            ClientId = "test",
            Secrets = [],
            IsPublic = true,
            RedirectUris = new HashSet<string>(),
            PostLogoutRedirectUris = new HashSet<string>(),
        };

        client.AllowedSigningAlgorithms.Should().BeNull();
    }

    [Fact]
    public void IClientRegistration_AllowedSigningAlgorithms_dim_default_is_null()
    {
        IClientWithCredentials client = new MinimalPublicClient();

        client.AllowedSigningAlgorithms.Should().BeNull();
    }

    // Gap 1 — default property values

    [Fact]
    public void DefaultProperties_AllowedGrantTypes_defaults_to_AuthorizationCode()
    {
        var client = new Client
        {
            ClientId = "test",
            Secrets = [],
            IsPublic = true,
            RedirectUris = new HashSet<string>(),
            PostLogoutRedirectUris = new HashSet<string>(),
        };

        client.AllowedGrantTypes.Should().BeEquivalentTo(new[] { GrantType.AuthorizationCode });
    }

    [Fact]
    public void DefaultProperties_AllowedResponseTypes_defaults_to_Code()
    {
        var client = new Client
        {
            ClientId = "test",
            Secrets = [],
            IsPublic = true,
            RedirectUris = new HashSet<string>(),
            PostLogoutRedirectUris = new HashSet<string>(),
        };

        client.AllowedResponseTypes.Should().BeEquivalentTo(new[] { ResponseType.Code });
    }

    [Fact]
    public void DefaultProperties_AllowedResponseModes_defaults_to_Query_only()
    {
        var client = new Client
        {
            ClientId = "test",
            Secrets = [],
            IsPublic = true,
            RedirectUris = new HashSet<string>(),
            PostLogoutRedirectUris = new HashSet<string>(),
        };

        // Query is the one mode the authorization endpoint answers with; a default the server cannot
        // serve would fail every default client at startup.
        client.AllowedResponseModes.Should().BeEquivalentTo(new[] { ResponseMode.Query });
    }

    [Theory]
    [InlineData(false, TokenEndpointAuthMethods.ClientSecretBasic)]
    [InlineData(true, TokenEndpointAuthMethods.None)]
    public void DefaultProperties_AllowedTokenEndpointAuthMethods_follows_IsPublic(bool isPublic, string expected)
    {
        var client = new Client { ClientId = "test", IsPublic = isPublic };

        client.AllowedTokenEndpointAuthMethods.Should().BeEquivalentTo([expected]);
    }

    [Fact]
    public void DefaultProperties_AllowedScopes_defaults_to_empty()
    {
        var client = new Client
        {
            ClientId = "test",
            Secrets = [],
            IsPublic = true,
            RedirectUris = new HashSet<string>(),
            PostLogoutRedirectUris = new HashSet<string>(),
        };

        client.AllowedScopes.Should().BeEmpty();
    }

    // Gap 2 — CreatePublic stores arguments

    [Fact]
    public void CreatePublic_stores_AllowedScopes()
    {
        var client = Client.CreatePublic(
            clientId: "spa-client",
            redirectUris: ["https://app/callback"],
            postLogoutRedirectUris: ["https://app/logout"],
            allowedScopes: ["openid", "profile"]);

        client.AllowedScopes.Should().BeEquivalentTo(new[] { "openid", "profile" });
    }

    [Fact]
    public void CreatePublic_stores_RedirectUris()
    {
        var client = Client.CreatePublic(
            clientId: "spa-client",
            redirectUris: ["https://app/callback"],
            postLogoutRedirectUris: [],
            allowedScopes: []);

        client.RedirectUris.Should().BeEquivalentTo(new[] { "https://app/callback" });
    }

    [Fact]
    public void CreatePublic_stores_PostLogoutRedirectUris()
    {
        var client = Client.CreatePublic(
            clientId: "spa-client",
            redirectUris: [],
            postLogoutRedirectUris: ["https://app/logout"],
            allowedScopes: []);

        client.PostLogoutRedirectUris.Should().BeEquivalentTo(new[] { "https://app/logout" });
    }

    // Gap 3 — CreateConfidential stores the exact secret instance

    [Fact]
    public void CreateConfidential_stores_exact_secret_instance()
    {
        var secret = FakeSecret();

        var client = Client.CreateConfidential(
            clientId: "my-client",
            secret: secret,
            redirectUris: [],
            postLogoutRedirectUris: [],
            allowedScopes: []);

        client.Secrets.Should().ContainSingle()
            .Which.Should().BeSameAs(secret);
    }

    // Gap 4 — CreateConfidential leaves AllowedTokenEndpointAuthMethods as client_secret_basic

    [Fact]
    public void CreateConfidential_sets_AllowedTokenEndpointAuthMethods_to_ClientSecretBasic()
    {
        var client = Client.CreateConfidential(
            clientId: "my-client",
            secret: FakeSecret(),
            redirectUris: [],
            postLogoutRedirectUris: [],
            allowedScopes: []);

        client.AllowedTokenEndpointAuthMethods
            .Should().BeEquivalentTo(new[] { TokenEndpointAuthMethods.ClientSecretBasic });
    }

    // Gap 5 — CreateConfidential stores arguments

    [Fact]
    public void CreateConfidential_stores_AllowedScopes()
    {
        var client = Client.CreateConfidential(
            clientId: "my-client",
            secret: FakeSecret(),
            redirectUris: [],
            postLogoutRedirectUris: [],
            allowedScopes: ["openid", "profile"]);

        client.AllowedScopes.Should().BeEquivalentTo(new[] { "openid", "profile" });
    }

    [Fact]
    public void CreateConfidential_stores_RedirectUris()
    {
        var client = Client.CreateConfidential(
            clientId: "my-client",
            secret: FakeSecret(),
            redirectUris: ["https://app/callback"],
            postLogoutRedirectUris: [],
            allowedScopes: []);

        client.RedirectUris.Should().BeEquivalentTo(new[] { "https://app/callback" });
    }

    [Fact]
    public void CreateConfidential_stores_PostLogoutRedirectUris()
    {
        var client = Client.CreateConfidential(
            clientId: "my-client",
            secret: FakeSecret(),
            redirectUris: [],
            postLogoutRedirectUris: ["https://app/logout"],
            allowedScopes: []);

        client.PostLogoutRedirectUris.Should().BeEquivalentTo(new[] { "https://app/logout" });
    }

    // Gap 6 (security) — string sets use ordinal comparison

    [Fact]
    public void CreatePublic_RedirectUris_does_not_match_different_case()
    {
        var client = Client.CreatePublic(
            clientId: "spa-client",
            redirectUris: ["https://app/callback"],
            postLogoutRedirectUris: [],
            allowedScopes: []);

        client.RedirectUris.Contains("HTTPS://APP/CALLBACK").Should().BeFalse();
    }

    [Fact]
    public void CreatePublic_AllowedScopes_does_not_match_different_case()
    {
        var client = Client.CreatePublic(
            clientId: "spa-client",
            redirectUris: [],
            postLogoutRedirectUris: [],
            allowedScopes: ["openid"]);

        client.AllowedScopes.Contains("OPENID").Should().BeFalse();
    }

    // Gap 8 — TokenEndpointAuthMethods wire-format string values

    [Fact]
    public void TokenEndpointAuthMethods_ClientSecretBasic_has_correct_wire_value()
    {
        TokenEndpointAuthMethods.ClientSecretBasic.Should().Be("client_secret_basic");
    }

    [Fact]
    public void TokenEndpointAuthMethods_ClientSecretPost_has_correct_wire_value()
    {
        TokenEndpointAuthMethods.ClientSecretPost.Should().Be("client_secret_post");
    }

    [Fact]
    public void TokenEndpointAuthMethods_None_has_correct_wire_value()
    {
        TokenEndpointAuthMethods.None.Should().Be("none");
    }

    [Fact]
    public void CreateConfidential_refuses_a_null_secret()
    {
        var act = () => Client.CreateConfidential("c", null!, [], [], []);

        act.Should().Throw<ArgumentNullException>().WithParameterName("secret");
    }

    // Gap 9 — a secret never prints its value

    [Fact]
    public void ClientSecret_ToString_does_not_reveal_the_stored_value()
    {
        // A plaintext secret pasted into a store where a hash belongs would otherwise reach any log
        // that prints a registration.
        var secret = new ClientSecret("pasted-plaintext");

        secret.ToString().Should().NotContain("pasted-plaintext");
        (Client.CreateConfidential("c", secret, [], [], []) with { }).ToString()
            .Should().NotContain("pasted-plaintext");
    }

    // Gap 11 — IsPublic is a non-DIM declared property with no silent default

    [Fact]
    public void IClientRegistration_IsPublic_returns_implemented_value()
    {
        IClientWithCredentials client = new MinimalPublicClient();

        client.IsPublic.Should().BeTrue();
    }
}
