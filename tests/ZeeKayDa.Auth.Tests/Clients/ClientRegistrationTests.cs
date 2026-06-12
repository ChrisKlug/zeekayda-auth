using ZeeKayDa.Auth.Clients;

namespace ZeeKayDa.Auth.Tests.Clients;

public sealed class ClientRegistrationTests
{
    private sealed record FakeCredential : IClientCredential;

    private sealed class MinimalPublicClient : IClientRegistration
    {
        public string ClientId => "minimal";
        public IReadOnlyList<IClientCredential> Credentials => [];
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
    public void CreateConfidential_sets_IsPublic_to_false_and_provides_non_empty_Credentials()
    {
        var client = ClientRegistration.CreateConfidential(
            clientId: "my-client",
            credential: new FakeCredential(),
            redirectUris: ["https://app/callback"],
            postLogoutRedirectUris: [],
            allowedScopes: ["openid"]);

        client.IsPublic.Should().BeFalse();
        client.Credentials.Should().NotBeEmpty();
    }

    [Fact]
    public void CreatePublic_sets_IsPublic_to_true_and_Credentials_to_empty()
    {
        var client = ClientRegistration.CreatePublic(
            clientId: "spa-client",
            redirectUris: ["https://app/callback"],
            postLogoutRedirectUris: [],
            allowedScopes: ["openid"]);

        client.IsPublic.Should().BeTrue();
        client.Credentials.Should().BeEmpty();
    }

    [Fact]
    public void CreatePublic_sets_AllowedTokenEndpointAuthMethods_to_none()
    {
        var client = ClientRegistration.CreatePublic(
            clientId: "spa-client",
            redirectUris: ["https://app/callback"],
            postLogoutRedirectUris: [],
            allowedScopes: ["openid"]);

        client.AllowedTokenEndpointAuthMethods
            .Should().BeEquivalentTo(new[] { TokenEndpointAuthMethods.None });
    }

    [Fact]
    public void AllowedPromptValues_defaults_to_empty()
    {
        var client = new ClientRegistration
        {
            ClientId = "test",
            Credentials = [],
            IsPublic = true,
            RedirectUris = new HashSet<string>(),
            PostLogoutRedirectUris = new HashSet<string>(),
        };

        client.AllowedPromptValues.Should().BeEmpty();
    }

    [Fact]
    public void AllowedSigningAlgorithms_defaults_to_null()
    {
        var client = new ClientRegistration
        {
            ClientId = "test",
            Credentials = [],
            IsPublic = true,
            RedirectUris = new HashSet<string>(),
            PostLogoutRedirectUris = new HashSet<string>(),
        };

        client.AllowedSigningAlgorithms.Should().BeNull();
    }

    [Fact]
    public void IClientRegistration_AllowedPromptValues_dim_default_is_empty()
    {
        IClientRegistration client = new MinimalPublicClient();

        client.AllowedPromptValues.Should().BeEmpty();
    }

    [Fact]
    public void IClientRegistration_AllowedSigningAlgorithms_dim_default_is_null()
    {
        IClientRegistration client = new MinimalPublicClient();

        client.AllowedSigningAlgorithms.Should().BeNull();
    }

    // Gap 1 — default property values

    [Fact]
    public void DefaultProperties_AllowedGrantTypes_defaults_to_AuthorizationCode()
    {
        var client = new ClientRegistration
        {
            ClientId = "test",
            Credentials = [],
            IsPublic = true,
            RedirectUris = new HashSet<string>(),
            PostLogoutRedirectUris = new HashSet<string>(),
        };

        client.AllowedGrantTypes.Should().BeEquivalentTo(new[] { GrantType.AuthorizationCode });
    }

    [Fact]
    public void DefaultProperties_AllowedResponseTypes_defaults_to_Code()
    {
        var client = new ClientRegistration
        {
            ClientId = "test",
            Credentials = [],
            IsPublic = true,
            RedirectUris = new HashSet<string>(),
            PostLogoutRedirectUris = new HashSet<string>(),
        };

        client.AllowedResponseTypes.Should().BeEquivalentTo(new[] { ResponseType.Code });
    }

    [Fact]
    public void DefaultProperties_AllowedResponseModes_defaults_to_Query_and_FormPost()
    {
        var client = new ClientRegistration
        {
            ClientId = "test",
            Credentials = [],
            IsPublic = true,
            RedirectUris = new HashSet<string>(),
            PostLogoutRedirectUris = new HashSet<string>(),
        };

        client.AllowedResponseModes.Should().BeEquivalentTo(new[] { ResponseMode.Query, ResponseMode.FormPost });
    }

    [Fact]
    public void DefaultProperties_AllowedTokenEndpointAuthMethods_defaults_to_ClientSecretBasic()
    {
        var client = new ClientRegistration
        {
            ClientId = "test",
            Credentials = [],
            IsPublic = true,
            RedirectUris = new HashSet<string>(),
            PostLogoutRedirectUris = new HashSet<string>(),
        };

        client.AllowedTokenEndpointAuthMethods
            .Should().BeEquivalentTo(new[] { TokenEndpointAuthMethods.ClientSecretBasic });
    }

    [Fact]
    public void DefaultProperties_AllowedScopes_defaults_to_empty()
    {
        var client = new ClientRegistration
        {
            ClientId = "test",
            Credentials = [],
            IsPublic = true,
            RedirectUris = new HashSet<string>(),
            PostLogoutRedirectUris = new HashSet<string>(),
        };

        client.AllowedScopes.Should().BeEmpty();
    }

    [Fact]
    public void DefaultProperties_EnableZkdErrorCodes_defaults_to_false()
    {
        var client = new ClientRegistration
        {
            ClientId = "test",
            Credentials = [],
            IsPublic = true,
            RedirectUris = new HashSet<string>(),
            PostLogoutRedirectUris = new HashSet<string>(),
        };

        client.EnableZkdErrorCodes.Should().BeFalse();
    }

    // Gap 2 — CreatePublic stores arguments

    [Fact]
    public void CreatePublic_stores_AllowedScopes()
    {
        var client = ClientRegistration.CreatePublic(
            clientId: "spa-client",
            redirectUris: ["https://app/callback"],
            postLogoutRedirectUris: ["https://app/logout"],
            allowedScopes: ["openid", "profile"]);

        client.AllowedScopes.Should().BeEquivalentTo(new[] { "openid", "profile" });
    }

    [Fact]
    public void CreatePublic_stores_RedirectUris()
    {
        var client = ClientRegistration.CreatePublic(
            clientId: "spa-client",
            redirectUris: ["https://app/callback"],
            postLogoutRedirectUris: [],
            allowedScopes: []);

        client.RedirectUris.Should().BeEquivalentTo(new[] { "https://app/callback" });
    }

    [Fact]
    public void CreatePublic_stores_PostLogoutRedirectUris()
    {
        var client = ClientRegistration.CreatePublic(
            clientId: "spa-client",
            redirectUris: [],
            postLogoutRedirectUris: ["https://app/logout"],
            allowedScopes: []);

        client.PostLogoutRedirectUris.Should().BeEquivalentTo(new[] { "https://app/logout" });
    }

    // Gap 3 — CreateConfidential stores the exact credential instance

    [Fact]
    public void CreateConfidential_stores_exact_credential_instance()
    {
        var credential = new FakeCredential();

        var client = ClientRegistration.CreateConfidential(
            clientId: "my-client",
            credential: credential,
            redirectUris: [],
            postLogoutRedirectUris: [],
            allowedScopes: []);

        client.Credentials.Should().ContainSingle()
            .Which.Should().BeSameAs(credential);
    }

    // Gap 4 — CreateConfidential leaves AllowedTokenEndpointAuthMethods as client_secret_basic

    [Fact]
    public void CreateConfidential_sets_AllowedTokenEndpointAuthMethods_to_ClientSecretBasic()
    {
        var client = ClientRegistration.CreateConfidential(
            clientId: "my-client",
            credential: new FakeCredential(),
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
        var client = ClientRegistration.CreateConfidential(
            clientId: "my-client",
            credential: new FakeCredential(),
            redirectUris: [],
            postLogoutRedirectUris: [],
            allowedScopes: ["openid", "profile"]);

        client.AllowedScopes.Should().BeEquivalentTo(new[] { "openid", "profile" });
    }

    [Fact]
    public void CreateConfidential_stores_RedirectUris()
    {
        var client = ClientRegistration.CreateConfidential(
            clientId: "my-client",
            credential: new FakeCredential(),
            redirectUris: ["https://app/callback"],
            postLogoutRedirectUris: [],
            allowedScopes: []);

        client.RedirectUris.Should().BeEquivalentTo(new[] { "https://app/callback" });
    }

    [Fact]
    public void CreateConfidential_stores_PostLogoutRedirectUris()
    {
        var client = ClientRegistration.CreateConfidential(
            clientId: "my-client",
            credential: new FakeCredential(),
            redirectUris: [],
            postLogoutRedirectUris: ["https://app/logout"],
            allowedScopes: []);

        client.PostLogoutRedirectUris.Should().BeEquivalentTo(new[] { "https://app/logout" });
    }

    // Gap 6 (security) — string sets use ordinal comparison

    [Fact]
    public void CreatePublic_RedirectUris_does_not_match_different_case()
    {
        var client = ClientRegistration.CreatePublic(
            clientId: "spa-client",
            redirectUris: ["https://app/callback"],
            postLogoutRedirectUris: [],
            allowedScopes: []);

        client.RedirectUris.Contains("HTTPS://APP/CALLBACK").Should().BeFalse();
    }

    [Fact]
    public void CreatePublic_AllowedScopes_does_not_match_different_case()
    {
        var client = ClientRegistration.CreatePublic(
            clientId: "spa-client",
            redirectUris: [],
            postLogoutRedirectUris: [],
            allowedScopes: ["openid"]);

        client.AllowedScopes.Contains("OPENID").Should().BeFalse();
    }

    // Gap 7 — PromptValue enum membership

    [Fact]
    public void PromptValue_contains_exactly_expected_members()
    {
        var values = Enum.GetValues<PromptValue>();

        values.Should().BeEquivalentTo(new[]
        {
            PromptValue.None,
            PromptValue.Login,
            PromptValue.Consent,
            PromptValue.SelectAccount,
        });
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

    // Gap 9 — Pbkdf2ClientSecret stores constructor arguments

    [Fact]
    public void Pbkdf2ClientSecret_stores_Iterations_Salt_and_Hash()
    {
        var salt = new byte[] { 1, 2, 3 };
        var hash = new byte[] { 4, 5, 6 };

        var secret = new Pbkdf2ClientSecret(600_000, salt, hash);

        secret.Iterations.Should().Be(600_000);
        secret.Salt.Should().BeSameAs(salt);
        secret.Hash.Should().BeSameAs(hash);
    }

    [Fact]
    public void Pbkdf2ClientSecret_is_assignable_to_IPbkdf2ClientSecret()
    {
        var secret = new Pbkdf2ClientSecret(600_000, new byte[] { 1 }, new byte[] { 2 });

        secret.Should().BeAssignableTo<IPbkdf2ClientSecret>();
    }

    // Gap 10 — interface hierarchy

    [Fact]
    public void Pbkdf2ClientSecret_is_assignable_to_IClientSecret_and_IClientCredential()
    {
        var secret = new Pbkdf2ClientSecret(600_000, new byte[] { 1 }, new byte[] { 2 });

        secret.Should().BeAssignableTo<IClientSecret>();
        secret.Should().BeAssignableTo<IClientCredential>();
    }

    // Gap 11 — IsPublic is a non-DIM declared property with no silent default

    [Fact]
    public void IClientRegistration_IsPublic_returns_implemented_value()
    {
        IClientRegistration client = new MinimalPublicClient();

        client.IsPublic.Should().BeTrue();
    }
}
