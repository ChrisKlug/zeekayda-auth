using ZeeKayDa.Auth.Clients;

namespace ZeeKayDa.Auth.Tests.Clients;

public sealed class ClientRegistrationTests
{
    private sealed record FakeCredential : IClientCredential;

    [Fact]
    public void CreateConfidential_SetsIsPublicFalseAndNonEmptyCredentials()
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
    public void CreatePublic_SetsIsPublicTrueAndEmptyCredentials()
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
    public void CreatePublic_SetsAllowedTokenEndpointAuthMethodsToNone()
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
    public void AllowedPromptValues_DefaultIsEmpty()
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
    public void AllowedSigningAlgorithms_DefaultIsNull()
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
    public void IClientRegistration_AllowedPromptValues_DimDefaultIsEmpty()
    {
        IClientRegistration client = new ClientRegistration
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
    public void IClientRegistration_AllowedSigningAlgorithms_DimDefaultIsNull()
    {
        IClientRegistration client = new ClientRegistration
        {
            ClientId = "test",
            Credentials = [],
            IsPublic = true,
            RedirectUris = new HashSet<string>(),
            PostLogoutRedirectUris = new HashSet<string>(),
        };

        client.AllowedSigningAlgorithms.Should().BeNull();
    }
}
