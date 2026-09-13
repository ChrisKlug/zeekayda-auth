using System.Collections.Generic;
using ZeeKayDa.Auth.Clients;
using ZeeKayDa.Auth.Tokens;

namespace ZeeKayDa.Auth.Tests.Tokens;

public sealed class TokenIssuanceContextTests
{
    private sealed class TestClient : IClientMetadata
    {
        public string ClientId => "test-client";
        public bool IsPublic => true;
        public IReadOnlySet<string> RedirectUris => new HashSet<string>();
        public IReadOnlySet<string> PostLogoutRedirectUris => new HashSet<string>();
        public IReadOnlySet<string> AllowedScopes => new HashSet<string>();
        public IReadOnlySet<GrantType> AllowedGrantTypes => new HashSet<GrantType>();
        public IReadOnlySet<ZeeKayDa.Auth.Authorization.ResponseType> AllowedResponseTypes => new HashSet<ZeeKayDa.Auth.Authorization.ResponseType>();
        public IReadOnlySet<ZeeKayDa.Auth.Authorization.ResponseMode> AllowedResponseModes => new HashSet<ZeeKayDa.Auth.Authorization.ResponseMode>();
        public IReadOnlySet<string> AllowedTokenEndpointAuthMethods => new HashSet<string>();
        public bool EnableZkdErrorCodes => false;
    }

    [Fact]
    public void Constructor_throws_ArgumentNullException_if_client_is_null()
    {
        var act = () => TokenIssuanceContext.ForAccessToken(null!);

        act.Should().Throw<ArgumentNullException>();
    }

    [Fact]
    public void Client_round_trips_for_a_constructed_instance()
    {
        var client = new TestClient();

        var context = TokenIssuanceContext.ForIdToken(client, new IssuedToken("access", TokenKind.AccessToken));

        context.Client.Should().BeSameAs(client);
        context.Kind.Should().Be(TokenKind.IdToken);
        context.AccessToken!.Value.Should().Be("access");
    }

    [Fact]
    public void An_access_token_context_carries_no_companion()
    {
        var context = TokenIssuanceContext.ForAccessToken(new TestClient());

        context.Kind.Should().Be(TokenKind.AccessToken);
        context.AccessToken.Should().BeNull();
    }
}
