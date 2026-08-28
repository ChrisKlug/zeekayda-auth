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
    public void Client_throws_InvalidOperationException_on_a_default_instance()
    {
        // default(TokenIssuanceContext) would otherwise hand a third-party issuer a null Client
        // from a member the API declares non-null — the SigningContext pattern closes it.
        var context = default(TokenIssuanceContext);

        var act = () => context.Client;

        act.Should().Throw<InvalidOperationException>();
    }

    [Fact]
    public void Constructor_throws_ArgumentNullException_if_client_is_null()
    {
        var act = () => new TokenIssuanceContext(null!, TokenKind.AccessToken);

        act.Should().Throw<ArgumentNullException>();
    }

    [Fact]
    public void ToString_prints_default_instances_without_throwing()
    {
        default(TokenIssuanceContext).ToString().Should().Contain("<default>");
    }

    [Fact]
    public void Client_round_trips_for_a_constructed_instance()
    {
        var client = new TestClient();

        var context = new TokenIssuanceContext(client, TokenKind.IdToken);

        context.Client.Should().BeSameAs(client);
        context.Kind.Should().Be(TokenKind.IdToken);
    }
}
