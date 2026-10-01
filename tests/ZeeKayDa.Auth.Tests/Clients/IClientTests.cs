using ZeeKayDa.Auth.Clients;

namespace ZeeKayDa.Auth.Tests.Clients;

public sealed class IClientTests
{
    [Fact]
    public void IClient_does_not_expose_credentials()
    {
        // The point of the split: code that only decides what to issue a client never sees its
        // secrets. Moving Credentials up to IClient would silently undo that.
        typeof(IClient).GetProperty(nameof(IClientWithCredentials.Credentials))
            .Should().BeNull();
    }

    [Fact]
    public void IClientWithCredentials_is_an_IClient()
    {
        typeof(IClient).IsAssignableFrom(typeof(IClientWithCredentials)).Should().BeTrue();
    }

    [Fact]
    public void An_implementation_that_never_heard_of_consent_requires_it()
    {
        // The default interface member is what keeps consent on for a third-party registration
        // written before the member existed: a silent opt-out would remove the one protection a
        // user has against an authorization request they never started.
        IClient client = new BareClient();

        client.RequireConsent.Should().BeTrue();
        client.DisplayName.Should().BeNull();
        client.InitiateLoginUri.Should().BeNull();
    }

    [Fact]
    public void An_implementation_that_never_heard_of_logout_confirmation_asks_for_it()
    {
        // Skipping the question is an opt-out a registration must state; one written before the
        // member existed keeps asking.
        IClient client = new BareClient();

        client.SkipLogoutConfirmation.Should().BeFalse();
    }

    private sealed class BareClient : IClient
    {
        public string ClientId => "bare";
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
}
