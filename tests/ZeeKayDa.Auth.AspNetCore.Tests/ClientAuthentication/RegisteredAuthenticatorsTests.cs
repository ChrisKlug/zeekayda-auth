using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;
using ZeeKayDa.Auth.AspNetCore.ClientAuthentication;
using ZeeKayDa.Auth.Tokens;

namespace ZeeKayDa.Auth.AspNetCore.Tests.ClientAuthentication;

public sealed class RegisteredAuthenticatorsTests
{
    private sealed class ChangingDeclarationAuthenticator : IClientAuthenticator
    {
        public HashSet<string> Declared { get; } = new(StringComparer.Ordinal) { TokenEndpointAuthMethods.ClientSecretBasic };
        public IReadOnlySet<string> AuthenticationMethods => Declared;
        public ClientAuthenticatorMatch CanHandle(TokenRequestContext context) => ClientAuthenticatorMatch.None;
        public Task<ClientAuthenticationResult> AuthenticateAsync(
            ClientAuthenticationContext context, CancellationToken ct)
            => Task.FromResult(ClientAuthenticationResult.NotValid());
    }

    [Fact]
    public void The_advertised_methods_ignore_a_declaration_changed_after_registration()
    {
        var authenticator = new ChangingDeclarationAuthenticator();
        var services = new ServiceCollection();
        services.AddSingleton(Options.Create(new AuthorizationServerOptions()));
        services.AddSingleton(new RegisteredAuthenticators([authenticator]));
        using var provider = services.BuildServiceProvider();

        authenticator.Declared.Clear();
        authenticator.Declared.Add("private_key_jwt");

        RegisteredAuthenticators.Advertise(provider).Methods.Should().Equal(
            TokenEndpointAuthMethods.ClientSecretBasic, TokenEndpointAuthMethods.None);
    }

    [Fact]
    public void The_declaration_is_read_once_at_registration()
    {
        var authenticator = new ChangingDeclarationAuthenticator();
        var registered = new RegisteredAuthenticators([authenticator]).All.Single();

        authenticator.Declared.Add("private_key_jwt");

        registered.Declared.Should().Equal(TokenEndpointAuthMethods.ClientSecretBasic);
        registered.Performs("private_key_jwt").Should().BeFalse();
    }
}
