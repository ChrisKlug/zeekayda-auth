using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;
using ZeeKayDa.Auth.Tokens;

namespace ZeeKayDa.Auth.AspNetCore.ClientAuthentication;

/// <summary>Builds the advertised token endpoint auth methods from the registered authenticators.</summary>
internal static class AuthenticatorAuthMethods
{
    /// <summary>The DI factory <c>AddZeeKayDaAuth</c> registers for <see cref="AdvertisedAuthMethods"/>.</summary>
    public static AdvertisedAuthMethods Resolve(IServiceProvider services) => new(
        // A null set breaks the interface contract; ClientAuthenticatorActivator names it at startup.
        services.GetServices<IClientAuthenticator>()
            .SelectMany(authenticator => authenticator.AuthenticationMethods ?? (IEnumerable<string>)[]),
        services.GetRequiredService<IOptions<AuthorizationServerOptions>>().Value.TokenEndpoint.AdvertisedAuthMethods);
}
