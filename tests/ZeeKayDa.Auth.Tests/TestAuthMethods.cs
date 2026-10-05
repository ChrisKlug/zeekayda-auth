using ZeeKayDa.Auth.Tokens;

namespace ZeeKayDa.Auth.Tests;

/// <summary>The token endpoint auth methods a host built by <c>AddZeeKayDaAuth</c> advertises.</summary>
internal static class TestAuthMethods
{
    /// <summary>What the framework's own client-secret authenticator performs, narrowed by the options' filter.</summary>
    public static AdvertisedAuthMethods Advertised(AuthorizationServerOptions options) => new(
        [TokenEndpointAuthMethods.ClientSecretBasic, TokenEndpointAuthMethods.ClientSecretPost],
        options.TokenEndpoint.AdvertisedAuthMethods);
}
