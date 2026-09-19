using ZeeKayDa.Auth.AspNetCore.Clients;

namespace ZeeKayDa.Auth.AspNetCore.Tests;

/// <summary>
/// The public client <c>test-client</c> a test host registers, allowed exactly the grants that host
/// serves.
/// </summary>
/// <remarks>
/// A client may be allowed only what the server serves, so a host that switches the code grant off
/// would reject a default client that kept it. Reading the grants off the host's own options callback
/// lets such a test say only what it is about.
/// </remarks>
internal static class DefaultTestClient
{
    internal static IInMemoryClientRegistrationBuilder AddDefaultTestClient(
        this IInMemoryClientRegistrationBuilder clients,
        Action<AuthorizationServerOptions>? configureOptions)
    {
        var served = new AuthorizationServerOptions();
        configureOptions?.Invoke(served);

        return clients.AddPublic("test-client", ["https://test.example.com/callback"], [], ["openid"], client =>
        {
            client.AllowedGrantTypes.Clear();
            client.AllowedGrantTypes.UnionWith(served.GrantTypesSupported);
        });
    }
}
