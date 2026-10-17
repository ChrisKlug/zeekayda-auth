using ZeeKayDa.Auth.Clients;

namespace ZeeKayDa.Auth.AspNetCore.Tests;

/// <summary>
/// The client <c>test-client</c> a test host registers, allowed the grants that host serves.
/// </summary>
/// <remarks>
/// A client may be allowed only what the server serves, and must be allowed something, so a host
/// that switches the code grant off would reject a default client that kept it. Reading the grants
/// off the host's own options callback lets such a test say only what it is about; a host serving
/// no grant gets no client.
/// </remarks>
internal static class DefaultTestClient
{
    internal static InMemoryClientRegistrationBuilder AddDefaultTestClient(
        this InMemoryClientRegistrationBuilder clients,
        Action<AuthorizationServerOptions>? configureOptions)
    {
        var served = new AuthorizationServerOptions();
        configureOptions?.Invoke(served);

        if (served.GrantTypesSupported is not { Count: > 0 } grants)
            return clients;

        return clients.AddPublic("test-client", client =>
        {
            client.RedirectUris.Add("https://test.example.com/callback");
            client.AllowedScopes.Add("openid");
            client.AllowedGrantTypes.UnionWith(grants);
        });
    }
}
