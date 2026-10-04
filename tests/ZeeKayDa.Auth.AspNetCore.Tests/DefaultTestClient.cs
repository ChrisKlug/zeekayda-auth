using ZeeKayDa.Auth.Clients;

namespace ZeeKayDa.Auth.AspNetCore.Tests;

/// <summary>
/// The client <c>test-client</c> a test host registers, allowed the grants that host serves.
/// </summary>
/// <remarks>
/// A client may be allowed only what the server serves, so a host that switches the code grant off
/// would reject a default client that kept it. Reading the grants off the host's own options callback
/// lets such a test say only what it is about. The client is public, and so never allowed
/// client_credentials (RFC 6749 §4.4); a host serving nothing else gets a confidential client instead.
/// </remarks>
internal static class DefaultTestClient
{
    private const string Secret = "test-client-secret";

    internal static InMemoryClientRegistrationBuilder AddDefaultTestClient(
        this InMemoryClientRegistrationBuilder clients,
        Action<AuthorizationServerOptions>? configureOptions)
    {
        var served = new AuthorizationServerOptions();
        configureOptions?.Invoke(served);

        var publicGrants = served.GrantTypesSupported.Where(grant => grant != GrantType.ClientCredentials).ToList();
        if (publicGrants.Count == 0)
        {
            return clients.AddConfidential("test-client", client =>
            {
                client.Secret = Secret;
                client.RedirectUris.Add("https://test.example.com/callback");
                client.AllowedScopes.Add("openid");
                client.AllowedGrantTypes.UnionWith(served.GrantTypesSupported);
            });
        }

        return clients.AddPublic("test-client", client =>
        {
            client.RedirectUris.Add("https://test.example.com/callback");
            client.AllowedScopes.Add("openid");
            client.AllowedGrantTypes.UnionWith(publicGrants);
        });
    }
}
