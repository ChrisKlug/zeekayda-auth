using ZeeKayDa.Auth.Clients;

namespace ZeeKayDa.Auth.Authorization;

/// <summary>What PKCE requires of a client: the one rule the authorize and token endpoints must agree on.</summary>
internal static class PkceRules
{
    /// <summary>
    /// Whether <paramref name="client"/> may omit the code challenge: only a confidential client not
    /// requiring PKCE, since a public client's PKCE is all that binds redemption to the flow's starter.
    /// </summary>
    public static bool MayOmitChallenge(IClient client)
    {
        ArgumentNullException.ThrowIfNull(client);
        return !client.RequirePkce && !client.IsPublic;
    }
}
