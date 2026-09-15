using ZeeKayDa.Auth.Clients;

namespace ZeeKayDa.Auth.Authorization;

/// <summary>What PKCE requires of a client: the one rule the authorize and token endpoints must agree on.</summary>
internal static class PkceRules
{
    /// <summary>
    /// Whether <paramref name="client"/> may send an authorization request without a code
    /// challenge. Only a confidential client that opted in: a public client's PKCE is the only
    /// thing binding the redemption to the party that started the flow, so its opt-in is ignored
    /// whatever the registration says.
    /// </summary>
    public static bool MayOmitChallenge(IClientMetadata client)
    {
        ArgumentNullException.ThrowIfNull(client);
        return client.AllowNonceInsteadOfPkce && !client.IsPublic;
    }
}
