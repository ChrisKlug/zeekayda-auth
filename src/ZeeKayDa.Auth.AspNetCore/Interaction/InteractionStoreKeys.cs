using System.Security.Cryptography;
using System.Text;
using ZeeKayDa.Auth.Stores;

namespace ZeeKayDa.Auth.AspNetCore.Interaction;

/// <summary>
/// The keys the framework derives for the interaction store: one per kind of entry, each from
/// the interaction identifier and the secret in that interaction's binding cookie together, so
/// that the store never holds either value and a forged cookie finds nothing.
/// </summary>
internal static class InteractionStoreKeys
{
    private const string Prefix = "zkd:interaction:";

    /// <summary>The entry holding the <see cref="Authorization.AuthorizationRequestContext"/>.</summary>
    public static StoreKey Context(string interactionId, string secret) => Derive("c", interactionId, secret);

    /// <summary>The entry holding a principal an external provider returned, parked for a host page.</summary>
    public static StoreKey PendingPrincipal(string interactionId, string secret) => Derive("p", interactionId, secret);

    private static StoreKey Derive(string kind, string interactionId, string secret)
    {
        var hash = SHA256.HashData(Encoding.UTF8.GetBytes(string.Concat(interactionId, ".", secret)));
        return new StoreKey($"{Prefix}{kind}:{Convert.ToHexStringLower(hash)}");
    }
}
