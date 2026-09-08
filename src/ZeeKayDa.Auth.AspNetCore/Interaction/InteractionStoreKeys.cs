using System.Security.Cryptography;
using System.Text;
using Microsoft.AspNetCore.DataProtection;
using ZeeKayDa.Auth.Stores;

namespace ZeeKayDa.Auth.AspNetCore.Interaction;

/// <summary>
/// How an interaction-store entry is addressed and sealed: the key the framework derives for it,
/// and the Data Protection purpose its bytes are protected under. Both come from the interaction
/// identifier and the secret in that interaction's binding cookie together, so that the store
/// never holds either value and a forged cookie finds nothing.
/// </summary>
/// <remarks>
/// The key alone would leave one attack open. The identifier is treated as leakable, and a
/// writer to the store — not a copy of it — could move an entry's valid ciphertext under the key
/// for that identifier and a secret of their own choosing, then present that secret in a cookie
/// of their own. Deriving the purpose from the same pair closes it: bytes sealed for one secret
/// do not unprotect under another, whichever row they sit in.
/// </remarks>
internal static class InteractionStoreKeys
{
    private const string Prefix = "zkd:interaction:";

    /// <summary>The entry holding the <see cref="Authorization.AuthorizationRequestContext"/>.</summary>
    public static StoreKey Context(string interactionId, string secret) => Derive("c", interactionId, secret);

    /// <summary>The entry holding a principal an external provider returned, parked for a host page.</summary>
    public static StoreKey PendingPrincipal(string interactionId, string secret) => Derive("p", interactionId, secret);

    /// <summary>
    /// The protector for one entry: <paramref name="root"/> — already carrying the purpose that
    /// separates one kind of entry from another — narrowed to this interaction and this secret.
    /// </summary>
    public static IDataProtector ProtectorFor(IDataProtector root, string interactionId, string secret) =>
        root.CreateProtector(interactionId, secret);

    private static StoreKey Derive(string kind, string interactionId, string secret)
    {
        var hash = SHA256.HashData(Encoding.UTF8.GetBytes(string.Concat(interactionId, ".", secret)));
        return new StoreKey($"{Prefix}{kind}:{Convert.ToHexStringLower(hash)}");
    }
}
