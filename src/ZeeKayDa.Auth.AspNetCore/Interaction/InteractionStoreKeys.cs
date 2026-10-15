using System.Security.Cryptography;
using System.Text;
using Microsoft.AspNetCore.DataProtection;
using ZeeKayDa.Auth.Stores;

namespace ZeeKayDa.Auth.AspNetCore.Interaction;

/// <summary>
/// How an interaction-store entry is addressed and sealed, both derived from the interaction
/// identifier and its binding secret together, so the store holds neither.
/// </summary>
/// <remarks>
/// The sealing purpose is derived too, so a writer to the store cannot move an entry under a
/// secret of their own choosing and present that secret in a cookie.
/// </remarks>
internal static class InteractionStoreKeys
{
    /// <summary>The entry holding the <see cref="Authorization.AuthorizationRequestContext"/>.</summary>
    public static StoreKey Context(string interactionId, string secret) => Derive("c", interactionId, secret);

    /// <summary>The entry holding a principal an external provider returned, parked for a host page.</summary>
    public static StoreKey PendingPrincipal(string interactionId, string secret) => Derive("p", interactionId, secret);

    /// <summary>The entry holding a sign-out waiting for the user to confirm it.</summary>
    public static StoreKey Logout(string interactionId, string secret) => Derive("l", interactionId, secret);

    /// <summary>
    /// The protector for one entry: <paramref name="root"/>, per kind of entry, narrowed to this pair.
    /// </summary>
    public static IDataProtector ProtectorFor(IDataProtector root, string interactionId, string secret) =>
        root.CreateProtector(interactionId, secret);

    private static StoreKey Derive(string kind, string interactionId, string secret) =>
        StoreKey.Hash("interaction", kind, string.Concat(interactionId, ".", secret));
}
