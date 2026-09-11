using System.Security.Claims;

namespace ZeeKayDa.Auth.AspNetCore.Interaction;

/// <summary>
/// The claim namespace the framework reserves for what it mints into its own cookies. Every such
/// claim is removed from a principal the host supplies or a provider returns before the framework
/// stores it, and again before a stored principal is handed back — otherwise a principal built
/// from an inbound token could carry a chosen session identifier or interaction binding in with it.
/// </summary>
internal static class ReservedClaims
{
    public const string Prefix = "zkd:";

    /// <summary>
    /// Compared ignoring case, because that is how claims are read back: <c>ClaimsPrincipal</c>
    /// matches a claim type with <c>OrdinalIgnoreCase</c>, so an ordinal strip would leave
    /// <c>ZKD:sid</c> in place to win the lookup.
    /// </summary>
    public static bool IsReserved(Claim claim)
    {
        ArgumentNullException.ThrowIfNull(claim);

        return claim.Type.StartsWith(Prefix, StringComparison.OrdinalIgnoreCase);
    }

    /// <summary>The same identities with every reserved claim removed.</summary>
    /// <remarks>
    /// Also the framework's copy of a caller's principal. The identities are rebuilt on the base
    /// <see cref="ClaimsIdentity"/> from the claims they carry at this moment, so the result
    /// shares no object with the caller and depends on none of the caller's virtual members —
    /// a <c>Clone</c> override that returned the same instance would hand back the original,
    /// and a change the caller made after the call would then be what the framework signed in.
    /// </remarks>
    public static ClaimsPrincipal Strip(ClaimsPrincipal principal)
    {
        ArgumentNullException.ThrowIfNull(principal);

        return new ClaimsPrincipal(principal.Identities.Select(identity => new ClaimsIdentity(
            identity.Claims.Where(claim => !IsReserved(claim)),
            identity.AuthenticationType,
            identity.NameClaimType,
            identity.RoleClaimType)));
    }

    /// <summary>
    /// A copy of <paramref name="principal"/> that the caller cannot change afterwards: what
    /// was validated is what is used once the store has been awaited. The same rebuild as
    /// <see cref="Strip"/>, named for what the caller wants from it.
    /// </summary>
    public static ClaimsPrincipal Snapshot(ClaimsPrincipal principal) => Strip(principal);
}
