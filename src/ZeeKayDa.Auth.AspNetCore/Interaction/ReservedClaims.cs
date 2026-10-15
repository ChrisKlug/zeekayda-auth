using System.Security.Claims;

namespace ZeeKayDa.Auth.AspNetCore.Interaction;

/// <summary>
/// The <c>zkd:</c> claim namespace the framework mints into its own cookies, stripped from every
/// principal a host or provider supplies, on the way in and on the way back out.
/// </summary>
internal static class ReservedClaims
{
    public const string Prefix = "zkd:";

    /// <summary>Ignoring case, as <c>ClaimsPrincipal</c> looks claims up: <c>ZKD:sid</c> must not survive.</summary>
    public static bool IsReserved(Claim claim)
    {
        ArgumentNullException.ThrowIfNull(claim);

        return claim.Type.StartsWith(Prefix, StringComparison.OrdinalIgnoreCase);
    }

    /// <summary>The same identities with every reserved claim removed.</summary>
    /// <remarks>
    /// Rebuilt on the base types from non-virtual members, never through the virtual <c>Clone</c>,
    /// which an override could make return the caller's own instance.
    /// </remarks>
    public static ClaimsPrincipal Strip(ClaimsPrincipal principal)
    {
        ArgumentNullException.ThrowIfNull(principal);

        return new ClaimsPrincipal(principal.Identities.Select(identity => new ClaimsIdentity(
            identity.Claims.Where(claim => !IsReserved(claim)).Select(Materialize),
            identity.AuthenticationType,
            identity.NameClaimType,
            identity.RoleClaimType)));
    }

    /// <summary>A base <see cref="Claim"/> copied member by member, properties included, without its own <c>Clone</c>.</summary>
    public static Claim Materialize(Claim claim)
    {
        var copy = new Claim(claim.Type, claim.Value, claim.ValueType, claim.Issuer, claim.OriginalIssuer);
        foreach (var (key, value) in claim.Properties)
            copy.Properties[key] = value;

        return copy;
    }

    /// <summary>A copy the caller cannot change afterwards: the same rebuild as <see cref="Strip"/>.</summary>
    public static ClaimsPrincipal Snapshot(ClaimsPrincipal principal) => Strip(principal);
}
