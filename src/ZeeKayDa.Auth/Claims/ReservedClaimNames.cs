using System.Collections.Frozen;

namespace ZeeKayDa.Auth.Claims;

/// <summary>
/// The claim names the framework writes from the grant. A record carrying one of them is
/// dropped from a provider's result before selection, so a provider cannot re-assert a subject,
/// an audience or an authentication event.
/// </summary>
/// <remarks>
/// Compared ignoring case, because that is how a resource server reads a claim back: a
/// <c>ClaimsPrincipal</c> matches a claim type with <c>OrdinalIgnoreCase</c>, so an ordinal
/// strip would leave <c>Sub</c> in place to win the lookup.
/// </remarks>
internal static class ReservedClaimNames
{
    /// <summary>The namespace the framework mints its own claims into, in tokens and cookies alike.</summary>
    public const string Prefix = "zkd:";

    private static readonly FrozenSet<string> Names = FrozenSet.ToFrozenSet(
        [
            "iss", "sub", "aud", "exp", "nbf", "iat", "jti",
            "auth_time", "nonce", "acr", "amr", "azp", "at_hash", "c_hash", "sid",
            "scope", "client_id", "cnf", "act",
        ],
        StringComparer.OrdinalIgnoreCase);

    public static bool IsReserved(string name)
    {
        ArgumentNullException.ThrowIfNull(name);

        return Names.Contains(name) || name.StartsWith(Prefix, StringComparison.OrdinalIgnoreCase);
    }
}
