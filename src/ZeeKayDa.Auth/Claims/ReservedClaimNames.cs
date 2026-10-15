using System.Collections.Frozen;

namespace ZeeKayDa.Auth.Claims;

/// <summary>
/// The claim names the framework writes from the grant, dropped from a provider's result. Compared ignoring
/// case, as a <c>ClaimsPrincipal</c> reads them, so <c>Sub</c> cannot win a lookup.
/// </summary>
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
