using System.Collections.Frozen;

namespace ZeeKayDa.Auth.Claims;

/// <summary>
/// The protocol claims an ID token carries: what <c>claims_supported</c> advertises beyond the scopes' own.
/// </summary>
/// <remarks>
/// Smaller than <see cref="ReservedClaimNames"/>, a blocklist that also holds names never issued: advertising
/// a claim no grant produces would claim a capability the server lacks. Every name here must be reserved
/// too, and the set is pinned against a signed ID token, since the issuer writes <c>at_hash</c> after the
/// payload is built.
/// </remarks>
internal static class IdTokenProtocolClaims
{
    /// <summary>Seven claims always, and three when the request or grant has them: Discovery §3 asks what the OP MAY supply.</summary>
    public static readonly FrozenSet<string> Names = FrozenSet.ToFrozenSet(
        [
            // Always; at_hash is written by the issuer (OIDC Core §3.1.3.6).
            "iss", "sub", "aud", "iat", "exp", "auth_time", "at_hash",
            // When the request carried a nonce, and when the grant carries the values.
            "nonce", "acr", "amr",
        ],
        StringComparer.Ordinal);
}
