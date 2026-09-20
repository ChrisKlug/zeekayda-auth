using System.Collections.Frozen;

namespace ZeeKayDa.Auth.Claims;

/// <summary>
/// The protocol claim names an ID token carries, as opposed to the ones a scope unlocks. This is
/// what the discovery document advertises in <c>claims_supported</c> beyond the scopes' own claims.
/// </summary>
/// <remarks>
/// <para>
/// <strong>Not the same set as <see cref="ReservedClaimNames"/>, and deliberately smaller.</strong>
/// That set is a blocklist: a subject claim must never occupy a protocol-reserved name, so it holds
/// names the framework does not issue at all — <c>azp</c>, <c>c_hash</c>, <c>sid</c>, <c>nbf</c>,
/// <c>jti</c> — precisely so a claims provider cannot mint one. This set
/// answers the opposite question: what the server can actually supply. Advertising a claim no
/// grant ever produces tells a relying party the server has a capability it does not have, which
/// is worse than the RECOMMENDED metadata being absent (OpenID Connect Discovery 1.0 §3).
/// </para>
/// <para>
/// Every name here must also be reserved, or the claims provider could assert one and the
/// discovery document would be advertising a claim the subject controls;
/// <c>Every_advertised_protocol_claim_is_reserved</c> fails the build if that ever stops holding.
/// </para>
/// <para>
/// <strong>The set is pinned against a finished ID token, not against a payload builder.</strong>
/// An ID token is assembled at more than one seam — <see cref="Tokens.JwtTokenIssuer"/> writes
/// <c>at_hash</c> after the grant's payload is built — so a guard placed at the first seam cannot
/// see the later ones, and missed <c>at_hash</c> when this set was first written.
/// <c>The_advertised_protocol_claims_are_exactly_what_a_signed_ID_token_carries</c> asserts
/// equality against a signed token, which fails in both directions.
/// </para>
/// </remarks>
internal static class IdTokenProtocolClaims
{
    /// <summary>
    /// What an ID token carries, whichever grant issues it: seven always, and three when the
    /// request or the grant has the values. A claim the server supplies only sometimes still
    /// belongs here — Discovery §3 asks for the claims the OP <em>MAY</em> be able to supply, not
    /// the ones it always does.
    /// </summary>
    public static readonly FrozenSet<string> Names = FrozenSet.ToFrozenSet(
        [
            // Always. at_hash is written by the issuer rather than the grant's payload builder,
            // and binds the ID token to the access token issued with it (OIDC Core §3.1.3.6).
            "iss", "sub", "aud", "iat", "exp", "auth_time", "at_hash",
            // When the request carried a nonce, and when the grant carries the values.
            "nonce", "acr", "amr",
        ],
        StringComparer.Ordinal);
}
