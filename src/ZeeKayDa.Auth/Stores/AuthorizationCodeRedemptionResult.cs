using System.Diagnostics.CodeAnalysis;

namespace ZeeKayDa.Auth.Stores;

/// <summary>
/// Represents the outcome of an authorization code redemption attempt via
/// <see cref="IAuthorizationCodeStore.TryRedeemAsync"/>.
/// </summary>
/// <remarks>
/// <para>
/// This is a closed discriminated union with exactly four states. The <see langword="private"/>
/// constructor prevents external subclassing, ensuring exhaustive pattern matching is safe and
/// complete. No further subtypes will be added without a major version bump. Callers MUST
/// handle every case:
/// </para>
/// <list type="bullet">
/// <item><description>
///   <see cref="Redeemed"/> — code was valid, bound to the presenting client, and has been
///   atomically consumed. The token endpoint may proceed to issue tokens.
/// </description></item>
/// <item><description>
///   <see cref="ClientMismatch"/> — code exists and is unredeemed but is bound to a different
///   client. The store has NOT consumed the code. Caller MUST return
///   <c>error=invalid_grant</c>.
/// </description></item>
/// <item><description>
///   <see cref="AlreadyRedeemed"/> — code has already been redeemed; a tombstone exists.
///   Caller MUST revoke the refresh token family identified by
///   <see cref="AlreadyRedeemed.FamilyId"/> and return <c>error=invalid_grant</c>
///   (RFC 9700 §2.1.1).
/// </description></item>
/// <item><description>
///   <see cref="NotFound"/> — code is not known to the store (never issued or already expired).
///   Caller MUST return <c>error=invalid_grant</c>.
/// </description></item>
/// </list>
/// <para>
/// The distinction between <see cref="ClientMismatch"/>, <see cref="AlreadyRedeemed"/>, and
/// <see cref="NotFound"/> is security-critical: each triggers a different response behaviour
/// at the token endpoint, and collapsing them would either under-revoke on replay attacks or
/// over-revoke on legitimate requests.
/// </para>
/// </remarks>
public abstract class AuthorizationCodeRedemptionResult
{
    [ExcludeFromCodeCoverage]
    private AuthorizationCodeRedemptionResult() { }

    /// <summary>
    /// The code was valid, bound to the presenting client, and has been marked as redeemed.
    /// A tombstone has been written with the family identifier so that any subsequent replay
    /// of the same code will surface as <see cref="AlreadyRedeemed"/>.
    /// </summary>
    public sealed class Redeemed : AuthorizationCodeRedemptionResult
    {
        /// <summary>
        /// The entry that was stored at issuance time, containing all claims needed for token
        /// generation. The store has already consumed the entry; callers MUST NOT attempt to
        /// redeem it a second time.
        /// </summary>
        public required AuthorizationCodeEntry Entry { get; init; }
    }

    /// <summary>
    /// The code exists and is unredeemed, but is bound to a different client than the one
    /// presenting it. The store has NOT consumed the code.
    /// </summary>
    /// <remarks>
    /// <para>
    /// Caller MUST return <c>error=invalid_grant</c> per RFC 6749 §5.2. The code is left
    /// in place so that the legitimate client may still redeem it (the store does not
    /// invalidate the entry on a client-mismatch attempt).
    /// </para>
    /// <para>
    /// Callers SHOULD emit a security-relevant log event on this outcome. It may indicate a
    /// code-injection attempt or a confused-deputy / token mix-up attack against the
    /// legitimate client.
    /// </para>
    /// </remarks>
    public sealed class ClientMismatch : AuthorizationCodeRedemptionResult { }

    /// <summary>
    /// The code has already been redeemed; a tombstone entry exists in the store.
    /// </summary>
    /// <remarks>
    /// <para>
    /// This outcome indicates a potential replay attack. Caller MUST immediately revoke the
    /// refresh token family identified by <see cref="FamilyId"/> and return
    /// <c>error=invalid_grant</c> (RFC 9700 §2.1.1).
    /// </para>
    /// <para>
    /// <see cref="FamilyId"/> is the plaintext identifier written atomically into the tombstone
    /// envelope during the original redemption (ADR 0013 §7) — it is recoverable even across a
    /// Data-Protection key rotation, since it lives in the envelope's cleartext part rather than
    /// its Data-Protection-protected part. Callers MUST always call <c>RevokeFamilyAsync</c> with
    /// it; the pre-0013 "empty <see cref="FamilyId"/> means skip revocation" fallback no longer
    /// applies — a rotated key can no longer degrade this outcome.
    /// </para>
    /// </remarks>
    public sealed class AlreadyRedeemed : AuthorizationCodeRedemptionResult
    {
        /// <summary>
        /// The refresh token family identifier committed into the tombstone envelope during the
        /// original redemption (ADR 0013 §7). Plaintext, and recoverable even when the envelope's
        /// Data-Protection-protected part cannot be decrypted (e.g. after a key rotation).
        /// </summary>
        /// <remarks>
        /// Caller MUST revoke all tokens in this family via the refresh token store before
        /// returning an error to the client. A future tombstone-loss edge case may still surface
        /// <see cref="string.Empty"/> if the tombstone record itself is missing; that case remains
        /// "reject the replay, skip revocation" — but a DP key rotation alone no longer causes it.
        /// </remarks>
        public required string FamilyId { get; init; }
    }

    /// <summary>
    /// The code is not known to the store — it was never issued, has already expired and been
    /// purged, or the handle is malformed.
    /// </summary>
    /// <remarks>
    /// Caller MUST return <c>error=invalid_grant</c> per RFC 6749 §5.2. No store state is
    /// modified by this outcome.
    /// </remarks>
    public sealed class NotFound : AuthorizationCodeRedemptionResult { }
}
