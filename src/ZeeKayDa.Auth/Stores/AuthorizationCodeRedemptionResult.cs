using System.Diagnostics.CodeAnalysis;

namespace ZeeKayDa.Auth.Stores;

/// <summary>
/// Represents the outcome of an authorization code redemption attempt via
/// <see cref="IAuthorizationCodeStore.TryRedeemAsync"/>.
/// </summary>
/// <remarks>
/// A closed discriminated union with exactly four states — see <see cref="Redeemed"/>,
/// <see cref="ClientMismatch"/>, <see cref="AlreadyRedeemed"/>, and <see cref="NotFound"/>. The
/// <see langword="private"/> constructor prevents external subclassing, ensuring exhaustive
/// pattern matching is safe and complete. Callers MUST handle every case: collapsing the
/// distinction between them would either under-revoke on replay attacks or over-revoke on
/// legitimate requests.
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
    /// Caller MUST return <c>error=invalid_grant</c> per RFC 6749 §5.2. The code is left in place
    /// so the legitimate client may still redeem it. Callers SHOULD emit a security-relevant log
    /// event on this outcome — it may indicate a code-injection or token-mix-up attack.
    /// </remarks>
    public sealed class ClientMismatch : AuthorizationCodeRedemptionResult { }

    /// <summary>
    /// The code has already been redeemed; a tombstone entry exists in the store.
    /// </summary>
    /// <remarks>
    /// This outcome indicates a potential replay attack. Caller MUST immediately revoke the
    /// refresh token family identified by <see cref="FamilyId"/> and return
    /// <c>error=invalid_grant</c> (RFC 9700 §2.1.1). <see cref="FamilyId"/> lives in the
    /// tombstone envelope's cleartext part, so it remains recoverable even across a
    /// Data-Protection key rotation.
    /// </remarks>
    public sealed class AlreadyRedeemed : AuthorizationCodeRedemptionResult
    {
        /// <summary>
        /// The refresh token family identifier committed into the tombstone envelope during the
        /// original redemption. Plaintext, and recoverable even when the envelope's
        /// Data-Protection-protected part cannot be decrypted (e.g. after a key rotation).
        /// </summary>
        /// <remarks>
        /// Caller MUST revoke all tokens in this family via the refresh token store before
        /// returning an error to the client. A future tombstone-loss edge case may still surface
        /// <see cref="string.Empty"/> if the tombstone record itself is missing; that case remains
        /// "reject the replay, skip revocation."
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
