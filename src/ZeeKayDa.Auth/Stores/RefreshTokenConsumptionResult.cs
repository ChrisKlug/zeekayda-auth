using System.Diagnostics.CodeAnalysis;

namespace ZeeKayDa.Auth.Stores;

/// <summary>
/// Represents the outcome of a <see cref="IRefreshTokenStore.TryConsumeAsync"/> call.
/// </summary>
/// <remarks>
/// A closed hierarchy — exhaustive pattern matching over its nested subtypes
/// (<see cref="Consumed"/>, <see cref="ClientMismatch"/>, <see cref="AlreadyConsumed"/>,
/// <see cref="Revoked"/>, <see cref="NotFound"/>) is both safe and encouraged. No further
/// subtypes will be added without a major version bump.
/// </remarks>
public abstract class RefreshTokenConsumptionResult
{
    [ExcludeFromCodeCoverage]
    private RefreshTokenConsumptionResult() { }

    /// <summary>
    /// The token was valid and has been atomically consumed. The entry is returned for use
    /// in issuing a rotated token.
    /// </summary>
    public sealed class Consumed : RefreshTokenConsumptionResult
    {
        /// <summary>Gets the refresh token entry that was consumed.</summary>
        public required RefreshTokenEntry Entry { get; init; }
    }

    /// <summary>
    /// The token handle resolved to an entry that belongs to a different client than the one
    /// that presented the token. The request MUST be rejected.
    /// </summary>
    /// <remarks>
    /// Indicates a possible confused-deputy or token mix-up scenario. The store MUST NOT consume
    /// the token and MUST NOT trigger family revocation — doing so would let an attacker who
    /// captured a token handle but not the <c>client_id</c> force-revoke the legitimate user's
    /// session. Reject with <c>invalid_grant</c> only.
    /// </remarks>
    public sealed class ClientMismatch : RefreshTokenConsumptionResult { }

    /// <summary>
    /// The token handle was found but had already been consumed — reuse detected.
    /// </summary>
    /// <remarks>
    /// The primary signal for refresh token reuse detection. On receiving this outcome, the
    /// caller MUST revoke the entire token family by calling
    /// <see cref="IRefreshTokenStore.RevokeFamilyAsync"/> with <see cref="FamilyId"/>.
    /// </remarks>
    public sealed class AlreadyConsumed : RefreshTokenConsumptionResult
    {
        /// <summary>Gets the family identifier of the replayed token chain.</summary>
        public required string FamilyId { get; init; }
    }

    /// <summary>
    /// The token's family has been revoked, for example due to a prior reuse detection.
    /// </summary>
    /// <remarks>
    /// The family is already revoked when this outcome is returned — a defensive call to
    /// <see cref="IRefreshTokenStore.RevokeFamilyAsync"/> is safe and idempotent but not required.
    /// </remarks>
    public sealed class Revoked : RefreshTokenConsumptionResult
    {
        /// <summary>Gets the family identifier that was revoked.</summary>
        public required string FamilyId { get; init; }
    }

    /// <summary>
    /// No token matching the given handle was found. The request MUST be rejected.
    /// </summary>
    public sealed class NotFound : RefreshTokenConsumptionResult { }
}
