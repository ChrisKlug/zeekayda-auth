namespace ZeeKayDa.Auth.Stores;

/// <summary>
/// Represents the outcome of a <see cref="IRefreshTokenStore.TryConsumeAsync"/> call.
/// </summary>
/// <remarks>
/// <para>
/// This is a closed hierarchy — exhaustive pattern matching over its nested subtypes is
/// both safe and encouraged. No further subtypes will be added without a major version bump.
/// </para>
/// <para>
/// The subtypes are:
/// <list type="bullet">
///   <item><description><see cref="Consumed"/> — the token was valid and has been consumed.</description></item>
///   <item><description><see cref="ClientMismatch"/> — the token exists but belongs to a different client.</description></item>
///   <item><description><see cref="AlreadyConsumed"/> — reuse detected; the entire family should be revoked.</description></item>
///   <item><description><see cref="Revoked"/> — the token's family was revoked (e.g. due to an earlier reuse detection).</description></item>
///   <item><description><see cref="NotFound"/> — no token matching the given handle was found.</description></item>
/// </list>
/// </para>
/// </remarks>
public abstract class RefreshTokenConsumptionOutcome
{
    private RefreshTokenConsumptionOutcome() { }

    /// <summary>
    /// The token was valid and has been atomically consumed. The entry is returned for use
    /// in issuing a rotated token.
    /// </summary>
    public sealed class Consumed : RefreshTokenConsumptionOutcome
    {
        /// <summary>Gets the refresh token entry that was consumed.</summary>
        public required RefreshTokenEntry Entry { get; init; }
    }

    /// <summary>
    /// The token handle resolved to an entry that belongs to a different client than the one
    /// that presented the token. The request MUST be rejected.
    /// </summary>
    /// <remarks>
    /// This outcome indicates a possible confused-deputy or token mix-up scenario.
    /// The store MUST NOT consume the token when this is the outcome.
    /// </remarks>
    public sealed class ClientMismatch : RefreshTokenConsumptionOutcome { }

    /// <summary>
    /// The token handle was found but had already been consumed — reuse detected.
    /// </summary>
    /// <remarks>
    /// <para>
    /// On receiving this outcome, the caller MUST revoke the entire token family by calling
    /// <see cref="IRefreshTokenStore.RevokeFamilyAsync"/> with <see cref="FamilyId"/>.
    /// </para>
    /// <para>
    /// This is the primary signal for the refresh token reuse detection mechanism described
    /// in ADR 0008 §4.
    /// </para>
    /// </remarks>
    public sealed class AlreadyConsumed : RefreshTokenConsumptionOutcome
    {
        /// <summary>Gets the family identifier of the replayed token chain.</summary>
        public required string FamilyId { get; init; }
    }

    /// <summary>
    /// The token's family has been revoked, for example due to a prior reuse detection.
    /// </summary>
    public sealed class Revoked : RefreshTokenConsumptionOutcome
    {
        /// <summary>Gets the family identifier that was revoked.</summary>
        public required string FamilyId { get; init; }
    }

    /// <summary>
    /// No token matching the given handle was found. The request MUST be rejected.
    /// </summary>
    public sealed class NotFound : RefreshTokenConsumptionOutcome { }
}
