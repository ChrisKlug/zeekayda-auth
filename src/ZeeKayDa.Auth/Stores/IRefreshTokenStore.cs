namespace ZeeKayDa.Auth.Stores;

/// <summary>
/// Provides storage and lifecycle management for refresh tokens.
/// </summary>
/// <remarks>
/// <para>
/// <strong>Restart behaviour.</strong>
/// The default in-memory store loses all refresh tokens on process restart. For a
/// single-instance deployment where occasional deployment-triggered re-authentication is
/// acceptable, this is fine. For continuous availability across restarts or rolling
/// deployments, replace <see cref="IRefreshTokenStore"/> with an implementation backed by
/// a persistent store (e.g. Redis or a relational database).
/// </para>
/// <para>
/// <strong>Single-instance only.</strong>
/// The default in-memory store is single-instance only. Running multiple instances of the
/// identity provider with the default store silently disables reuse detection — each
/// instance holds an independent view of consumed tokens, so a replayed token presented to
/// a different instance appears valid. Multi-instance deployments MUST replace the default
/// with a shared, atomic backend.
/// </para>
/// <para>
/// <strong>Multi-tenant limitation.</strong>
/// This interface does not carry a <c>TenantId</c> parameter. Multi-tenant key-space
/// isolation is the responsibility of the custom store implementation. A naive multi-tenant
/// store that does not namespace cache keys or check tenant binding creates a
/// confused-deputy risk — a token issued in one tenant could be replayed in another.
/// Isolation requires a custom store that encodes tenant context in its storage keys and
/// validates tenant binding on every lookup.
/// </para>
/// <para>
/// Implementations MUST throw <see cref="ZeeKayDaStoreException"/> (not raw infrastructure
/// exceptions) when an underlying transport (cache, database, network) fails. Semantic
/// outcomes such as <see cref="RefreshTokenConsumptionOutcome.NotFound"/> or
/// <see cref="RefreshTokenConsumptionOutcome.AlreadyConsumed"/> are returned, not thrown.
/// </para>
/// </remarks>
public interface IRefreshTokenStore
{
    /// <summary>
    /// Stores a new refresh token entry.
    /// </summary>
    /// <param name="entry">The refresh token metadata to persist. The token handle itself is
    /// expected to be stored as a hashed key by the implementation — it is not a property on
    /// <see cref="RefreshTokenEntry"/>.</param>
    /// <param name="cancellationToken">A token to cancel the operation.</param>
    /// <exception cref="ZeeKayDaStoreException">
    /// Thrown when the underlying store transport fails.
    /// </exception>
    Task StoreAsync(RefreshTokenEntry entry, CancellationToken cancellationToken);

    /// <summary>
    /// Looks up a refresh token entry by its raw handle without consuming it.
    /// </summary>
    /// <param name="tokenHandle">The raw (unhashed) refresh token handle.</param>
    /// <param name="cancellationToken">A token to cancel the operation.</param>
    /// <returns>
    /// The <see cref="RefreshTokenEntry"/> if found and not yet consumed; otherwise
    /// <see langword="null"/>.
    /// </returns>
    /// <remarks>
    /// This method is intended for read-only lookups (e.g. introspection). To consume a
    /// token as part of a token refresh request, use
    /// <see cref="TryConsumeAsync"/> instead.
    /// </remarks>
    /// <exception cref="ZeeKayDaStoreException">
    /// Thrown when the underlying store transport fails.
    /// </exception>
    ValueTask<RefreshTokenEntry?> FindAsync(string tokenHandle, CancellationToken cancellationToken);

    /// <summary>
    /// Atomically validates and consumes a refresh token presented by a client.
    /// </summary>
    /// <param name="tokenHandle">The raw (unhashed) refresh token handle.</param>
    /// <param name="clientId">The client identifier that presented the token.</param>
    /// <param name="cancellationToken">A token to cancel the operation.</param>
    /// <returns>
    /// A <see cref="RefreshTokenConsumptionOutcome"/> describing the result. Callers MUST
    /// pattern-match exhaustively over all subtypes. On
    /// <see cref="RefreshTokenConsumptionOutcome.AlreadyConsumed"/>, callers MUST immediately
    /// call <see cref="RevokeFamilyAsync"/> with the returned
    /// <see cref="RefreshTokenConsumptionOutcome.AlreadyConsumed.FamilyId"/>.
    /// </returns>
    /// <remarks>
    /// The consume operation MUST be atomic. Implementations using non-transactional stores
    /// (e.g. Redis) MUST use a compare-and-swap or Lua script to ensure that two concurrent
    /// requests for the same handle produce exactly one <see cref="RefreshTokenConsumptionOutcome.Consumed"/>
    /// and one <see cref="RefreshTokenConsumptionOutcome.AlreadyConsumed"/> outcome.
    /// </remarks>
    /// <exception cref="ZeeKayDaStoreException">
    /// Thrown when the underlying store transport fails.
    /// </exception>
    ValueTask<RefreshTokenConsumptionOutcome> TryConsumeAsync(
        string tokenHandle,
        string clientId,
        CancellationToken cancellationToken);

    /// <summary>
    /// Revokes all tokens belonging to the specified family.
    /// </summary>
    /// <param name="familyId">The family identifier to revoke.</param>
    /// <param name="cancellationToken">A token to cancel the operation.</param>
    /// <remarks>
    /// <para>
    /// This operation MUST be idempotent. Calling <see cref="RevokeFamilyAsync"/> on a
    /// family that has already been revoked MUST NOT throw. Calling with a
    /// <paramref name="familyId"/> that has no associated entries (for example, a defensive
    /// call from a catch block) is a successful idempotent no-op.
    /// </para>
    /// <para>
    /// After revocation, any call to <see cref="TryConsumeAsync"/> for a token in this
    /// family MUST return <see cref="RefreshTokenConsumptionOutcome.Revoked"/>.
    /// </para>
    /// </remarks>
    /// <exception cref="ZeeKayDaStoreException">
    /// Thrown when the underlying store transport fails.
    /// </exception>
    Task RevokeFamilyAsync(string familyId, CancellationToken cancellationToken);
}
