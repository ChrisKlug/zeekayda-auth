namespace ZeeKayDa.Auth.Stores;

/// <summary>
/// Provides storage and lifecycle management for refresh tokens.
/// </summary>
/// <remarks>
/// <para>
/// <strong>Framework-sealed (ADR 0014 §4, mirroring ADR 0013 §1).</strong> This interface is the
/// protocol surface the token endpoint depends on, but it is no longer a third-party extension
/// point: the framework ships one sealed coordinator, <c>RefreshTokenStore</c>, that implements
/// it. The interface stays <see langword="public"/> so it can be injected and consumed across
/// assemblies, but an internal member (see below) means only assemblies named in
/// <c>[InternalsVisibleTo]</c> can implement it — a third-party <c>class MyStore :
/// IRefreshTokenStore</c> fails to compile. To back a new persistence technology, implement
/// <see cref="IRefreshTokenGrantStore"/> instead.
/// </para>
/// <para>
/// <strong>Restart behaviour.</strong>
/// The default in-memory store loses all refresh tokens on process restart. For a
/// single-instance deployment where occasional deployment-triggered re-authentication is
/// acceptable, this is fine. For continuous availability across restarts or rolling
/// deployments, replace the underlying <see cref="IRefreshTokenGrantStore"/> with an
/// implementation backed by a persistent store (e.g. a relational database or Cosmos).
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
/// isolation is the responsibility of the custom grant store implementation. A naive
/// multi-tenant store that does not namespace grants or check tenant binding creates a
/// confused-deputy risk — a token issued in one tenant could be replayed in another.
/// Isolation requires a custom <see cref="IRefreshTokenGrantStore"/> that encodes tenant
/// context in its storage and validates tenant binding on every lookup.
/// </para>
/// <para>
/// Implementations MUST throw <see cref="ZeeKayDaStoreException"/> (not raw infrastructure
/// exceptions) when an underlying transport (cache, database, network) fails. Semantic
/// outcomes such as <see cref="RefreshTokenConsumptionResult.NotFound"/> or
/// <see cref="RefreshTokenConsumptionResult.AlreadyConsumed"/> are returned, not thrown.
/// </para>
/// </remarks>
public interface IRefreshTokenStore
{
    /// <summary>
    /// Stores a new refresh token entry.
    /// </summary>
    /// <param name="tokenHandle">The raw (unhashed) refresh token handle. The implementation is
    /// expected to hash this before using it as a storage key.</param>
    /// <param name="entry">The refresh token metadata to persist. The token handle itself is
    /// expected to be stored as a hashed key by the implementation — it is not a property on
    /// <see cref="RefreshTokenEntry"/>.</param>
    /// <param name="cancellationToken">A token to cancel the operation.</param>
    /// <exception cref="ZeeKayDaStoreException">
    /// Thrown when the underlying store transport fails.
    /// </exception>
    /// <returns>A <see cref="Task"/> that completes when the operation has finished.</returns>
    Task StoreAsync(string tokenHandle, RefreshTokenEntry entry, CancellationToken cancellationToken);

    /// <summary>
    /// Looks up a refresh token entry by its raw handle without consuming it.
    /// </summary>
    /// <param name="tokenHandle">The raw (unhashed) refresh token handle.</param>
    /// <param name="cancellationToken">A token to cancel the operation.</param>
    /// <returns>
    /// The <see cref="RefreshTokenEntry"/> if a matching token exists, has not been consumed,
    /// has not expired, and its family has not been revoked; otherwise <see langword="null"/>.
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
    /// A <see cref="RefreshTokenConsumptionResult"/> describing the result. Callers MUST
    /// pattern-match exhaustively over all subtypes. On
    /// <see cref="RefreshTokenConsumptionResult.AlreadyConsumed"/>, callers MUST immediately
    /// call <see cref="RevokeFamilyAsync"/> with the returned
    /// <see cref="RefreshTokenConsumptionResult.AlreadyConsumed.FamilyId"/>.
    /// </returns>
    /// <remarks>
    /// <para>
    /// The consume operation MUST be atomic. This is guaranteed by the sealed coordinator's use
    /// of the single atomic invariant on <see cref="IRefreshTokenGrantStore.TryMarkConsumedAsync"/>
    /// (ADR 0014 §3/§4): two concurrent requests for the same handle produce exactly one
    /// <see cref="RefreshTokenConsumptionResult.Consumed"/> and one
    /// <see cref="RefreshTokenConsumptionResult.AlreadyConsumed"/> outcome.
    /// </para>
    /// <para>
    /// On backend unavailability, implementations MUST throw <see cref="ZeeKayDaStoreException"/>;
    /// they MUST NOT return <see cref="RefreshTokenConsumptionResult.NotFound"/>. Returning
    /// <c>NotFound</c> on a transport failure silently suppresses reuse detection — the caller
    /// cannot distinguish a genuine missing token from a store outage, so the reuse signal
    /// would be swallowed rather than surfaced.
    /// </para>
    /// </remarks>
    /// <exception cref="ZeeKayDaStoreException">
    /// Thrown when the underlying store transport fails.
    /// </exception>
    ValueTask<RefreshTokenConsumptionResult> TryConsumeAsync(
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
    /// family MUST return <see cref="RefreshTokenConsumptionResult.Revoked"/>.
    /// </para>
    /// </remarks>
    /// <exception cref="ZeeKayDaStoreException">
    /// Thrown when the underlying store transport fails.
    /// </exception>
    /// <returns>A <see cref="Task"/> that completes when the operation has finished.</returns>
    Task RevokeFamilyAsync(string familyId, CancellationToken cancellationToken);

    // Reserved: satisfying this member requires internal access, so only assemblies named in
    // [InternalsVisibleTo] can implement IRefreshTokenStore (ADR 0014 §4, ADR 0013 §1).
    internal void SealAsFrameworkOwnedProtocol();
}
