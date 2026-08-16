namespace ZeeKayDa.Auth.Stores;

/// <summary>
/// Provides storage and lifecycle management for refresh tokens.
/// </summary>
/// <remarks>
/// <para>
/// <strong>Framework-sealed.</strong> The framework ships one sealed coordinator,
/// <c>RefreshTokenStore</c>, that implements this interface. It stays <see langword="public"/> so
/// it can be injected and consumed across assemblies, but an internal member means only assemblies
/// named in <c>[InternalsVisibleTo]</c> can implement it. To back a new persistence technology,
/// implement <see cref="IRefreshTokenGrantStore"/> instead.
/// </para>
/// <para>
/// <strong>Restart and multi-instance behaviour.</strong> The default in-memory store loses all
/// refresh tokens on process restart and is single-instance only — running multiple instances
/// with it silently disables reuse detection, since each instance holds an independent view of
/// consumed tokens. Replace the underlying <see cref="IRefreshTokenGrantStore"/> with a shared,
/// atomic, persistent backend for continuous availability or multi-instance deployment.
/// </para>
/// <para>
/// <strong>Multi-tenant limitation.</strong> This interface does not carry a <c>TenantId</c>
/// parameter. A custom <see cref="IRefreshTokenGrantStore"/> handling multiple tenants must
/// namespace grants and validate tenant binding on every lookup, or a token issued in one tenant
/// could be replayed in another.
/// </para>
/// <para>
/// Implementations MUST throw <see cref="ZeeKayDaStoreException"/> (not raw infrastructure
/// exceptions) when an underlying transport fails. Semantic outcomes such as
/// <see cref="RefreshTokenConsumptionResult.NotFound"/> are returned, not thrown.
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
    /// The consume operation MUST be atomic: two concurrent requests for the same handle produce
    /// exactly one <see cref="RefreshTokenConsumptionResult.Consumed"/> and one
    /// <see cref="RefreshTokenConsumptionResult.AlreadyConsumed"/> outcome.
    /// </para>
    /// <para>
    /// On backend unavailability, implementations MUST throw <see cref="ZeeKayDaStoreException"/>;
    /// they MUST NOT return <see cref="RefreshTokenConsumptionResult.NotFound"/> — that would
    /// silently suppress reuse detection, since the caller cannot distinguish a genuine missing
    /// token from a store outage.
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
    // [InternalsVisibleTo] can implement IRefreshTokenStore.
    internal void SealAsFrameworkOwnedProtocol();
}
