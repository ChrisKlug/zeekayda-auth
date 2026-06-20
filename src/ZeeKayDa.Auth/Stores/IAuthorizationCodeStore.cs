namespace ZeeKayDa.Auth.Stores;

/// <summary>
/// Persists and redeems authorization codes issued by the authorization endpoint.
/// </summary>
/// <remarks>
/// <para>
/// Implementations are responsible for distinguishing four states when a code is presented
/// at the token endpoint:
/// </para>
/// <list type="number">
/// <item><description>
///   Present, unredeemed, and bound to the presenting client — code is valid and may be
///   exchanged for tokens.
/// </description></item>
/// <item><description>
///   Present and unredeemed, but bound to a different client — the presenting client is not
///   the intended recipient; the code MUST NOT be consumed.
/// </description></item>
/// <item><description>
///   Already redeemed (tombstone exists) — a replay attack is likely in progress; the
///   associated refresh token family MUST be revoked.
/// </description></item>
/// <item><description>
///   Never issued or already expired and purged — code is entirely unknown to the store.
/// </description></item>
/// </list>
/// <para>
/// <strong>Multi-tenancy:</strong> The framework is not tenant-aware. Custom multi-tenant
/// stores must namespace authorization code keys by tenant (e.g. prefix the store key with a
/// tenant identifier) and validate tenant binding at consume time. Failure to do so can allow
/// cross-tenant code redemption.
/// </para>
/// <para>
/// <strong>Failure semantics:</strong> Implementations MUST fail closed. Any I/O failure
/// (cache unavailable, database timeout, network error) MUST surface as
/// <see cref="ZeeKayDaStoreException"/> and MUST NOT be swallowed or converted to a
/// <see cref="AuthorizationCodeRedemptionOutcome.NotFound"/> outcome.
/// </para>
/// </remarks>
public interface IAuthorizationCodeStore
{
    /// <summary>
    /// Stores the authorization code entry so that it can be retrieved during token endpoint
    /// redemption.
    /// </summary>
    /// <param name="entry">
    /// The entry to persist. The store is responsible for deriving its own storage key from the
    /// code handle that will be presented to <see cref="TryRedeemAsync"/>; <paramref name="entry"/>
    /// itself does not contain the cleartext code handle.
    /// </param>
    /// <param name="cancellationToken">A token to cancel the operation.</param>
    /// <returns>A task that completes when the entry has been durably stored.</returns>
    /// <remarks>
    /// Called by the authorization endpoint immediately after code generation, before the
    /// code is returned to the client. Implementations MUST fail closed: any I/O failure MUST
    /// surface as <see cref="ZeeKayDaStoreException"/>. Silently swallowing errors here would
    /// allow a code to be delivered to the client that can never be redeemed, which is a
    /// confusing but non-exploitable failure mode — however, silently returning success while
    /// the entry was not actually stored would allow token issuance without a stored record,
    /// which undermines replay detection.
    /// </remarks>
    /// <exception cref="ZeeKayDaStoreException">
    /// Thrown when the underlying store cannot complete the write due to an infrastructure
    /// failure (network, cache, database).
    /// </exception>
    Task StoreAsync(AuthorizationCodeEntry entry, CancellationToken cancellationToken);

    /// <summary>
    /// Attempts to atomically redeem the authorization code identified by
    /// <paramref name="code"/> on behalf of <paramref name="clientId"/>.
    /// </summary>
    /// <param name="code">
    /// The raw authorization code handle as received from the token endpoint request. The store
    /// is responsible for deriving the store key (e.g. SHA-256 of this value) before lookup.
    /// </param>
    /// <param name="clientId">
    /// The client identifier presented at the token endpoint. The store MUST verify that this
    /// value matches the <see cref="AuthorizationCodeEntry.ClientId"/> bound at issuance time.
    /// </param>
    /// <param name="familyId">
    /// A freshly-minted refresh token family identifier chosen by the token endpoint
    /// <em>before</em> calling this method (minimum 128 bits of CSPRNG entropy). This value
    /// MUST be written atomically into the redemption tombstone so that any later replay
    /// producing <see cref="AuthorizationCodeRedemptionOutcome.AlreadyRedeemed"/> is guaranteed
    /// to carry the correct <see cref="AuthorizationCodeRedemptionOutcome.AlreadyRedeemed.FamilyId"/>
    /// for revocation. The token endpoint will use this same identifier when issuing the
    /// refresh token.
    /// </param>
    /// <param name="cancellationToken">A token to cancel the operation.</param>
    /// <returns>
    /// <para>One of four outcomes:</para>
    /// <list type="bullet">
    /// <item><description>
    ///   <see cref="AuthorizationCodeRedemptionOutcome.Redeemed"/> — code was valid, bound to
    ///   the presenting client, and has been atomically consumed. Proceed to issue tokens.
    /// </description></item>
    /// <item><description>
    ///   <see cref="AuthorizationCodeRedemptionOutcome.ClientMismatch"/> — code exists and is
    ///   unredeemed but is bound to a different client. Store has NOT consumed the code.
    ///   Return <c>error=invalid_grant</c>.
    /// </description></item>
    /// <item><description>
    ///   <see cref="AuthorizationCodeRedemptionOutcome.AlreadyRedeemed"/> — code has already
    ///   been redeemed. Revoke the refresh token family in
    ///   <see cref="AuthorizationCodeRedemptionOutcome.AlreadyRedeemed.FamilyId"/> and return
    ///   <c>error=invalid_grant</c> (RFC 9700 §2.1.1).
    /// </description></item>
    /// <item><description>
    ///   <see cref="AuthorizationCodeRedemptionOutcome.NotFound"/> — code is unknown to the
    ///   store. Return <c>error=invalid_grant</c>.
    /// </description></item>
    /// </list>
    /// </returns>
    /// <remarks>
    /// <para>
    /// Implementations MUST perform the check-and-consume atomically (e.g. using a Redis
    /// compare-and-swap or a database transaction with appropriate isolation). Non-atomic
    /// backends are vulnerable to a time-of-check/time-of-use (TOCTOU) race where concurrent
    /// requests can both read the entry as unredeemed before either marks it as consumed.
    /// If true atomicity is not achievable, document the limitation clearly and consider
    /// accepting the risk only in single-instance deployments.
    /// </para>
    /// <para>
    /// Implementations MUST fail closed: any I/O failure MUST surface as
    /// <see cref="ZeeKayDaStoreException"/> and MUST NOT be converted to
    /// <see cref="AuthorizationCodeRedemptionOutcome.NotFound"/>.
    /// </para>
    /// </remarks>
    /// <exception cref="ZeeKayDaStoreException">
    /// Thrown when the underlying store cannot complete the operation due to an infrastructure
    /// failure (network, cache, database).
    /// </exception>
    ValueTask<AuthorizationCodeRedemptionOutcome> TryRedeemAsync(
        string code,
        string clientId,
        string familyId,
        CancellationToken cancellationToken);
}
