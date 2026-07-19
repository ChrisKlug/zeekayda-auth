using System.Buffers.Text;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.Extensions.Options;
using ZeeKayDa.Auth.Tokens;

using static ZeeKayDa.Auth.Stores.StoreGuard;

namespace ZeeKayDa.Auth.Stores;

/// <summary>
/// The framework's sealed <see cref="IRefreshTokenStore"/> coordinator (ADR 0014 §4).
/// </summary>
/// <remarks>
/// <para>
/// Owns everything protocol-critical: handle hashing into <see cref="StoreKey"/>, Data
/// Protection encryption, the single-use compare-and-set pivot and its atomicity, fail-closed
/// I/O (<see cref="StoreGuard.Guarded{T}(Func{ValueTask{T}}, string)"/>), logical expiry / clock
/// skew, and outcome selection. Persists cleartext queryable columns plus one encrypted payload
/// through an injected <see cref="IRefreshTokenGrantStore"/>, which has no knowledge of any of
/// the above.
/// </para>
/// <para>
/// <strong>One <c>Unprotect</c> catch site (ADR 0014 §7).</strong> Unlike the authorization-code
/// coordinator, reuse (<c>Consumed</c> status), revocation, expiry, and client mismatch are all
/// decided from cleartext columns on <see cref="RefreshTokenGrant"/> before anything is
/// decrypted. The only <c>Unprotect</c> call is on the happy path, after the atomic
/// consume-pivot has already committed, and its sole failure mode degrades to
/// <see cref="RefreshTokenConsumptionResult.NotFound"/> — fail-closed, because the token is
/// already dead and no successor is issued.
/// </para>
/// </remarks>
internal sealed class RefreshTokenStore : IRefreshTokenStore
{
    private static readonly string DataProtectionPurpose = "ZeeKayDa.Auth:RefreshTokenStore";

    /// <summary>
    /// Reserved sentinel value for a revocation-sentinel row's <see cref="RefreshTokenGrant.Subject"/>
    /// and <see cref="RefreshTokenGrant.ClientId"/> (ADR 0014 §12). Never a real subject or
    /// client_id — a real grant's own values can never equal this constant.
    /// </summary>
    private const string RevocationSentinelReservedValue = "__zeekayda-revocation-sentinel__";

    private readonly IRefreshTokenGrantStore _grantStore;
    private readonly IDataProtector _protector;
    private readonly TimeProvider _timeProvider;
    private readonly TimeSpan _refreshTokenLifetime;
    private readonly TimeSpan _clockSkewTolerance;
    private readonly TokenEndpointOptions _tokenEndpointOptions;

    /// <summary>Initialises a new <see cref="RefreshTokenStore"/>.</summary>
    /// <param name="grantStore">The queryable persistence extension point.</param>
    /// <param name="dataProtectionProvider">Provider used to create the payload protector.</param>
    /// <param name="serverOptions">
    /// Server options providing <see cref="AuthorizationServerOptions.ClockSkewTolerance"/> and
    /// <c>TokenEndpoint.RefreshTokenLifetime</c>.
    /// </param>
    /// <param name="timeProvider">Time provider used for all UTC timestamp reads.</param>
    public RefreshTokenStore(
        IRefreshTokenGrantStore grantStore,
        IDataProtectionProvider dataProtectionProvider,
        IOptions<AuthorizationServerOptions> serverOptions,
        TimeProvider timeProvider)
    {
        ArgumentNullException.ThrowIfNull(grantStore);
        ArgumentNullException.ThrowIfNull(dataProtectionProvider);
        ArgumentNullException.ThrowIfNull(serverOptions);
        ArgumentNullException.ThrowIfNull(timeProvider);

        _grantStore = grantStore;
        _protector = dataProtectionProvider.CreateProtector(DataProtectionPurpose);
        _timeProvider = timeProvider;
        _tokenEndpointOptions = serverOptions.Value.TokenEndpoint;
        _refreshTokenLifetime = _tokenEndpointOptions.RefreshTokenLifetime;
        _clockSkewTolerance = serverOptions.Value.ClockSkewTolerance;
    }

    /// <inheritdoc/>
    public async Task StoreAsync(string tokenHandle, RefreshTokenEntry entry, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(tokenHandle);
        ArgumentNullException.ThrowIfNull(entry);
        cancellationToken.ThrowIfCancellationRequested();

        var key = BuildHandleKey(tokenHandle);
        var now = _timeProvider.GetUtcNow();

        // §5: clamp — the whole family shares one absolute ceiling; a token never outlives it.
        // Applied to the encrypted entry too, so a caller reading Consumed.Entry.ExpiresAt never
        // sees a value larger than what the cleartext column actually enforces.
        var expiresAt = Min(now + _refreshTokenLifetime, entry.FamilyAbsoluteExpiry);
        var clampedEntry = entry with { ExpiresAt = expiresAt };

        var grant = new RefreshTokenGrant
        {
            HandleHash = key,
            FamilyId = entry.FamilyId,
            Subject = entry.Sub,
            ClientId = entry.ClientId,
            FamilyAbsoluteExpiry = entry.FamilyAbsoluteExpiry,
            ExpiresAt = expiresAt,
            Status = RefreshGrantStatus.Active,
            ProtectedPayload = ProtectEntry(clampedEntry),
        };

        await Guarded(
            () => _grantStore.InsertAsync(grant, cancellationToken),
            "store the refresh token grant").ConfigureAwait(false);
    }

    /// <inheritdoc/>
    public async ValueTask<RefreshTokenEntry?> FindAsync(string tokenHandle, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(tokenHandle);
        cancellationToken.ThrowIfCancellationRequested();

        var key = BuildHandleKey(tokenHandle);

        var grant = await Guarded(
            () => _grantStore.FindByHandleAsync(key, cancellationToken),
            "read the refresh token grant").ConfigureAwait(false);

        if (grant is null || grant.Status != RefreshGrantStatus.Active)
            return null;

        // #386 gate (ADR 0014 §11): a successor inserted after RevokeFamilyAsync still reads
        // Active on its own row, so introspection must not report it as a live grant either.
        if (await Guarded(
                () => _grantStore.IsFamilyRevokedAsync(grant.FamilyId, cancellationToken),
                "check whether the refresh token family is revoked").ConfigureAwait(false))
            return null;

        if (_timeProvider.GetUtcNow() >= grant.ExpiresAt + _clockSkewTolerance)
            return null;

        try
        {
            return UnprotectEntry(grant.ProtectedPayload);
        }
        catch (Exception ex) when (ex is CryptographicException or JsonException)
        {
            _ = ex;
            return null;
        }
    }

    /// <inheritdoc/>
    public async ValueTask<RefreshTokenConsumptionResult> TryConsumeAsync(
        string tokenHandle,
        string clientId,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(tokenHandle);
        ArgumentNullException.ThrowIfNull(clientId);
        cancellationToken.ThrowIfCancellationRequested();

        var key = BuildHandleKey(tokenHandle);

        var grant = await Guarded(
            () => _grantStore.FindByHandleAsync(key, cancellationToken),
            "read the refresh token grant").ConfigureAwait(false);

        if (grant is null)
            return new RefreshTokenConsumptionResult.NotFound();

        // §4: cleartext decisions, in order, before anything is decrypted.
        if (grant.Status == RefreshGrantStatus.Revoked)
            return new RefreshTokenConsumptionResult.Revoked { FamilyId = grant.FamilyId };

        if (grant.Status == RefreshGrantStatus.Consumed)
            return new RefreshTokenConsumptionResult.AlreadyConsumed { FamilyId = grant.FamilyId };

        // #386 gate (ADR 0014 §11): the family may have been revoked after this grant was
        // inserted, so its own still-Active status is not the last word — re-check the family.
        if (await Guarded(
                () => _grantStore.IsFamilyRevokedAsync(grant.FamilyId, cancellationToken),
                "check whether the refresh token family is revoked").ConfigureAwait(false))
            return new RefreshTokenConsumptionResult.Revoked { FamilyId = grant.FamilyId };

        if (_timeProvider.GetUtcNow() >= grant.ExpiresAt + _clockSkewTolerance)
            return new RefreshTokenConsumptionResult.NotFound();

        if (!string.Equals(grant.ClientId, clientId, StringComparison.Ordinal))
            return new RefreshTokenConsumptionResult.ClientMismatch();

        // The ONE correctness-critical atomic op in the whole design.
        var won = await Guarded(
            () => _grantStore.TryMarkConsumedAsync(key, cancellationToken),
            "mark the refresh token grant consumed").ConfigureAwait(false);

        if (!won)
            return await ResolveLostRaceAsync(key, grant.FamilyId, cancellationToken).ConfigureAwait(false);

        // We won the transition; now — and ONLY now — do we touch ciphertext.
        try
        {
            return new RefreshTokenConsumptionResult.Consumed { Entry = UnprotectEntry(grant.ProtectedPayload) };
        }
        catch (Exception ex) when (ex is CryptographicException or JsonException)
        {
            // §7: the single catch site. The token is already dead (marked Consumed above), so
            // no successor is issued and no reuse is enabled — fail-closed.
            _ = ex;
            return new RefreshTokenConsumptionResult.NotFound();
        }
    }

    /// <inheritdoc/>
    public async Task RevokeFamilyAsync(string familyId, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(familyId);
        cancellationToken.ThrowIfCancellationRequested();

        // ADR 0014 §12 (issue #388): unconditionally insert a durable revocation sentinel FIRST.
        // This closes the case where the family has zero rows at revoke time (e.g. an
        // authorization-code replay racing ahead of its own first StoreAsync) — without it, the
        // bulk mark below would match nothing and leave no trace for the §11
        // IsFamilyRevokedAsync gate to find. The sentinel alone is self-sufficient: it arms the
        // gate for the whole family regardless of whether any real row exists yet, and regardless
        // of a crash between this step and the bulk mark below.
        await InsertRevocationSentinelAsync(familyId, cancellationToken).ConfigureAwait(false);

        await Guarded(
            () => _grantStore.RevokeFamilyAsync(familyId, cancellationToken),
            "revoke the refresh token family").ConfigureAwait(false);
    }

    /// <inheritdoc/>
    void IRefreshTokenStore.SealAsFrameworkOwnedProtocol() { }

    private async ValueTask<RefreshTokenConsumptionResult> ResolveLostRaceAsync(
        StoreKey key, string familyId, CancellationToken cancellationToken)
    {
        // Lost the race: re-read (cleartext only) to report the correct terminal state.
        var reread = await Guarded(
            () => _grantStore.FindByHandleAsync(key, cancellationToken),
            "re-read the refresh token grant after a lost consume race").ConfigureAwait(false);

        return reread?.Status == RefreshGrantStatus.Revoked
            ? new RefreshTokenConsumptionResult.Revoked { FamilyId = familyId }
            : new RefreshTokenConsumptionResult.AlreadyConsumed { FamilyId = familyId };
    }

    private ReadOnlyMemory<byte> ProtectEntry(RefreshTokenEntry entry)
    {
        try
        {
            var json = JsonSerializer.SerializeToUtf8Bytes(entry, StoreJsonSerializerContext.Default.RefreshTokenEntry);
            return _protector.Protect(json);
        }
        catch (Exception ex) when (ex is not ZeeKayDaStoreException)
        {
            throw new ZeeKayDaStoreException("Failed to protect the refresh token entry for storage.", ex);
        }
    }

    private RefreshTokenEntry UnprotectEntry(ReadOnlyMemory<byte> protectedPayload)
    {
        var json = _protector.Unprotect(protectedPayload.ToArray());
        return JsonSerializer.Deserialize(json, StoreJsonSerializerContext.Default.RefreshTokenEntry)!;
    }

    /// <summary>
    /// Inserts the ADR 0014 §12 revocation-sentinel row for <paramref name="familyId"/>, treating
    /// a confirmed collision on the sentinel's own deterministic key as an idempotent no-op.
    /// </summary>
    /// <remarks>
    /// <para>
    /// The sentinel's <see cref="RefreshTokenGrant.HandleHash"/> is derived solely from
    /// <paramref name="familyId"/> (never a random handle), so it is the same on every call for
    /// the same family. <see cref="IRefreshTokenGrantStore.InsertAsync"/>'s contract still throws
    /// on any handle collision — that stays correct for the 256-bit random handles every real
    /// grant uses.
    /// </para>
    /// <para>
    /// <see cref="StoreGuard.Guarded{T}(Func{ValueTask{T}}, string)"/> wraps every non-cancellation
    /// backend fault into the same <see cref="ZeeKayDaStoreException"/> type, so a genuine
    /// self-collision with our own prior sentinel and a genuine transport/database fault look
    /// identical at the exception site — the exception type/message must never be used to infer
    /// which one occurred. Instead, an <see cref="IRefreshTokenGrantStore.InsertAsync"/> failure is
    /// only ever treated as benign after a confirming <see cref="IRefreshTokenGrantStore.FindByHandleAsync"/>
    /// read shows the sentinel's exact <see cref="RefreshTokenGrant.HandleHash"/> durably present
    /// with <see cref="RefreshGrantStatus.Revoked"/>. If that read shows the row absent (or present
    /// but not <c>Revoked</c>), the original failure was a genuine fault and is rethrown — this
    /// method never lets <see cref="RevokeFamilyAsync"/> return successfully while the sentinel is
    /// not confirmed durable. If the confirming read itself throws, that propagates unchanged
    /// (fail-closed, per <see cref="IRefreshTokenGrantStore.FindByHandleAsync"/>'s own contract).
    /// </para>
    /// </remarks>
    private async Task InsertRevocationSentinelAsync(string familyId, CancellationToken cancellationToken)
    {
        var familyAbsoluteExpiry = _tokenEndpointOptions.ComputeFamilyAbsoluteExpiry(_timeProvider.GetUtcNow());
        var sentinelKey = BuildRevocationSentinelKey(familyId);

        var sentinel = new RefreshTokenGrant
        {
            HandleHash = sentinelKey,
            FamilyId = familyId,
            Subject = RevocationSentinelReservedValue,
            ClientId = RevocationSentinelReservedValue,
            FamilyAbsoluteExpiry = familyAbsoluteExpiry,
            ExpiresAt = familyAbsoluteExpiry,
            Status = RefreshGrantStatus.Revoked,
            ProtectedPayload = ReadOnlyMemory<byte>.Empty,
        };

        try
        {
            await Guarded(
                () => _grantStore.InsertAsync(sentinel, cancellationToken),
                "insert the refresh token family revocation sentinel").ConfigureAwait(false);
        }
        catch (ZeeKayDaStoreException)
        {
            // Do not infer meaning from the exception type/message — verify the actual persisted
            // state before treating this as the benign self-collision case (see remarks above).
            var existing = await Guarded(
                () => _grantStore.FindByHandleAsync(sentinelKey, cancellationToken),
                "confirm the refresh token family revocation sentinel after an insert failure").ConfigureAwait(false);

            if (existing is null || existing.Status != RefreshGrantStatus.Revoked)
                throw;
        }
    }

    private static StoreKey BuildHandleKey(string tokenHandle) => new(HashBase64Url(tokenHandle));

    // The sentinel key is deterministic in familyId alone, reusing the same H(x) construction
    // (ADR 0014 §12) so repeated RevokeFamilyAsync calls for the same family always target the
    // same row, preserving idempotency without unbounded row growth.
    private static StoreKey BuildRevocationSentinelKey(string familyId) => new(HashBase64Url($"revocation-sentinel:{familyId}"));

    // H(x) = Base64Url(SHA-256(UTF8(x))) (ADR 0014 §4).
    private static string HashBase64Url(string handle) => Base64Url.EncodeToString(SHA256.HashData(Encoding.UTF8.GetBytes(handle)));

    private static DateTimeOffset Min(DateTimeOffset a, DateTimeOffset b) => a < b ? a : b;
}
