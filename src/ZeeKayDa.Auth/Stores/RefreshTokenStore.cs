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
/// The framework's refresh-token store: the protocol over an <see cref="IRefreshTokenBackingStore"/>.
/// </summary>
/// <remarks>
/// Owns everything protocol-critical: handle hashing into <see cref="StoreKey"/>, Data
/// Protection encryption, the single-use compare-and-set pivot and its atomicity, fail-closed
/// I/O, logical expiry/clock skew, and outcome selection — persisting cleartext queryable columns
/// plus one encrypted payload through an injected <see cref="IRefreshTokenBackingStore"/>, which has
/// no knowledge of any of the above. Reuse, revocation, expiry, and client mismatch are all
/// decided from cleartext columns before anything is decrypted; the only <c>Unprotect</c> call is
/// on the happy path, after the atomic consume-pivot has already committed, and its sole failure
/// mode degrades to <see cref="RefreshTokenConsumptionResult.NotFound"/> — fail-closed, since the
/// token is already dead and no successor is issued.
/// </remarks>
internal sealed class RefreshTokenStore(
    IRefreshTokenBackingStore grantStore,
    IDataProtectionProvider dataProtectionProvider,
    IOptions<AuthorizationServerOptions> serverOptions,
    TimeProvider timeProvider)
{
    private static readonly string DataProtectionPurpose = "ZeeKayDa.Auth:RefreshTokenStore";

    private readonly IDataProtector _protector = dataProtectionProvider.CreateProtector(DataProtectionPurpose);
    private readonly TokenEndpointOptions _tokenEndpointOptions = serverOptions.Value.TokenEndpoint;
    private readonly TimeSpan _refreshTokenLifetime = serverOptions.Value.TokenEndpoint.RefreshTokenLifetime;
    private readonly TimeSpan _clockSkewTolerance = serverOptions.Value.ClockSkewTolerance;

    /// <summary>Stores a refresh token's grant under the hash of its handle.</summary>
    /// <exception cref="ZeeKayDaStoreException">Thrown when the backing store fails.</exception>
    public async Task StoreAsync(string tokenHandle, RefreshTokenEntry entry, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(tokenHandle);
        ArgumentNullException.ThrowIfNull(entry);
        cancellationToken.ThrowIfCancellationRequested();

        var key = BuildHandleKey(tokenHandle);
        var now = timeProvider.GetUtcNow();

        // The whole family shares one absolute ceiling, applied here to the encrypted entry too, so
        // a caller reading Consumed.Entry.ExpiresAt never sees a value larger than what the
        // cleartext column actually enforces. RefreshTokenLifetime has no upper bound, so the
        // addition saturates rather than throwing out of token issuance.
        var expiresAt = Min(TokenLifetimes.ExpiresAt(now, _refreshTokenLifetime), entry.FamilyAbsoluteExpiry);
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
            () => grantStore.InsertAsync(grant, cancellationToken),
            "store the refresh token grant").ConfigureAwait(false);
    }

    /// <summary>The live entry for a handle, or <see langword="null"/> when it is unknown, used, revoked, expired or unreadable.</summary>
    public async ValueTask<RefreshTokenEntry?> FindAsync(string tokenHandle, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(tokenHandle);
        cancellationToken.ThrowIfCancellationRequested();

        var key = BuildHandleKey(tokenHandle);

        var grant = await Guarded(
            () => grantStore.FindByHandleAsync(key, cancellationToken),
            "read the refresh token grant").ConfigureAwait(false);

        if (grant is null || grant.Status != RefreshGrantStatus.Active)
            return null;

        // A successor inserted after RevokeFamilyAsync still reads Active on its own row, so
        // introspection must not report it as a live grant either.
        if (await Guarded(
                () => grantStore.IsFamilyRevokedAsync(grant.FamilyId, cancellationToken),
                "check whether the refresh token family is revoked").ConfigureAwait(false))
            return null;

        if (timeProvider.GetUtcNow() >= TokenLifetimes.ExpiresAt(grant.ExpiresAt, _clockSkewTolerance))
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

    /// <summary>
    /// Consumes a handle exactly once. A reused or revoked handle reports its family id so the
    /// caller can revoke the family; a client mismatch leaves the grant intact.
    /// </summary>
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
            () => grantStore.FindByHandleAsync(key, cancellationToken),
            "read the refresh token grant").ConfigureAwait(false);

        if (grant is null)
            return new RefreshTokenConsumptionResult.NotFound();

        // Cleartext decisions, in order, before anything is decrypted.
        if (grant.Status == RefreshGrantStatus.Revoked)
            return new RefreshTokenConsumptionResult.Revoked { FamilyId = grant.FamilyId };

        if (grant.Status == RefreshGrantStatus.Consumed)
            return new RefreshTokenConsumptionResult.AlreadyConsumed { FamilyId = grant.FamilyId };

        // The family may have been revoked after this grant was inserted, so its own
        // still-Active status is not the last word — re-check the family.
        if (await Guarded(
                () => grantStore.IsFamilyRevokedAsync(grant.FamilyId, cancellationToken),
                "check whether the refresh token family is revoked").ConfigureAwait(false))
            return new RefreshTokenConsumptionResult.Revoked { FamilyId = grant.FamilyId };

        if (timeProvider.GetUtcNow() >= TokenLifetimes.ExpiresAt(grant.ExpiresAt, _clockSkewTolerance))
            return new RefreshTokenConsumptionResult.NotFound();

        if (!string.Equals(grant.ClientId, clientId, StringComparison.Ordinal))
            return new RefreshTokenConsumptionResult.ClientMismatch();

        // The ONE correctness-critical atomic op in the whole design.
        var won = await Guarded(
            () => grantStore.TryMarkConsumedAsync(key, cancellationToken),
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
            // The single catch site. The token is already dead (marked Consumed above), so no
            // successor is issued and no reuse is enabled — fail-closed.
            _ = ex;
            return new RefreshTokenConsumptionResult.NotFound();
        }
    }

    /// <summary>Revokes every grant in a family, including one issued after this call returns. Idempotent.</summary>
    public async Task RevokeFamilyAsync(string familyId, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(familyId);
        cancellationToken.ThrowIfCancellationRequested();

        // Clocked at revoke time, so a first row born a moment later lives that moment longer than an
        // unpadded record would be kept. The skew tolerance covers it, saturating like every other expiry.
        var rememberUntil = TokenLifetimes.ExpiresAt(
            _tokenEndpointOptions.ComputeFamilyAbsoluteExpiry(timeProvider.GetUtcNow()),
            _clockSkewTolerance);

        await Guarded(
            () => grantStore.RevokeFamilyAsync(familyId, rememberUntil, cancellationToken),
            "revoke the refresh token family").ConfigureAwait(false);
    }

    private async ValueTask<RefreshTokenConsumptionResult> ResolveLostRaceAsync(
        StoreKey key, string familyId, CancellationToken cancellationToken)
    {
        // Lost the race: re-read (cleartext only) to report the correct terminal state.
        var reread = await Guarded(
            () => grantStore.FindByHandleAsync(key, cancellationToken),
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

    private static StoreKey BuildHandleKey(string tokenHandle) => StoreKey.Hash("refresh", "h", tokenHandle);

    private static DateTimeOffset Min(DateTimeOffset a, DateTimeOffset b) => a < b ? a : b;
}
