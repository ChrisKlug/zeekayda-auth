using System.Buffers.Text;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.Extensions.Options;

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

    private readonly IRefreshTokenGrantStore _grantStore;
    private readonly IDataProtector _protector;
    private readonly TimeProvider _timeProvider;
    private readonly TimeSpan _refreshTokenLifetime;
    private readonly TimeSpan _clockSkewTolerance;

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
        _refreshTokenLifetime = serverOptions.Value.TokenEndpoint.RefreshTokenLifetime;
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
        var expiresAt = Min(now + _refreshTokenLifetime, entry.FamilyAbsoluteExpiry);

        var grant = new RefreshTokenGrant
        {
            HandleHash = key,
            FamilyId = entry.FamilyId,
            Subject = entry.Sub,
            ClientId = entry.ClientId,
            FamilyAbsoluteExpiry = entry.FamilyAbsoluteExpiry,
            ExpiresAt = expiresAt,
            Status = RefreshGrantStatus.Active,
            ProtectedPayload = ProtectEntry(entry),
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

    private static StoreKey BuildHandleKey(string tokenHandle) => new(HashBase64Url(tokenHandle));

    // H(x) = Base64Url(SHA-256(UTF8(x))) (ADR 0014 §4).
    private static string HashBase64Url(string handle) => Base64Url.EncodeToString(SHA256.HashData(Encoding.UTF8.GetBytes(handle)));

    private static DateTimeOffset Min(DateTimeOffset a, DateTimeOffset b) => a < b ? a : b;
}
