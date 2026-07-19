using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.Extensions.Options;

using static ZeeKayDa.Auth.Stores.StoreGuard;

namespace ZeeKayDa.Auth.Stores;

/// <summary>
/// The framework's sealed <see cref="IAuthorizationCodeStore"/> coordinator (ADR 0013 §1).
/// </summary>
/// <remarks>
/// <para>
/// Owns everything protocol-critical: handle hashing into <see cref="StoreKey"/>, Data
/// Protection encryption, the check-and-consume state machine and its atomicity, fail-closed
/// I/O (<see cref="Guarded{T}"/>), logical expiry / clock skew, and outcome selection. Persists
/// opaque bytes through an injected <see cref="IAuthorizationCodeBackingStore"/>, which has no
/// knowledge of any of the above.
/// </para>
/// <para>
/// Key layout (ADR 0013 §9): entries are keyed <c>zkd:code:e:{hex(sha256(handle))}</c>,
/// tombstones <c>zkd:code:t:{hex(sha256(handle))}</c>. Raw handles are never persisted as keys
/// or embedded in stored values.
/// </para>
/// </remarks>
internal sealed class AuthorizationCodeStore : IAuthorizationCodeStore
{
    private static readonly string DataProtectionPurpose = "ZeeKayDa.Auth:AuthorizationCodeStore";

    private readonly IAuthorizationCodeBackingStore _backingStore;
    private readonly IDataProtector _protector;
    private readonly TimeProvider _timeProvider;
    private readonly TimeSpan _clockSkewTolerance;

    /// <summary>Initialises a new <see cref="AuthorizationCodeStore"/>.</summary>
    /// <param name="backingStore">The opaque persistence primitive.</param>
    /// <param name="dataProtectionProvider">Provider used to create the entry/tombstone protector.</param>
    /// <param name="serverOptions">Server options providing <see cref="AuthorizationServerOptions.ClockSkewTolerance"/>.</param>
    /// <param name="timeProvider">Time provider used for all UTC timestamp reads.</param>
    public AuthorizationCodeStore(
        IAuthorizationCodeBackingStore backingStore,
        IDataProtectionProvider dataProtectionProvider,
        IOptions<AuthorizationServerOptions> serverOptions,
        TimeProvider timeProvider)
    {
        ArgumentNullException.ThrowIfNull(backingStore);
        ArgumentNullException.ThrowIfNull(dataProtectionProvider);
        ArgumentNullException.ThrowIfNull(serverOptions);
        ArgumentNullException.ThrowIfNull(timeProvider);

        _backingStore = backingStore;
        _protector = dataProtectionProvider.CreateProtector(DataProtectionPurpose);
        _timeProvider = timeProvider;
        _clockSkewTolerance = serverOptions.Value.ClockSkewTolerance;
    }

    /// <inheritdoc/>
    public async Task StoreAsync(string code, AuthorizationCodeEntry entry, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(code);
        ArgumentNullException.ThrowIfNull(entry);
        cancellationToken.ThrowIfCancellationRequested();

        var key = BuildEntryKey(code);
        var expiresAt = entry.ExpiresAt + _clockSkewTolerance;
        var protectedBytes = ProtectEntry(entry);

        var inserted = await Guarded(
            () => _backingStore.TryInsertAsync(key, protectedBytes, expiresAt, cancellationToken),
            "store the authorization code entry").ConfigureAwait(false);

        if (!inserted)
            throw new ZeeKayDaStoreException(
                "The authorization code handle collided with an existing store entry.");
    }

    /// <inheritdoc/>
    public async ValueTask<AuthorizationCodeRedemptionResult> TryRedeemAsync(
        string code,
        string clientId,
        string familyId,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(code);
        ArgumentNullException.ThrowIfNull(clientId);
        ArgumentNullException.ThrowIfNull(familyId);
        cancellationToken.ThrowIfCancellationRequested();

        var entryKey = BuildEntryKey(code);
        var tombstoneKey = BuildTombstoneKey(code);

        var entryBytes = await Guarded(
            () => _backingStore.GetAsync(entryKey, cancellationToken),
            "read the authorization code entry").ConfigureAwait(false);

        if (entryBytes is null)
            return await ResolveViaTombstoneAsync(tombstoneKey, cancellationToken).ConfigureAwait(false);

        AuthorizationCodeEntry entry;
        try
        {
            entry = UnprotectEntry(entryBytes.Value);
        }
        catch (Exception ex) when (ex is CryptographicException or JsonException)
        {
            // §7: the entry is unusable — there is nothing to hand back — so the redeem path
            // returns NotFound. Distinct from the tombstone catch site below.
            return new AuthorizationCodeRedemptionResult.NotFound();
        }

        var now = _timeProvider.GetUtcNow();
        if (now >= entry.ExpiresAt + _clockSkewTolerance)
            return new AuthorizationCodeRedemptionResult.NotFound();

        if (!string.Equals(entry.ClientId, clientId, StringComparison.Ordinal))
            return new AuthorizationCodeRedemptionResult.ClientMismatch();

        var tombstoneExpiresAt = entry.ExpiresAt + _clockSkewTolerance;
        var envelopeBytes = ProtectTombstone(familyId);

        var wonRace = await Guarded(
            () => _backingStore.TryInsertAsync(tombstoneKey, envelopeBytes, tombstoneExpiresAt, cancellationToken),
            "write the authorization code redemption tombstone").ConfigureAwait(false);

        if (!wonRace)
            return await ResolveViaTombstoneAsync(tombstoneKey, cancellationToken).ConfigureAwait(false);

        await Guarded(
            () => _backingStore.RemoveAsync(entryKey, cancellationToken),
            "remove the redeemed authorization code entry").ConfigureAwait(false);

        return new AuthorizationCodeRedemptionResult.Redeemed { Entry = entry };
    }

    /// <inheritdoc/>
    void IAuthorizationCodeStore.SealAsFrameworkOwnedProtocol() { }

    private async ValueTask<AuthorizationCodeRedemptionResult> ResolveViaTombstoneAsync(
        StoreKey tombstoneKey, CancellationToken cancellationToken)
    {
        var tombstoneBytes = await Guarded(
            () => _backingStore.GetAsync(tombstoneKey, cancellationToken),
            "read the authorization code redemption tombstone").ConfigureAwait(false);

        if (tombstoneBytes is null)
            return new AuthorizationCodeRedemptionResult.NotFound();

        AuthorizationCodeTombstoneEnvelope envelope;
        try
        {
            envelope = JsonSerializer.Deserialize(
                tombstoneBytes.Value.Span,
                StoreJsonSerializerContext.Default.AuthorizationCodeTombstoneEnvelope)!;
        }
        catch (JsonException ex)
        {
            throw new ZeeKayDaStoreException(
                "Failed to parse the authorization code redemption tombstone.", ex);
        }

        // §7: FamilyId is plaintext and recoverable independently of ProtectedSecret. Attempting
        // the unprotect here (and discarding the result either way) pins the two-catch-site
        // asymmetry: a rotated Data Protection key must not degrade this outcome to NotFound.
        try
        {
            _protector.Unprotect(envelope.ProtectedSecret);
        }
        catch (Exception ex) when (ex is CryptographicException or ArgumentNullException)
        {
            // Deliberately ignored — see remarks above.
        }

        return new AuthorizationCodeRedemptionResult.AlreadyRedeemed { FamilyId = envelope.FamilyId };
    }

    private byte[] ProtectEntry(AuthorizationCodeEntry entry)
    {
        try
        {
            var json = JsonSerializer.SerializeToUtf8Bytes(entry, StoreJsonSerializerContext.Default.AuthorizationCodeEntry);
            return _protector.Protect(json);
        }
        catch (Exception ex) when (ex is not ZeeKayDaStoreException)
        {
            throw new ZeeKayDaStoreException("Failed to protect the authorization code entry for storage.", ex);
        }
    }

    private AuthorizationCodeEntry UnprotectEntry(ReadOnlyMemory<byte> protectedBytes)
    {
        var json = _protector.Unprotect(protectedBytes.ToArray());
        return JsonSerializer.Deserialize(json, StoreJsonSerializerContext.Default.AuthorizationCodeEntry)!;
    }

    private byte[] ProtectTombstone(string familyId)
    {
        try
        {
            var protectedSecret = _protector.Protect([]);
            var envelope = new AuthorizationCodeTombstoneEnvelope { FamilyId = familyId, ProtectedSecret = protectedSecret };
            return JsonSerializer.SerializeToUtf8Bytes(envelope, StoreJsonSerializerContext.Default.AuthorizationCodeTombstoneEnvelope);
        }
        catch (Exception ex) when (ex is not ZeeKayDaStoreException)
        {
            throw new ZeeKayDaStoreException("Failed to protect the authorization code redemption tombstone.", ex);
        }
    }

    private static StoreKey BuildEntryKey(string code) => new($"zkd:code:e:{HashHex(code)}");

    private static StoreKey BuildTombstoneKey(string code) => new($"zkd:code:t:{HashHex(code)}");

    private static string HashHex(string handle) => Convert.ToHexStringLower(SHA256.HashData(Encoding.UTF8.GetBytes(handle)));
}
