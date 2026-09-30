using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.Extensions.Options;

using static ZeeKayDa.Auth.Stores.StoreGuard;

namespace ZeeKayDa.Auth.Stores;

/// <summary>
/// The framework's authorization-code store: the protocol over an <see cref="IAuthorizationCodeBackingStore"/>.
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
/// Key layout: entries are keyed <c>zkd:code:e:{hex(sha256(handle))}</c>,
/// tombstones <c>zkd:code:t:{hex(sha256(handle))}</c>, and the one-outcome-per-interaction claim
/// <c>zkd:code:i:{hex(sha256(interactionId))}</c>. Raw handles and identifiers are never
/// persisted as keys or embedded in stored values.
/// </para>
/// </remarks>
internal sealed class AuthorizationCodeStore(
    IAuthorizationCodeBackingStore backingStore,
    IDataProtectionProvider dataProtectionProvider,
    IOptions<AuthorizationServerOptions> serverOptions,
    TimeProvider timeProvider)
{
    private static readonly string DataProtectionPurpose = "ZeeKayDa.Auth:AuthorizationCodeStore";

    // The claim carries no information — its presence is the fact — so a single byte is stored
    // rather than an empty value some backends refuse.
    private static readonly ReadOnlyMemory<byte> ReservationMarker = new byte[] { 1 };

    private readonly IDataProtector _protector = dataProtectionProvider.CreateProtector(DataProtectionPurpose);
    private readonly TimeSpan _clockSkewTolerance = serverOptions.Value.ClockSkewTolerance;

    /// <summary>Stores a newly minted code's entry under the hash of the code.</summary>
    /// <exception cref="ZeeKayDaStoreException">Thrown when the backing store fails, or the key already exists.</exception>
    public async Task StoreAsync(string code, AuthorizationCodeEntry entry, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(code);
        ArgumentNullException.ThrowIfNull(entry);
        cancellationToken.ThrowIfCancellationRequested();

        var key = BuildEntryKey(code);
        var expiresAt = entry.ExpiresAt + _clockSkewTolerance;
        var protectedBytes = ProtectEntry(entry);

        var inserted = await Guarded(
            () => backingStore.TryInsertAsync(key, protectedBytes, expiresAt, cancellationToken),
            "store the authorization code entry").ConfigureAwait(false);

        if (!inserted)
            throw new ZeeKayDaStoreException(
                "The authorization code handle collided with an existing store entry.");
    }

    /// <summary>
    /// Claims an interaction's one terminal outcome (a code or a denial) through the same atomic
    /// insert that makes a code single-use; <see langword="false"/> when another response holds it.
    /// </summary>
    public async ValueTask<bool> TryClaimInteractionAsync(
        string interactionId,
        DateTimeOffset interactionExpiresAt,
        CancellationToken cancellationToken)
    {
        ArgumentException.ThrowIfNullOrEmpty(interactionId);
        cancellationToken.ThrowIfCancellationRequested();

        return await Guarded(
            () => backingStore.TryInsertAsync(
                BuildInteractionKey(interactionId),
                ReservationMarker,
                interactionExpiresAt + _clockSkewTolerance,
                cancellationToken),
            "claim the interaction's terminal outcome").ConfigureAwait(false);
    }

    /// <summary>
    /// Redeems a code exactly once: a client mismatch leaves it intact, and a replay reports the
    /// family id the first redemption recorded, so the caller can revoke that family.
    /// </summary>
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
            () => backingStore.GetAsync(entryKey, cancellationToken),
            "read the authorization code entry").ConfigureAwait(false);

        if (entryBytes is null)
            return await ResolveViaTombstoneAsync(tombstoneKey, cancellationToken).ConfigureAwait(false);

        AuthorizationCodeEntry entry;
        try
        {
            entry = UnprotectEntry(entryBytes.Value);
        }
        catch (Exception ex) when (ex is CryptographicException or JsonException or ArgumentException)
        {
            // The entry is unusable — there is nothing to hand back — so the redeem path returns
            // NotFound. Distinct from the tombstone catch site below. ArgumentException covers a
            // value the entry's own types refuse to construct, such as an incomplete PKCE binding.
            return new AuthorizationCodeRedemptionResult.NotFound();
        }

        var now = timeProvider.GetUtcNow();
        if (now >= entry.ExpiresAt + _clockSkewTolerance)
            return new AuthorizationCodeRedemptionResult.NotFound();

        if (!string.Equals(entry.ClientId, clientId, StringComparison.Ordinal))
            return new AuthorizationCodeRedemptionResult.ClientMismatch();

        var tombstoneExpiresAt = entry.ExpiresAt + _clockSkewTolerance;
        var tombstoneBytes = SerializeTombstone(familyId);

        var wonRace = await Guarded(
            () => backingStore.TryInsertAsync(tombstoneKey, tombstoneBytes, tombstoneExpiresAt, cancellationToken),
            "write the authorization code redemption tombstone").ConfigureAwait(false);

        if (!wonRace)
            return await ResolveViaTombstoneAsync(tombstoneKey, cancellationToken).ConfigureAwait(false);

        await Guarded(
            () => backingStore.RemoveAsync(entryKey, cancellationToken),
            "remove the redeemed authorization code entry").ConfigureAwait(false);

        return new AuthorizationCodeRedemptionResult.Redeemed { Entry = entry };
    }

    private async ValueTask<AuthorizationCodeRedemptionResult> ResolveViaTombstoneAsync(
        StoreKey tombstoneKey, CancellationToken cancellationToken)
    {
        var tombstoneBytes = await Guarded(
            () => backingStore.GetAsync(tombstoneKey, cancellationToken),
            "read the authorization code redemption tombstone").ConfigureAwait(false);

        if (tombstoneBytes is null)
            return new AuthorizationCodeRedemptionResult.NotFound();

        string? familyId;
        try
        {
            familyId = JsonSerializer.Deserialize(
                tombstoneBytes.Value.Span,
                StoreJsonSerializerContext.Default.AuthorizationCodeTombstone)?.FamilyId;
        }
        catch (JsonException ex)
        {
            throw new ZeeKayDaStoreException(
                "Failed to parse the authorization code redemption tombstone.", ex);
        }

        // A JSON null, or a tombstone whose family id is null, is as corrupt as unparseable bytes.
        return familyId is null
            ? throw new ZeeKayDaStoreException("Failed to parse the authorization code redemption tombstone.")
            : new AuthorizationCodeRedemptionResult.AlreadyRedeemed { FamilyId = familyId };
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

    private static byte[] SerializeTombstone(string familyId) =>
        JsonSerializer.SerializeToUtf8Bytes(
            new AuthorizationCodeTombstone { FamilyId = familyId },
            StoreJsonSerializerContext.Default.AuthorizationCodeTombstone);

    private static StoreKey BuildEntryKey(string code) => StoreKey.Hash("code", "e", code);

    private static StoreKey BuildTombstoneKey(string code) => StoreKey.Hash("code", "t", code);

    private static StoreKey BuildInteractionKey(string interactionId) => StoreKey.Hash("code", "i", interactionId);
}
