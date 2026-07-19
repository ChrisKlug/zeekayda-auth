namespace ZeeKayDa.Auth.Stores;

/// <summary>
/// The JSON-serializable projection of <see cref="RefreshTokenGrant"/> used by
/// <see cref="DistributedCacheRefreshTokenGrantStore"/> to persist a grant row as cache bytes.
/// </summary>
/// <remarks>
/// <see cref="RefreshTokenGrant.HandleHash"/> is a <see cref="StoreKey"/>, which has no public
/// constructor and is not itself JSON-serializable; this record carries its
/// <see cref="StoreKey.ToString"/> form instead, and the store converts back via the
/// framework-internal <see cref="StoreKey"/> constructor (accessible within this assembly).
/// </remarks>
internal sealed record RefreshTokenGrantRecord(
    string HandleHash,
    string FamilyId,
    string Subject,
    string ClientId,
    DateTimeOffset FamilyAbsoluteExpiry,
    DateTimeOffset ExpiresAt,
    RefreshGrantStatus Status,
    byte[] ProtectedPayload)
{
    public static RefreshTokenGrantRecord FromGrant(RefreshTokenGrant grant) => new(
        grant.HandleHash.ToString(),
        grant.FamilyId,
        grant.Subject,
        grant.ClientId,
        grant.FamilyAbsoluteExpiry,
        grant.ExpiresAt,
        grant.Status,
        grant.ProtectedPayload.ToArray());

    public RefreshTokenGrant ToGrant() => new()
    {
        HandleHash = new StoreKey(HandleHash),
        FamilyId = FamilyId,
        Subject = Subject,
        ClientId = ClientId,
        FamilyAbsoluteExpiry = FamilyAbsoluteExpiry,
        ExpiresAt = ExpiresAt,
        Status = Status,
        ProtectedPayload = ProtectedPayload,
    };
}
