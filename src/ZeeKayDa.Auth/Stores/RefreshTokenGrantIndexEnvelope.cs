namespace ZeeKayDa.Auth.Stores;

/// <summary>
/// A secondary-index entry maintained by <see cref="DistributedCacheRefreshTokenGrantStore"/> to
/// make family/subject revocation possible over a backend that has no native <c>WHERE</c>.
/// </summary>
/// <remarks>
/// <see cref="ExpiresAt"/> tracks the furthest-out <see cref="RefreshTokenGrant.FamilyAbsoluteExpiry"/>
/// seen across every handle folded into <see cref="HandleHashes"/>, so the index entry's cache TTL
/// never expires before the last grant it references could still need revoking.
/// </remarks>
internal sealed record RefreshTokenGrantIndexEnvelope(IReadOnlyList<string> HandleHashes, DateTimeOffset ExpiresAt);
