namespace ZeeKayDa.Auth.Tokens;

/// <summary>
/// One published key's expiry status, as reported by <see cref="SigningKeyExpiryHealthCheck"/>.
/// </summary>
/// <param name="Kid">The key's JWKS/JWS <c>kid</c>.</param>
/// <param name="IsSigningKey"><see langword="true"/> when this is the key that signs.</param>
/// <param name="ExpiresAt">The key's expiry, or <see langword="null"/> when it never expires.</param>
/// <param name="RemainingLifetime">
/// The time until <paramref name="ExpiresAt"/>, negative once expired; <see langword="null"/> when it never expires.
/// </param>
public sealed record SigningKeyExpiryStatus(string Kid, bool IsSigningKey, DateTimeOffset? ExpiresAt, TimeSpan? RemainingLifetime);
