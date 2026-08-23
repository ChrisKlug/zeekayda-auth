namespace ZeeKayDa.Auth.Tokens;

/// <summary>
/// One published key's expiry status, as reported by <see cref="SigningKeyExpiryHealthCheck"/>.
/// </summary>
/// <param name="Kid">The key's JWKS/JWS <c>kid</c>.</param>
/// <param name="IsSigningKey">
/// <see langword="true"/> when this is the key that signs. <c>Previous</c>/<c>Next</c> keys are
/// reported but never drive the health verdict.
/// </param>
/// <param name="ExpiresAt">The key's expiry, or <see langword="null"/> when it never expires.</param>
/// <param name="RemainingLifetime">
/// The time remaining until <paramref name="ExpiresAt"/>, or <see langword="null"/> when
/// <paramref name="ExpiresAt"/> is <see langword="null"/>. Negative once the key has expired.
/// </param>
public sealed record SigningKeyExpiryStatus(string Kid, bool IsSigningKey, DateTimeOffset? ExpiresAt, TimeSpan? RemainingLifetime);
