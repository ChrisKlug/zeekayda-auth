namespace ZeeKayDa.Auth.Stores;

/// <summary>
/// Represents the metadata stored for a single refresh token.
/// </summary>
/// <remarks>
/// <para>
/// The raw token handle is <strong>not</strong> a property on this record. The handle is stored
/// as a hashed cache key, not in the entry value. Storing the handle in the entry would
/// allow a compromised store to be used to forge tokens.
/// </para>
/// <para>
/// <see cref="FamilyId"/> is shared across all rotations in a token chain, enabling
/// whole-family revocation on reuse detection (see ADR 0008 §4).
/// </para>
/// <para>
/// <see cref="PreviousTokenHandleHash"/> is forensic metadata only — it is never used for
/// authorization decisions and MUST NOT be used to validate or look up a prior token.
/// </para>
/// </remarks>
public sealed record RefreshTokenEntry
{
    /// <summary>
    /// Gets the family identifier shared across all rotations of a token chain.
    /// </summary>
    /// <remarks>
    /// Used for whole-family revocation when reuse detection fires. All tokens issued via
    /// rotation from the same original grant share this value.
    /// </remarks>
    public required string FamilyId { get; init; }

    /// <summary>
    /// Gets the <c>Base64Url(SHA-256(previousHandle))</c> for the token that was rotated to
    /// produce this entry, or <see langword="null"/> for the original token in the family.
    /// </summary>
    /// <remarks>
    /// This is forensic metadata only. It MUST NOT be used for authorization decisions or to
    /// look up or validate a prior token.
    /// </remarks>
    public string? PreviousTokenHandleHash { get; init; }

    /// <summary>Gets the client identifier the token is bound to.</summary>
    /// <remarks>The client binding is set at issuance and MUST NOT be changed on rotation.</remarks>
    public required string ClientId { get; init; }

    /// <summary>Gets the authenticated user's subject identifier.</summary>
    public required string Sub { get; init; }

    /// <summary>
    /// Gets the list of scope values granted to this token.
    /// </summary>
    /// <remarks>
    /// Rotation MUST NOT widen the scope beyond what is recorded here.
    /// </remarks>
    public required IReadOnlyList<string> Scope { get; init; }

    /// <summary>Gets the SSO session identifier that produced this token.</summary>
    public required string SsoSessionId { get; init; }

    /// <summary>Gets the UTC timestamp at which this token was issued.</summary>
    public required DateTimeOffset IssuedAt { get; init; }

    /// <summary>Gets the UTC timestamp at which this token expires.</summary>
    public required DateTimeOffset ExpiresAt { get; init; }

    /// <summary>
    /// Gets the absolute wall-clock ceiling shared verbatim by every token in this family.
    /// </summary>
    /// <remarks>
    /// Baked at family birth (the first token of the family) from
    /// <c>AuthorizationServerOptions.TokenEndpoint.AbsoluteFamilyLifetime</c> and propagated
    /// unchanged through every rotation, so the whole chain shares one absolute cap (ADR 0014
    /// §5). Each token's own <see cref="ExpiresAt"/> is clamped to
    /// <c>min(now + RefreshTokenLifetime, FamilyAbsoluteExpiry)</c>.
    /// </remarks>
    public required DateTimeOffset FamilyAbsoluteExpiry { get; init; }
}
