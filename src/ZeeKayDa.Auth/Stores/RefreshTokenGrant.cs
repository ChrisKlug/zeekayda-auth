namespace ZeeKayDa.Auth.Stores;

/// <summary>
/// One persisted refresh-token grant row, as seen by a persistence backend. The framework
/// constructs and consumes these; a backend only stores, retrieves, and runs equality queries over
/// them. The columns above <see cref="ProtectedPayload"/> are non-secret and queryable; the payload
/// is opaque Data-Protection ciphertext a backend MUST store verbatim and never interpret.
/// </summary>
/// <remarks>
/// See ADR 0014 §2 for the reasoning behind each column's cleartext-vs-encrypted treatment,
/// including why <see cref="Subject"/> is deliberately cleartext (not a <see cref="StoreKey"/>)
/// and why <see cref="FamilyId"/> stays a plain <see cref="string"/> rather than an opaque hash.
/// </remarks>
public sealed record RefreshTokenGrant
{
    /// <summary>Primary key: the framework's SHA-256 hash of the raw handle. Never the raw handle.</summary>
    public required StoreKey HandleHash { get; init; }

    /// <summary>Queryable. Cleartext, non-secret random GUID shared across a rotation chain. Index this.</summary>
    public required string FamilyId { get; init; }

    /// <summary>
    /// Queryable. Cleartext subject identifier (PII, not a bearer credential). NOT a
    /// <see cref="StoreKey"/>: it is honest cleartext, not opaque-already-hashed. Protected by
    /// DB access control + encryption at rest, the Duende/OpenIddict posture (see ADR 0014
    /// Security Considerations). Index this.
    /// </summary>
    public required string Subject { get; init; }

    /// <summary>Queryable. Cleartext client_id (public, not secret) the grant is bound to.</summary>
    public required string ClientId { get; init; }

    /// <summary>Queryable, non-secret. Absolute wall-clock the whole family expires at; drives cleanup.</summary>
    public required DateTimeOffset FamilyAbsoluteExpiry { get; init; }

    /// <summary>Queryable, non-secret. This token's logical expiry (coordinator applies accept-grace skew).</summary>
    public required DateTimeOffset ExpiresAt { get; init; }

    /// <summary>Queryable, non-secret. Lifecycle state. The single-use pivot is a CAS on this column.</summary>
    public required RefreshGrantStatus Status { get; init; }

    /// <summary>
    /// Opaque Data-Protection ciphertext of the serialized <see cref="RefreshTokenEntry"/>.
    /// Store verbatim. A backend can never read the sub/scope/session claims inside it.
    /// </summary>
    public required ReadOnlyMemory<byte> ProtectedPayload { get; init; }
}

/// <summary>Lifecycle state of a persisted refresh-token grant.</summary>
public enum RefreshGrantStatus
{
    /// <summary>Live and consumable.</summary>
    Active = 0,

    /// <summary>Consumed exactly once (its rotated successor was issued). Presenting it again is reuse.</summary>
    Consumed = 1,

    /// <summary>Its family was revoked. A still-live token in the family reads as this.</summary>
    Revoked = 2,
}
