namespace ZeeKayDa.Auth.Stores;

/// <summary>What one refresh token grants; keyed by a hash of the handle and never holding it, so a store breach forges nothing.</summary>
internal sealed record RefreshTokenEntry
{
    /// <summary>The family shared by every rotation of one grant, revoked whole on reuse.</summary>
    public required string FamilyId { get; init; }

    /// <summary>The hash of the handle this one rotated from; forensic only, never used to authorize or look up.</summary>
    public string? PreviousTokenHandleHash { get; init; }

    /// <summary>The client the token is bound to, unchanged by rotation.</summary>
    public required string ClientId { get; init; }

    /// <summary>Gets the authenticated user's subject identifier.</summary>
    public required string Sub { get; init; }

    /// <summary>The granted scopes, which rotation never widens.</summary>
    public required IReadOnlyList<string> Scope { get; init; }

    /// <summary>Gets the SSO session identifier that produced this token.</summary>
    public required string SsoSessionId { get; init; }

    /// <summary>Gets the UTC timestamp at which this token was issued.</summary>
    public required DateTimeOffset IssuedAt { get; init; }

    /// <summary>Gets the UTC timestamp at which this token expires.</summary>
    public required DateTimeOffset ExpiresAt { get; init; }

    /// <summary>The family's absolute expiry, set at birth and kept through every rotation; each <see cref="ExpiresAt"/> is clamped to it.</summary>
    public required DateTimeOffset FamilyAbsoluteExpiry { get; init; }
}
