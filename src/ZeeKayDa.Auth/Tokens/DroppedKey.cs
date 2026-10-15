namespace ZeeKayDa.Auth.Tokens;

/// <summary>
/// A source entry that cannot be used, with the first problem found, and its dates when it had any.
/// </summary>
internal sealed record DroppedKey(
    SourceKeyId Id, ZeeKayDaConfigurationFailure Failure, (DateTimeOffset NotBefore, DateTimeOffset ExpiresAt)? Dates);
