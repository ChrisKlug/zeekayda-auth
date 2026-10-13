namespace ZeeKayDa.Auth.Tokens;

/// <summary>
/// A source entry that cannot be used, with the first problem found. It is neither published nor
/// ever signs.
/// </summary>
/// <param name="Id">The source's own identifier for the entry.</param>
/// <param name="Failure">The first problem found.</param>
/// <param name="Dates">
/// The dates the source listed the key with, when it listed one whose own dates or material were
/// unusable; <see langword="null"/> when the source reported the entry as a failure, with no dates
/// to place it by.
/// </param>
internal sealed record DroppedKey(
    SourceKeyId Id, ZeeKayDaConfigurationFailure Failure, (DateTimeOffset NotBefore, DateTimeOffset ExpiresAt)? Dates);
