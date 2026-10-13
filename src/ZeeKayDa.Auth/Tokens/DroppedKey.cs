namespace ZeeKayDa.Auth.Tokens;

/// <summary>
/// A source entry that cannot be used, with the first problem found. It is neither published nor
/// ever signs.
/// </summary>
/// <param name="Id">The source's own identifier for the entry.</param>
/// <param name="Key">
/// The key as listed, when the source listed it and its own dates or material were unusable;
/// <see langword="null"/> when the source reported the entry as a failure, with no dates to place it by.
/// </param>
/// <param name="Failure">The first problem found.</param>
internal sealed record DroppedKey(SourceKeyId Id, SourceKey? Key, ZeeKayDaConfigurationFailure Failure);
