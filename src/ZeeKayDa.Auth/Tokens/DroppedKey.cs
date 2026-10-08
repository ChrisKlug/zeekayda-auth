namespace ZeeKayDa.Auth.Tokens;

/// <summary>
/// A key the source listed but whose own dates or material are unusable, with the first problem found.
/// It is neither published nor ever signs.
/// </summary>
internal sealed record DroppedKey(SourceKey Key, ZeeKayDaConfigurationFailure Failure);
