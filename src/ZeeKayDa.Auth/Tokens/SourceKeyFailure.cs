namespace ZeeKayDa.Auth.Tokens;

/// <summary>An entry a signing key source holds but could not list, and why.</summary>
/// <param name="Id">The source's own identifier for the entry, as it would have listed it.</param>
/// <param name="Failure">
/// Why the entry could not be listed. Its message reaches the logs and a startup failure, so it
/// names an exception's type, never its message.
/// </param>
public sealed record SourceKeyFailure(SourceKeyId Id, ZeeKayDaConfigurationFailure Failure);
