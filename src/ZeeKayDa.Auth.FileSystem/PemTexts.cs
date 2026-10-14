namespace ZeeKayDa.Auth.FileSystem;

/// <summary>
/// A <see cref="PemSigningFile"/>'s certificate text and key text, the same text twice for a combined file.
/// </summary>
internal sealed record PemTexts(string Cert, string Key);
