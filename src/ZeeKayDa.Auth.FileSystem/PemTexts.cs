namespace ZeeKayDa.Auth.FileSystem;

/// <summary>
/// A <see cref="PemSigningFile"/>'s certificate text and key text, the same text twice for a combined file.
/// </summary>
internal sealed class PemTexts(PemText cert, PemText key) : IDisposable
{
    public PemText Cert { get; } = cert;

    public PemText Key { get; } = key;

    public void Dispose()
    {
        Cert.Dispose();
        Key.Dispose();
    }
}
