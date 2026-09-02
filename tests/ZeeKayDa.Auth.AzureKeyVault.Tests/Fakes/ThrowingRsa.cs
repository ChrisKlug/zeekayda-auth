using System.Security.Cryptography;

namespace ZeeKayDa.Auth.AzureKeyVault.Tests.Fakes;

/// <summary>
/// An <see cref="RSA"/> whose PKCS#8 imports throw the configured exception and which records
/// whether it was disposed, so <see cref="KeyVaultCertificateReader"/>'s import-failure arms —
/// which create and dispose the handle entirely inside the class — become observable.
/// </summary>
internal sealed class ThrowingRsa(Exception importFailure) : RSA
{
    public bool Disposed { get; private set; }

    public override void ImportPkcs8PrivateKey(ReadOnlySpan<byte> source, out int bytesRead) =>
        throw importFailure;

    public override void ImportEncryptedPkcs8PrivateKey(
        ReadOnlySpan<char> password, ReadOnlySpan<byte> source, out int bytesRead) =>
        throw importFailure;

    public override RSAParameters ExportParameters(bool includePrivateParameters) =>
        throw new NotSupportedException();

    public override void ImportParameters(RSAParameters parameters) =>
        throw new NotSupportedException();

    protected override void Dispose(bool disposing)
    {
        Disposed = true;
        base.Dispose(disposing);
    }
}
