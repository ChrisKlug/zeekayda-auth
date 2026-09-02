using System.Security.Cryptography;

namespace ZeeKayDa.Auth.AzureKeyVault.Tests.Fakes;

/// <summary>
/// An <see cref="ECDsa"/> whose PKCS#8 imports throw the configured exception and which records
/// whether it was disposed — the EC counterpart of <see cref="ThrowingRsa"/>.
/// </summary>
internal sealed class ThrowingEcdsa(Exception importFailure) : ECDsa
{
    public bool Disposed { get; private set; }

    public override void ImportPkcs8PrivateKey(ReadOnlySpan<byte> source, out int bytesRead) =>
        throw importFailure;

    public override void ImportEncryptedPkcs8PrivateKey(
        ReadOnlySpan<char> password, ReadOnlySpan<byte> source, out int bytesRead) =>
        throw importFailure;

    public override byte[] SignHash(byte[] hash) => throw new NotSupportedException();

    public override bool VerifyHash(byte[] hash, byte[] signature) => throw new NotSupportedException();

    protected override void Dispose(bool disposing)
    {
        Disposed = true;
        base.Dispose(disposing);
    }
}
