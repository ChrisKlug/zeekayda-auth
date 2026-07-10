using System.Runtime.Versioning;
using System.Security.Cryptography;

namespace ZeeKayDa.Auth.MacOS.Interop;

/// <summary>
/// An <see cref="ECDsa"/> whose private-key operations are performed by a native macOS Keychain
/// <c>SecKeyRef</c> via <c>SecKeyCreateSignature</c>, rather than by raw key material held in
/// managed memory. See <see cref="SecKeyBackedRsa"/>'s remarks for the RSA counterpart of this design.
/// </summary>
/// <remarks>
/// <c>SecKeyCreateSignature</c>'s ECDSA "Digest" algorithms always return a DER (X9.62) encoded
/// signature; <see cref="SignHash"/> converts it to the IEEE P1363 fixed-width <c>r||s</c> format
/// .NET's <see cref="ECDsa"/> contract requires via <see cref="EcdsaSignatureCodec"/>.
/// <see cref="ECDsa.SignHash(byte[])"/> is not told which hash algorithm produced its input, so the
/// digest algorithm to sign with is inferred from the <c>hash</c> argument's length (32/48/64 bytes
/// for SHA-256/384/512) — safe here because <see cref="ZeeKayDa.Auth.Tokens.SigningAlgorithms"/> only
/// ever calls this with a length matching the <see cref="ZeeKayDa.Auth.Tokens.SigningAlgorithm"/>'s
/// own declared hash. The curve's field width (needed for the fixed-width conversion, and distinct
/// from the hash length for ES512/P-521) is captured once at construction instead.
/// </remarks>
[SupportedOSPlatform("macos")]
internal sealed class SecKeyBackedECDsa : ECDsa
{
    private readonly SafeCFTypeRefHandle _privateKeyHandle;
    private readonly ECParameters _publicParameters;
    private readonly int _fieldSizeBytes;

    public SecKeyBackedECDsa(SafeCFTypeRefHandle privateKeyHandle, ECParameters publicParameters, int fieldSizeBytes)
    {
        ArgumentNullException.ThrowIfNull(privateKeyHandle);

        _privateKeyHandle = privateKeyHandle;
        _publicParameters = publicParameters;
        _fieldSizeBytes = fieldSizeBytes;
        KeySizeValue = fieldSizeBytes * 8;
    }

    /// <inheritdoc/>
    /// <exception cref="NotSupportedException">
    /// Thrown when <paramref name="includePrivateParameters"/> is <see langword="true"/> — private
    /// key material is held exclusively by the macOS Keychain and is never exported.
    /// </exception>
    public override ECParameters ExportParameters(bool includePrivateParameters)
    {
        if (includePrivateParameters)
        {
            throw new NotSupportedException(
                "This EC key is backed by a macOS Keychain item. Its private key material is held " +
                "by the OS and cannot be exported to managed memory.");
        }

        return _publicParameters;
    }

    /// <inheritdoc/>
    /// <exception cref="NotSupportedException">Always thrown — this key is bound to an existing Keychain item.</exception>
    public override void ImportParameters(ECParameters parameters) =>
        throw new NotSupportedException(
            "This EC key is bound to an existing macOS Keychain item and does not support importing new key material.");

    /// <inheritdoc/>
    public override byte[] SignHash(byte[] hash)
    {
        ArgumentNullException.ThrowIfNull(hash);

        var algorithm = SelectAlgorithm(hash.Length);
        var der = SecurityInterop.CreateSignature(_privateKeyHandle.DangerousGetHandle(), algorithm, hash);
        return EcdsaSignatureCodec.DerToP1363(der, _fieldSizeBytes);
    }

    /// <inheritdoc/>
    public override bool VerifyHash(byte[] hash, byte[] signature)
    {
        using var publicOnly = ECDsa.Create(_publicParameters);
        return publicOnly.VerifyHash(hash, signature);
    }

    /// <inheritdoc/>
    protected override void Dispose(bool disposing)
    {
        if (disposing)
            _privateKeyHandle.Dispose();

        base.Dispose(disposing);
    }

    private static IntPtr SelectAlgorithm(int hashLengthBytes) => hashLengthBytes switch
    {
        32 => SecurityInterop.KSecKeyAlgorithmEcdsaSignatureDigestX962Sha256,
        48 => SecurityInterop.KSecKeyAlgorithmEcdsaSignatureDigestX962Sha384,
        64 => SecurityInterop.KSecKeyAlgorithmEcdsaSignatureDigestX962Sha512,
        _ => throw new NotSupportedException(
            $"A {hashLengthBytes}-byte digest does not match a supported SHA-256/384/512 hash for macOS Keychain EC signing."),
    };
}
