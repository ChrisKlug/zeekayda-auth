using System.Runtime.Versioning;
using System.Security.Cryptography;

namespace ZeeKayDa.Auth.MacOS.Interop;

/// <summary>
/// An <see cref="RSA"/> whose private-key operations are performed by a native macOS Keychain
/// <c>SecKeyRef</c> via <c>SecKeyCreateSignature</c>, rather than by raw key material held in
/// managed memory.
/// </summary>
/// <remarks>
/// <para>
/// Per the issue #290 security requirement, this class never exports or imports private key bytes:
/// <see cref="ExportParameters(bool)"/> throws when <c>includePrivateParameters</c> is
/// <see langword="true"/>, and <see cref="ImportParameters(RSAParameters)"/> always throws. Only the
/// public modulus/exponent — captured once at construction from <c>SecKeyCopyExternalRepresentation</c>
/// on the key's public counterpart — is ever exposed in managed memory, matching exactly what
/// <see cref="ZeeKayDa.Auth.Tokens.SigningKeyDescriptorFactory"/> and the JWKS endpoint need.
/// </para>
/// <para>
/// Only <see cref="SignHash(byte[], HashAlgorithmName, RSASignaturePadding)"/> is overridden for the
/// signing path: <c>RSA.SignData</c> is a concrete base-class method that computes the hash and
/// dispatches to <c>SignHash</c>, so no further override is needed to satisfy
/// <see cref="ZeeKayDa.Auth.Tokens.SigningAlgorithms"/>'s call pattern.
/// </para>
/// </remarks>
[SupportedOSPlatform("macos")]
internal sealed class SecKeyBackedRsa : RSA
{
    private readonly SafeCFTypeRefHandle _privateKeyHandle;
    private readonly RSAParameters _publicParameters;

    public SecKeyBackedRsa(SafeCFTypeRefHandle privateKeyHandle, RSAParameters publicParameters)
    {
        ArgumentNullException.ThrowIfNull(privateKeyHandle);

        _privateKeyHandle = privateKeyHandle;
        _publicParameters = publicParameters;
        KeySizeValue = publicParameters.Modulus!.Length * 8;
    }

    /// <inheritdoc/>
    /// <exception cref="NotSupportedException">
    /// Thrown when <paramref name="includePrivateParameters"/> is <see langword="true"/> — private
    /// key material is held exclusively by the macOS Keychain and is never exported.
    /// </exception>
    public override RSAParameters ExportParameters(bool includePrivateParameters)
    {
        if (includePrivateParameters)
        {
            throw new NotSupportedException(
                "This RSA key is backed by a macOS Keychain item. Its private key material is held " +
                "by the OS and cannot be exported to managed memory.");
        }

        return _publicParameters;
    }

    /// <inheritdoc/>
    /// <exception cref="NotSupportedException">Always thrown — this key is bound to an existing Keychain item.</exception>
    public override void ImportParameters(RSAParameters parameters) =>
        throw new NotSupportedException(
            "This RSA key is bound to an existing macOS Keychain item and does not support importing new key material.");

    /// <inheritdoc/>
    public override byte[] SignHash(byte[] hash, HashAlgorithmName hashAlgorithm, RSASignaturePadding padding)
    {
        ArgumentNullException.ThrowIfNull(hash);
        ArgumentNullException.ThrowIfNull(padding);

        var algorithm = SelectAlgorithm(hashAlgorithm, padding);
        return SecurityInterop.CreateSignature(_privateKeyHandle.DangerousGetHandle(), algorithm, hash);
    }

    /// <inheritdoc/>
    public override bool VerifyHash(byte[] hash, byte[] signature, HashAlgorithmName hashAlgorithm, RSASignaturePadding padding)
    {
        using var publicOnly = RSA.Create();
        publicOnly.ImportParameters(_publicParameters);
        return publicOnly.VerifyHash(hash, signature, hashAlgorithm, padding);
    }

    /// <inheritdoc/>
    protected override void Dispose(bool disposing)
    {
        if (disposing)
            _privateKeyHandle.Dispose();

        base.Dispose(disposing);
    }

    private static IntPtr SelectAlgorithm(HashAlgorithmName hashAlgorithm, RSASignaturePadding padding)
    {
        if (padding == RSASignaturePadding.Pkcs1)
        {
            if (hashAlgorithm == HashAlgorithmName.SHA256)
                return SecurityInterop.KSecKeyAlgorithmRsaSignatureDigestPkcs1v15Sha256;
            if (hashAlgorithm == HashAlgorithmName.SHA384)
                return SecurityInterop.KSecKeyAlgorithmRsaSignatureDigestPkcs1v15Sha384;
            if (hashAlgorithm == HashAlgorithmName.SHA512)
                return SecurityInterop.KSecKeyAlgorithmRsaSignatureDigestPkcs1v15Sha512;
        }
        else if (padding == RSASignaturePadding.Pss)
        {
            if (hashAlgorithm == HashAlgorithmName.SHA256)
                return SecurityInterop.KSecKeyAlgorithmRsaSignatureDigestPssSha256;
            if (hashAlgorithm == HashAlgorithmName.SHA384)
                return SecurityInterop.KSecKeyAlgorithmRsaSignatureDigestPssSha384;
            if (hashAlgorithm == HashAlgorithmName.SHA512)
                return SecurityInterop.KSecKeyAlgorithmRsaSignatureDigestPssSha512;
        }

        throw new NotSupportedException(
            $"Hash algorithm '{hashAlgorithm.Name}' with padding '{padding}' is not supported for macOS Keychain RSA signing.");
    }
}
