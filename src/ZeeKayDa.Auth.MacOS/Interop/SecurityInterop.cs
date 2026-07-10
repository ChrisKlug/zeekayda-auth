using System.Runtime.InteropServices;
using System.Runtime.Versioning;

namespace ZeeKayDa.Auth.MacOS.Interop;

/// <summary>
/// Minimal P/Invoke surface over Security.framework: Keychain item lookup (<c>SecItemCopyMatching</c>),
/// certificate/private-key pairing (<c>SecIdentityCreateWithCertificate</c>), key introspection, and
/// signing (<c>SecKeyCreateSignature</c>).
/// </summary>
/// <remarks>
/// Every function declared here that returns a <c>CFTypeRef</c>-derived reference (<c>SecKeyRef</c>,
/// <c>SecCertificateRef</c>, <c>SecIdentityRef</c>, <c>CFDataRef</c>, <c>CFDictionaryRef</c>) follows
/// CoreFoundation's "Create Rule" per Apple's own header documentation (each declaration below cites
/// the exact header comment this was verified against) — the caller owns the result and must release
/// it via <see cref="CoreFoundationInterop.CFRelease"/>, which every call site in this package does by
/// wrapping the raw pointer in a <see cref="SafeCFTypeRefHandle"/> immediately.
/// </remarks>
[SupportedOSPlatform("macos")]
internal static class SecurityInterop
{
    private const string SecurityLib = "/System/Library/Frameworks/Security.framework/Security";

    private static readonly IntPtr LibraryHandle = NativeLibrary.Load(SecurityLib);

    // ── Class / attribute / result-type constants (SecItem.h) ──────────────────────────────────────
    internal static readonly IntPtr KSecClass = GetConstant("kSecClass");
    internal static readonly IntPtr KSecClassCertificate = GetConstant("kSecClassCertificate");
    internal static readonly IntPtr KSecClassKey = GetConstant("kSecClassKey");
    internal static readonly IntPtr KSecAttrLabel = GetConstant("kSecAttrLabel");
    internal static readonly IntPtr KSecAttrKeyClass = GetConstant("kSecAttrKeyClass");
    internal static readonly IntPtr KSecAttrKeyClassPrivate = GetConstant("kSecAttrKeyClassPrivate");
    internal static readonly IntPtr KSecAttrKeyType = GetConstant("kSecAttrKeyType");
    internal static readonly IntPtr KSecAttrKeyTypeRsa = GetConstant("kSecAttrKeyTypeRSA");
    internal static readonly IntPtr KSecAttrKeyTypeEcSecPrimeRandom = GetConstant("kSecAttrKeyTypeECSECPrimeRandom");
    internal static readonly IntPtr KSecAttrKeySizeInBits = GetConstant("kSecAttrKeySizeInBits");
    internal static readonly IntPtr KSecAttrCanSign = GetConstant("kSecAttrCanSign");
    internal static readonly IntPtr KSecReturnRef = GetConstant("kSecReturnRef");
    internal static readonly IntPtr KSecMatchLimit = GetConstant("kSecMatchLimit");
    internal static readonly IntPtr KSecMatchLimitOne = GetConstant("kSecMatchLimitOne");

    /// <summary>
    /// Not used by <see cref="KeychainItemReader"/> itself (which always looks up a single item via
    /// <see cref="KSecMatchLimitOne"/>) — exposed for the macOS-only integration test helpers that
    /// need to reliably delete every item (public and private key halves) sharing a test label.
    /// </summary>
    internal static readonly IntPtr KSecMatchLimitAll = GetConstant("kSecMatchLimitAll");

    // ── Signature algorithms (SecKey.h) — "Digest" variants: the input is an already-computed hash,
    // matching AsymmetricAlgorithm.SignHash's contract exactly, so no extra hashing step is needed
    // here. RSA digest variants return the raw PKCS#1/PSS signature value; ECDSA digest variants
    // return a DER (X9.62) SEQUENCE{r,s} that SecKeyBackedECDsa converts to IEEE P1363 fixed-width
    // r||s via EcdsaSignatureCodec, matching .NET ECDsa's own SignHash convention. ────────────────────
    internal static readonly IntPtr KSecKeyAlgorithmRsaSignatureDigestPkcs1v15Sha256 = GetConstant("kSecKeyAlgorithmRSASignatureDigestPKCS1v15SHA256");
    internal static readonly IntPtr KSecKeyAlgorithmRsaSignatureDigestPkcs1v15Sha384 = GetConstant("kSecKeyAlgorithmRSASignatureDigestPKCS1v15SHA384");
    internal static readonly IntPtr KSecKeyAlgorithmRsaSignatureDigestPkcs1v15Sha512 = GetConstant("kSecKeyAlgorithmRSASignatureDigestPKCS1v15SHA512");
    internal static readonly IntPtr KSecKeyAlgorithmRsaSignatureDigestPssSha256 = GetConstant("kSecKeyAlgorithmRSASignatureDigestPSSSHA256");
    internal static readonly IntPtr KSecKeyAlgorithmRsaSignatureDigestPssSha384 = GetConstant("kSecKeyAlgorithmRSASignatureDigestPSSSHA384");
    internal static readonly IntPtr KSecKeyAlgorithmRsaSignatureDigestPssSha512 = GetConstant("kSecKeyAlgorithmRSASignatureDigestPSSSHA512");
    internal static readonly IntPtr KSecKeyAlgorithmEcdsaSignatureDigestX962Sha256 = GetConstant("kSecKeyAlgorithmECDSASignatureDigestX962SHA256");
    internal static readonly IntPtr KSecKeyAlgorithmEcdsaSignatureDigestX962Sha384 = GetConstant("kSecKeyAlgorithmECDSASignatureDigestX962SHA384");
    internal static readonly IntPtr KSecKeyAlgorithmEcdsaSignatureDigestX962Sha512 = GetConstant("kSecKeyAlgorithmECDSASignatureDigestX962SHA512");

    // ── OSStatus codes (SecBase.h) ──────────────────────────────────────────────────────────────────

    /// <summary>The specified item could not be found in the Keychain (SecBase.h <c>errSecItemNotFound</c>).</summary>
    internal const int ErrSecItemNotFound = -25300;

    /// <summary>No Keychain is available (SecBase.h <c>errSecNotAvailable</c>).</summary>
    internal const int ErrSecNotAvailable = -25291;

    /// <summary>Authorization/authentication failed (SecBase.h <c>errSecAuthFailed</c>).</summary>
    internal const int ErrSecAuthFailed = -25293;

    /// <summary>User interaction is required but not allowed — typical of a locked/headless session (SecBase.h <c>errSecInteractionNotAllowed</c>).</summary>
    internal const int ErrSecInteractionNotAllowed = -25308;

    /// <summary>A required entitlement is not present (SecBase.h <c>errSecMissingEntitlement</c>).</summary>
    internal const int ErrSecMissingEntitlement = -34018;

    [DllImport(SecurityLib)]
    private static extern int SecItemCopyMatching(IntPtr query, out IntPtr result);

    [DllImport(SecurityLib)]
    private static extern int SecIdentityCreateWithCertificate(IntPtr keychainOrArray, IntPtr certificateRef, out IntPtr identityRef);

    [DllImport(SecurityLib)]
    private static extern int SecIdentityCopyCertificate(IntPtr identityRef, out IntPtr certificateRef);

    [DllImport(SecurityLib)]
    private static extern int SecIdentityCopyPrivateKey(IntPtr identityRef, out IntPtr privateKeyRef);

    [DllImport(SecurityLib)]
    private static extern IntPtr SecCertificateCopyData(IntPtr certificate);

    [DllImport(SecurityLib)]
    private static extern IntPtr SecKeyCopyPublicKey(IntPtr key);

    [DllImport(SecurityLib)]
    private static extern IntPtr SecKeyCopyExternalRepresentation(IntPtr key, out IntPtr error);

    [DllImport(SecurityLib)]
    private static extern IntPtr SecKeyCopyAttributes(IntPtr key);

    [DllImport(SecurityLib)]
    private static extern IntPtr SecKeyCreateSignature(IntPtr key, IntPtr algorithm, IntPtr dataToSign, out IntPtr error);

    /// <summary>
    /// Finds Keychain items matching <paramref name="query"/> (built via <see cref="CFDictionaryBuilder"/>).
    /// </summary>
    /// <returns>
    /// The OSStatus result code. On success (<c>errSecSuccess</c>, 0), <paramref name="result"/> owns
    /// the found reference (Create Rule) and must be wrapped in a <see cref="SafeCFTypeRefHandle"/>.
    /// </returns>
    internal static int ItemCopyMatching(IntPtr query, out SafeCFTypeRefHandle result)
    {
        var status = SecItemCopyMatching(query, out var raw);
        result = new SafeCFTypeRefHandle(raw);
        return status;
    }

    /// <summary>
    /// Pairs <paramref name="certificate"/> with its associated private key, searched for across the
    /// default Keychain list. Returns <see cref="ErrSecItemNotFound"/> when no matching private key
    /// is present (a certificate-only Keychain item).
    /// </summary>
    internal static int IdentityCreateWithCertificate(IntPtr certificate, out SafeCFTypeRefHandle identity)
    {
        var status = SecIdentityCreateWithCertificate(IntPtr.Zero, certificate, out var raw);
        identity = new SafeCFTypeRefHandle(raw);
        return status;
    }

    /// <summary>Returns the certificate half of an identity. Create Rule.</summary>
    internal static SafeCFTypeRefHandle IdentityCopyCertificate(IntPtr identity)
    {
        SecIdentityCopyCertificate(identity, out var raw);
        return new SafeCFTypeRefHandle(raw);
    }

    /// <summary>Returns the private-key half of an identity. Create Rule.</summary>
    internal static SafeCFTypeRefHandle IdentityCopyPrivateKey(IntPtr identity)
    {
        SecIdentityCopyPrivateKey(identity, out var raw);
        return new SafeCFTypeRefHandle(raw);
    }

    /// <summary>Returns the DER encoding of a certificate. Create Rule.</summary>
    internal static byte[] CertificateCopyDerData(IntPtr certificate)
    {
        using var data = new SafeCFTypeRefHandle(SecCertificateCopyData(certificate));
        return CoreFoundationInterop.GetDataBytes(data.DangerousGetHandle());
    }

    /// <summary>Returns the public-key counterpart of a key or key pair, or a null handle if unavailable. Create Rule.</summary>
    internal static SafeCFTypeRefHandle KeyCopyPublicKey(IntPtr key) => new(SecKeyCopyPublicKey(key));

    /// <summary>
    /// Exports a key in the format documented for its type (PKCS#1 for RSA, ANSI X9.63 <c>04||X||Y</c>
    /// for EC). Create Rule for the result; the out <c>CFErrorRef</c> is also owned and released here.
    /// </summary>
    internal static byte[] KeyCopyExternalRepresentation(IntPtr key)
    {
        var dataPtr = SecKeyCopyExternalRepresentation(key, out var errorPtr);
        using var error = new SafeCFTypeRefHandle(errorPtr);
        if (dataPtr == IntPtr.Zero)
            throw new InvalidOperationException("SecKeyCopyExternalRepresentation failed: " + DescribeError(error));

        using var data = new SafeCFTypeRefHandle(dataPtr);
        return CoreFoundationInterop.GetDataBytes(data.DangerousGetHandle());
    }

    /// <summary>Returns the Keychain attribute dictionary for a key. Create Rule.</summary>
    internal static SafeCFTypeRefHandle KeyCopyAttributes(IntPtr key) => new(SecKeyCopyAttributes(key));

    /// <summary>
    /// Signs an already-computed digest with a private key using one of the "Digest" <c>SecKeyAlgorithm</c>
    /// constants. Create Rule for the result; the out <c>CFErrorRef</c> is also owned and released here.
    /// </summary>
    internal static byte[] CreateSignature(IntPtr privateKey, IntPtr algorithm, byte[] digest)
    {
        using var digestData = new SafeCFTypeRefHandle(CoreFoundationInterop.CreateData(digest));
        var signaturePtr = SecKeyCreateSignature(privateKey, algorithm, digestData.DangerousGetHandle(), out var errorPtr);
        using var error = new SafeCFTypeRefHandle(errorPtr);
        if (signaturePtr == IntPtr.Zero)
            throw new System.Security.Cryptography.CryptographicException("SecKeyCreateSignature failed: " + DescribeError(error));

        using var signature = new SafeCFTypeRefHandle(signaturePtr);
        return CoreFoundationInterop.GetDataBytes(signature.DangerousGetHandle());
    }

    /// <summary>Renders a CFErrorRef's description for diagnostics, via <c>CFCopyDescription</c>.</summary>
    private static string DescribeError(SafeCFTypeRefHandle error)
    {
        if (error.IsInvalid)
            return "(no error information available)";

        return CoreFoundationInterop.Describe(error.DangerousGetHandle());
    }

    private static IntPtr GetConstant(string symbolName) =>
        Marshal.ReadIntPtr(NativeLibrary.GetExport(LibraryHandle, symbolName));
}
