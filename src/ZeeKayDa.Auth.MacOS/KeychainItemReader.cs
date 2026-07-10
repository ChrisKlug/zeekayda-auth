using System.Diagnostics.CodeAnalysis;
using System.Runtime.Versioning;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using ZeeKayDa.Auth.MacOS.Interop;
using ZeeKayDa.Auth.Tokens;

namespace ZeeKayDa.Auth.MacOS;

/// <summary>
/// Reads certificate and key items from a real macOS Keychain via Security.framework.
/// </summary>
/// <remarks>
/// This is the one genuinely macOS-only piece of I/O in this provider. It cannot be meaningfully
/// unit-tested on a single CI OS, so it is exercised only by the macOS-only integration tests in
/// <c>Integration/KeychainItemReaderTests.cs</c>; the rest of the provider is tested against
/// <c>IKeychainItemReader</c> fakes on any OS — mirroring the precedent set by
/// <c>ZeeKayDa.Auth.Windows.CertificateStoreReader</c>.
/// </remarks>
[ExcludeFromCodeCoverage(Justification = "Requires a real macOS Keychain; exercised by macOS-only integration tests. Unit tests fake IKeychainItemReader instead.")]
[SupportedOSPlatform("macos")]
internal sealed class KeychainItemReader : IKeychainItemReader
{
    /// <inheritdoc/>
    public bool TryGetCertificate(string label, [NotNullWhen(true)] out KeychainCertificateItem? certificate)
    {
        certificate = null;

        using var query = new CFDictionaryBuilder()
            .Add(SecurityInterop.KSecClass, SecurityInterop.KSecClassCertificate)
            .AddOwnedString(SecurityInterop.KSecAttrLabel, label)
            .Add(SecurityInterop.KSecReturnRef, CoreFoundationInterop.KCFBooleanTrue)
            .Add(SecurityInterop.KSecMatchLimit, SecurityInterop.KSecMatchLimitOne)
            .Build();

        var status = SecurityInterop.ItemCopyMatching(query.DangerousGetHandle(), out var certificateHandle);
        using (certificateHandle)
        {
            if (status == SecurityInterop.ErrSecItemNotFound)
                return false;

            ThrowIfInaccessible(status, label);

            var certificateRef = certificateHandle.DangerousGetHandle();
            var derBytes = SecurityInterop.CertificateCopyDerData(certificateRef);
            var certificateObject = X509CertificateLoader.LoadCertificate(derBytes);

            try
            {
                var identityStatus = SecurityInterop.IdentityCreateWithCertificate(certificateRef, out var identity);
                using (identity)
                {
                    if (identityStatus == SecurityInterop.ErrSecItemNotFound)
                    {
                        throw new ZeeKayDaConfigurationException(new ZeeKayDaConfigurationFailure(
                            "signing.macos_keychain.private_key_not_found",
                            $"A certificate with label '{label}' was found in the Keychain, but no matching " +
                            "private key is present. AddMacOsKeychainSigning requires a certificate with an " +
                            "accessible private key (an 'identity') — verify both were imported together " +
                            "(e.g. via a PKCS#12 import)."));
                    }

                    ThrowIfInaccessible(identityStatus, label);

                    // Not wrapped in `using`: ownership transfers into BuildSigningKey, which either
                    // hands it to the returned SecKeyBacked* wrapper (which disposes it) or disposes
                    // it itself on any failure path. Never both, never neither.
                    var privateKeyHandle = SecurityInterop.IdentityCopyPrivateKey(identity.DangerousGetHandle());
                    var (signingKey, keyType) = BuildSigningKey(privateKeyHandle, label);

                    certificate = new KeychainCertificateItem
                    {
                        Certificate = certificateObject,
                        SigningKey = signingKey,
                        KeyType = keyType,
                    };
                    return true;
                }
            }
            catch
            {
                certificateObject.Dispose();
                throw;
            }
        }
    }

    /// <inheritdoc/>
    public KeychainKeyItem GetKey(string label)
    {
        // Filters on kSecAttrKeyClass = Private directly, rather than inspecting whatever
        // SecItemCopyMatching happens to return first: a public and a private key item can
        // legitimately share the same label (e.g. tooling that labels both halves of a pair
        // identically), and without this filter, kSecMatchLimitOne's unspecified tie-break could
        // silently select the wrong one. A symmetric key never has kSecAttrKeyClassPrivate, so it is
        // also naturally excluded here, not just RSA/EC public keys.
        using var query = new CFDictionaryBuilder()
            .Add(SecurityInterop.KSecClass, SecurityInterop.KSecClassKey)
            .AddOwnedString(SecurityInterop.KSecAttrLabel, label)
            .Add(SecurityInterop.KSecAttrKeyClass, SecurityInterop.KSecAttrKeyClassPrivate)
            .Add(SecurityInterop.KSecReturnRef, CoreFoundationInterop.KCFBooleanTrue)
            .Add(SecurityInterop.KSecMatchLimit, SecurityInterop.KSecMatchLimitOne)
            .Build();

        var status = SecurityInterop.ItemCopyMatching(query.DangerousGetHandle(), out var keyHandle);
        if (status == SecurityInterop.ErrSecItemNotFound)
        {
            keyHandle.Dispose();
            throw BuildNotFoundOrNotAPrivateKeyException(label);
        }

        try
        {
            ThrowIfInaccessible(status, label);
        }
        catch
        {
            keyHandle.Dispose();
            throw;
        }

        // Not wrapped in `using`: ownership transfers into BuildSigningKey, which either hands it to
        // the returned SecKeyBacked* wrapper (which disposes it) or disposes it itself on failure.
        var (signingKey, keyType) = BuildSigningKey(keyHandle, label);
        return new KeychainKeyItem { SigningKey = signingKey, KeyType = keyType };
    }

    /// <summary>
    /// Validates a key handle's Keychain attributes and builds a signing-capable wrapper around it.
    /// Takes ownership of <paramref name="privateKeyHandle"/>: on success, the returned
    /// <see cref="AsymmetricAlgorithm"/> disposes it; on any failure, it is disposed here before the
    /// exception propagates.
    /// </summary>
    private static (AsymmetricAlgorithm SigningKey, SigningKeyType KeyType) BuildSigningKey(
        SafeCFTypeRefHandle privateKeyHandle, string label)
    {
        try
        {
            using var attributes = SecurityInterop.KeyCopyAttributes(privateKeyHandle.DangerousGetHandle());
            if (attributes.IsInvalid)
                throw UnsupportedKeyType(label);

            var attributesHandle = attributes.DangerousGetHandle();

            var keyClass = CoreFoundationInterop.GetDictionaryValue(attributesHandle, SecurityInterop.KSecAttrKeyClass);
            if (keyClass == IntPtr.Zero || !CoreFoundationInterop.AreEqual(keyClass, SecurityInterop.KSecAttrKeyClassPrivate))
            {
                throw new ZeeKayDaConfigurationException(new ZeeKayDaConfigurationFailure(
                    "signing.macos_keychain.not_a_private_key",
                    $"The Keychain item with label '{label}' is not a private key (it may be a public " +
                    "key or a symmetric key registered under this label). AddMacOsKeychainSigning " +
                    "requires an asymmetric private key."));
            }

            var canSign = CoreFoundationInterop.GetDictionaryValue(attributesHandle, SecurityInterop.KSecAttrCanSign);
            if (canSign == IntPtr.Zero || !CoreFoundationInterop.GetBooleanValue(canSign))
            {
                throw new ZeeKayDaConfigurationException(new ZeeKayDaConfigurationFailure(
                    "signing.macos_keychain.lacks_signing_capability",
                    $"The Keychain item with label '{label}' does not have signing capability " +
                    "(kSecAttrCanSign is false). Verify the key was created or imported for signing use."));
            }

            var keyType = CoreFoundationInterop.GetDictionaryValue(attributesHandle, SecurityInterop.KSecAttrKeyType);
            var keySizeBits = CoreFoundationInterop.GetNumberValue(
                CoreFoundationInterop.GetDictionaryValue(attributesHandle, SecurityInterop.KSecAttrKeySizeInBits));

            if (keyType != IntPtr.Zero && CoreFoundationInterop.AreEqual(keyType, SecurityInterop.KSecAttrKeyTypeRsa))
                return (BuildRsaSigningKey(privateKeyHandle), SigningKeyType.Rsa);

            if (keyType != IntPtr.Zero && CoreFoundationInterop.AreEqual(keyType, SecurityInterop.KSecAttrKeyTypeEcSecPrimeRandom))
                return (BuildEcSigningKey(privateKeyHandle, keySizeBits), SigningKeyType.Ec);

            throw UnsupportedKeyType(label);
        }
        catch
        {
            privateKeyHandle.Dispose();
            throw;
        }
    }

    private static SecKeyBackedRsa BuildRsaSigningKey(SafeCFTypeRefHandle privateKeyHandle)
    {
        using var publicKeyHandle = SecurityInterop.KeyCopyPublicKey(privateKeyHandle.DangerousGetHandle());
        var publicKeyBytes = SecurityInterop.KeyCopyExternalRepresentation(publicKeyHandle.DangerousGetHandle());

        using var publicRsa = RSA.Create();
        publicRsa.ImportRSAPublicKey(publicKeyBytes, out _);
        var parameters = publicRsa.ExportParameters(includePrivateParameters: false);

        return new SecKeyBackedRsa(privateKeyHandle, parameters);
    }

    private static SecKeyBackedECDsa BuildEcSigningKey(SafeCFTypeRefHandle privateKeyHandle, int keySizeBits)
    {
        using var publicKeyHandle = SecurityInterop.KeyCopyPublicKey(privateKeyHandle.DangerousGetHandle());
        var publicKeyBytes = SecurityInterop.KeyCopyExternalRepresentation(publicKeyHandle.DangerousGetHandle());

        // ANSI X9.63 uncompressed point: 0x04 || X || Y, each exactly the curve's field size in bytes.
        var fieldSizeBytes = (publicKeyBytes.Length - 1) / 2;
        var x = publicKeyBytes.AsSpan(1, fieldSizeBytes).ToArray();
        var y = publicKeyBytes.AsSpan(1 + fieldSizeBytes, fieldSizeBytes).ToArray();

        var parameters = new ECParameters
        {
            Curve = CurveForKeySize(keySizeBits),
            Q = new ECPoint { X = x, Y = y },
        };

        return new SecKeyBackedECDsa(privateKeyHandle, parameters, fieldSizeBytes);
    }

    private static ECCurve CurveForKeySize(int keySizeBits) => keySizeBits switch
    {
        256 => ECCurve.NamedCurves.nistP256,
        384 => ECCurve.NamedCurves.nistP384,
        521 => ECCurve.NamedCurves.nistP521,
        _ => throw new NotSupportedException($"EC key size {keySizeBits} bits is not a supported NIST curve (P-256, P-384, P-521)."),
    };

    private static ZeeKayDaConfigurationException UnsupportedKeyType(string label) =>
        new(new ZeeKayDaConfigurationFailure(
            "signing.macos_keychain.unsupported_key_type",
            $"The Keychain item with label '{label}' does not carry an RSA or EC key. Only RSA and " +
            "EC keys are supported for JWT signing."));

    /// <summary>
    /// Builds the exception for when no <em>private</em> key with this label was found. Distinguishes
    /// "nothing at all" from "something exists under this label, but it is not a usable private key"
    /// (AC #9 — e.g. a symmetric key, or a public key registered under this label by mistake) via a
    /// cheap, class-unfiltered follow-up lookup, purely for a clearer diagnostic message.
    /// </summary>
    private static ZeeKayDaConfigurationException BuildNotFoundOrNotAPrivateKeyException(string label)
    {
        using var anyClassQuery = new CFDictionaryBuilder()
            .Add(SecurityInterop.KSecClass, SecurityInterop.KSecClassKey)
            .AddOwnedString(SecurityInterop.KSecAttrLabel, label)
            .Add(SecurityInterop.KSecMatchLimit, SecurityInterop.KSecMatchLimitOne)
            .Build();

        var status = SecurityInterop.ItemCopyMatching(anyClassQuery.DangerousGetHandle(), out var anyKeyHandle);
        using (anyKeyHandle)
        {
            if (status == 0)
            {
                return new ZeeKayDaConfigurationException(new ZeeKayDaConfigurationFailure(
                    "signing.macos_keychain.not_a_private_key",
                    $"The Keychain item with label '{label}' is not a private key (it may be a public " +
                    "key or a symmetric key registered under this label). AddMacOsKeychainSigning " +
                    "requires an asymmetric private key."));
            }

            return new ZeeKayDaConfigurationException(new ZeeKayDaConfigurationFailure(
                "signing.macos_keychain.item_not_found",
                $"No certificate or key with label '{label}' was found in the Keychain. Verify the " +
                "label and that the item has been added to a Keychain this process can access " +
                "(login or System)."));
        }
    }

    private static void ThrowIfInaccessible(int status, string label)
    {
        if (status == 0)
            return;

        var reason = status switch
        {
            SecurityInterop.ErrSecAuthFailed => "authentication failed",
            SecurityInterop.ErrSecInteractionNotAllowed => "user interaction is required but not allowed (the session may be locked, or this is a headless/non-interactive process)",
            SecurityInterop.ErrSecNotAvailable => "no Keychain is available",
            SecurityInterop.ErrSecMissingEntitlement => "a required entitlement is missing",
            _ => $"OSStatus {status}",
        };

        throw new ZeeKayDaConfigurationException(new ZeeKayDaConfigurationFailure(
            "signing.macos_keychain.keychain_inaccessible",
            $"The Keychain could not be accessed while looking up label '{label}': {reason}. If this is " +
            "a headless server, unlock the login Keychain first (e.g. `security unlock-keychain`), grant " +
            "this application access via Keychain Access.app or the `security` CLI (`security " +
            "set-key-partition-list`), or move the item to the System Keychain with an appropriate ACL."));
    }
}
