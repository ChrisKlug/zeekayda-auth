using System.Diagnostics.CodeAnalysis;

namespace ZeeKayDa.Auth.MacOS;

/// <summary>
/// Reads certificate and key items from the macOS Keychain by label. The seam that isolates the one
/// genuinely macOS-only piece of I/O in this provider so it can be faked in tests that run on any OS —
/// mirrors <c>ZeeKayDa.Auth.Windows.ICertificateStoreReader</c>'s role for the Windows Certificate
/// Store provider.
/// </summary>
internal interface IKeychainItemReader
{
    /// <summary>
    /// Attempts to find a certificate-backed Keychain item by label and pair it with its private key.
    /// </summary>
    /// <param name="label">The Keychain item's label.</param>
    /// <param name="certificate">
    /// The found certificate and its paired signing key, if a certificate with this label exists.
    /// The caller owns the returned instance and must dispose it.
    /// </param>
    /// <returns>
    /// <see langword="false"/> only when no certificate with this label exists — the caller falls
    /// back to <see cref="GetKey"/> to check for a bare key instead. Every other failure (the
    /// certificate exists but has no matching private key, an unsupported key type, or the Keychain
    /// is inaccessible) is thrown, not reported via the return value.
    /// </returns>
    bool TryGetCertificate(string label, [NotNullWhen(true)] out KeychainCertificateItem? certificate);

    /// <summary>
    /// Finds a bare (certificate-less) private key Keychain item by label.
    /// </summary>
    /// <param name="label">The Keychain item's label.</param>
    /// <returns>The found key. The caller owns the returned instance and must dispose it.</returns>
    /// <exception cref="ZeeKayDaConfigurationException">
    /// Thrown when no item with this label exists, the item is not a private key (e.g. a symmetric
    /// key, or a public key registered under this label by mistake), the key's type is neither RSA
    /// nor EC, the key lacks signing capability, or the Keychain is inaccessible.
    /// </exception>
    KeychainKeyItem GetKey(string label);
}
