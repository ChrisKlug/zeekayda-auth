using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using ZeeKayDa.Auth.Tokens;

namespace ZeeKayDa.Auth.MacOS;

/// <summary>
/// A certificate-backed Keychain item: the certificate (for its <c>NotBefore</c>/<c>NotAfter</c>
/// activation window) paired with a signing-capable handle to its private key.
/// </summary>
/// <remarks>
/// The caller owns both members and must dispose this instance exactly once. <see cref="SigningKey"/>
/// is safe to use for signing (or, when this item is not the active signer, only for
/// <c>ExportParameters(includePrivateParameters: false)</c>) for as long as this instance has not
/// been disposed.
/// </remarks>
internal sealed class KeychainCertificateItem : IDisposable
{
    /// <summary>Gets the certificate, used for its <c>NotBefore</c>/<c>NotAfter</c> activation window.</summary>
    public required X509Certificate2 Certificate { get; init; }

    /// <summary>Gets a signing-capable handle to the certificate's private key.</summary>
    public required AsymmetricAlgorithm SigningKey { get; init; }

    /// <summary>Gets the key's type (RSA or EC).</summary>
    public required SigningKeyType KeyType { get; init; }

    /// <inheritdoc/>
    public void Dispose()
    {
        Certificate.Dispose();
        SigningKey.Dispose();
    }
}
