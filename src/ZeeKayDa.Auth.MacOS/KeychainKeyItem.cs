using System.Security.Cryptography;
using ZeeKayDa.Auth.Tokens;

namespace ZeeKayDa.Auth.MacOS;

/// <summary>
/// A bare, certificate-less Keychain key item: a signing-capable handle to a private key with no
/// associated certificate, and therefore no <c>NotBefore</c>/<c>NotAfter</c> to anchor rotation on.
/// </summary>
/// <remarks>
/// The caller owns <see cref="SigningKey"/> and must dispose this instance exactly once.
/// </remarks>
internal sealed class KeychainKeyItem : IDisposable
{
    /// <summary>Gets a signing-capable handle to the private key.</summary>
    public required AsymmetricAlgorithm SigningKey { get; init; }

    /// <summary>Gets the key's type (RSA or EC).</summary>
    public required SigningKeyType KeyType { get; init; }

    /// <inheritdoc/>
    public void Dispose() => SigningKey.Dispose();
}
