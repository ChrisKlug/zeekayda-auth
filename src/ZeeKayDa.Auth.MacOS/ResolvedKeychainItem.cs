using System.Security.Cryptography;
using ZeeKayDa.Auth.Tokens;

namespace ZeeKayDa.Auth.MacOS;

/// <summary>
/// A registered label, fully resolved against the Keychain: its signing key material and the
/// activation window to feed into <see cref="SigningKeyRotation"/>, regardless of whether it came
/// from a certificate's own <c>NotBefore</c>/<c>NotAfter</c> or an explicit
/// <see cref="MacOsKeychainSigningOptions.AddKey(string, DateTimeOffset, DateTimeOffset?)"/> call.
/// </summary>
internal sealed class ResolvedKeychainItem : IDisposable
{
    public required AsymmetricAlgorithm SigningKey { get; init; }

    public required SigningKeyType KeyType { get; init; }

    public required DateTimeOffset ActivatesAt { get; init; }

    public required DateTimeOffset ExpiresAt { get; init; }

    /// <summary>
    /// Gets the certificate subject, when this item is certificate-backed, for use in log messages.
    /// <see langword="null"/> for a bare key.
    /// </summary>
    public string? CertificateSubject { get; init; }

    /// <inheritdoc/>
    public void Dispose() => SigningKey.Dispose();
}
