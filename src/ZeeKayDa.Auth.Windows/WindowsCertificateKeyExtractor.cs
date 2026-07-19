using System.Security;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Security.Principal;
using ZeeKayDa.Auth.Tokens;

namespace ZeeKayDa.Auth.Windows;

/// <summary>
/// Extracts public and private key handles from an already-obtained <see cref="X509Certificate2"/>.
/// </summary>
/// <remarks>
/// Uses only <c>GetRSAPublicKey()</c> / <c>GetRSAPrivateKey()</c> / <c>GetECDsaPublicKey()</c> /
/// <c>GetECDsaPrivateKey()</c> — never <c>.PrivateKey</c>, never <c>ExportParameters(true)</c> — per the issue's security
/// requirement to prefer CNG/CAPI-backed handles over exporting raw key bytes into managed memory.
/// These accessors return handle objects that remain valid and usable independently after the
/// parent <see cref="X509Certificate2"/> is disposed (documented .NET Core 3.0+ behavior: the
/// returned handle duplicates the underlying key handle), which is what lets the caller dispose
/// every fetched certificate once all needed handles have been extracted.
/// </remarks>
internal static class WindowsCertificateKeyExtractor
{
    /// <summary>Extracts a public-only key handle and its key type from a certificate.</summary>
    public static (AsymmetricAlgorithm PublicKey, SigningKeyType KeyType) ExtractPublicKey(
        X509Certificate2 certificate, string thumbprint)
    {
        var rsa = certificate.GetRSAPublicKey();
        if (rsa is not null)
            return (rsa, SigningKeyType.Rsa);

        var ec = certificate.GetECDsaPublicKey();
        if (ec is not null)
            return (ec, SigningKeyType.Ec);

        throw UnsupportedKeyType(thumbprint);
    }

    /// <summary>Extracts a private key handle and its key type from a certificate.</summary>
    public static (AsymmetricAlgorithm PrivateKey, SigningKeyType KeyType) ExtractPrivateKey(
        X509Certificate2 certificate, string thumbprint)
    {
        if (!certificate.HasPrivateKey)
        {
            throw new ZeeKayDaConfigurationException(new ZeeKayDaConfigurationFailure(
                "signing.windows_certificate_store.private_key_not_found",
                $"Certificate '{thumbprint}' was found but has no private key installed alongside it " +
                "in the store. AddWindowsCertificateStoreSigning requires a certificate with an " +
                "accessible private key."));
        }

        var rsa = certificate.GetRSAPrivateKey();
        if (rsa is not null)
            return (rsa, SigningKeyType.Rsa);

        var ec = certificate.GetECDsaPrivateKey();
        if (ec is not null)
            return (ec, SigningKeyType.Ec);

        // HasPrivateKey was true but neither accessor returned a handle: the key exists but the
        // current process identity cannot access it (e.g. a restrictive CNG key ACL) — a distinct
        // root cause from "no private key at all", still surfaced under the same failure code with
        // a message tailored to this case.
        throw new ZeeKayDaConfigurationException(new ZeeKayDaConfigurationFailure(
            "signing.windows_certificate_store.private_key_not_found",
            $"Certificate '{thumbprint}' has a private key, but it could not be accessed by this " +
            $"process{FormatIdentitySuffix(TryResolveProcessIdentity())}. Verify the process identity " +
            "has permission to use the private key (see the Certificates MMC snap-in's 'Manage Private " +
            "Keys', or 'certutil -repairstore')."));
    }

    /// <summary>
    /// Formats the resolved process identity, if any, as a parenthetical suffix for an access-denied
    /// diagnostic message. A <see langword="null"/> or empty <paramref name="identity"/> — the
    /// best-effort degradation outcome when resolution fails or returns nothing usable — yields an
    /// empty suffix rather than a misleading or malformed message.
    /// </summary>
    internal static string FormatIdentitySuffix(string? identity) =>
        string.IsNullOrEmpty(identity) ? string.Empty : $" (running as '{identity}')";

    /// <summary>
    /// Resolves the current process identity for inclusion in an access-denied diagnostic message,
    /// best-effort. Identity resolution must never throw or mask the real root cause: a failure
    /// returns <see langword="null"/>, which <see cref="FormatIdentitySuffix"/> then omits from the
    /// message.
    /// </summary>
    private static string? TryResolveProcessIdentity()
    {
        try
        {
            return WindowsIdentity.GetCurrent().Name;
        }
        catch (Exception ex) when (ex is SecurityException or UnauthorizedAccessException)
        {
            return null;
        }
    }

    private static ZeeKayDaConfigurationException UnsupportedKeyType(string thumbprint) =>
        new(new ZeeKayDaConfigurationFailure(
            "signing.windows_certificate_store.unsupported_key_type",
            $"Certificate '{thumbprint}' does not carry an RSA or EC public key. Only RSA and EC " +
            "certificates are supported for JWT signing."));
}
