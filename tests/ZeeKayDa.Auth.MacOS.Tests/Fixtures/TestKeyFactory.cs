using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace ZeeKayDa.Auth.MacOS.Tests.Fixtures;

/// <summary>
/// Fabricates self-signed test certificates and bare RSA/EC key pairs in memory, entirely in managed
/// code — no real macOS Keychain needed, so rotation and descriptor-building logic can be
/// unit-tested on any OS. Mirrors <c>ZeeKayDa.Auth.Windows.Tests.Fixtures.TestCertificateFactory</c>.
/// </summary>
internal static class TestKeyFactory
{
    public static X509Certificate2 CreateRsaSelfSigned(
        string subjectName, DateTimeOffset notBefore, DateTimeOffset notAfter, int keySizeBits = 2048)
    {
        using var rsa = RSA.Create(keySizeBits);
        var request = new CertificateRequest($"CN={subjectName}", rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        return request.CreateSelfSigned(notBefore, notAfter);
    }

    public static X509Certificate2 CreateEcSelfSigned(
        string subjectName, DateTimeOffset notBefore, DateTimeOffset notAfter, ECCurve? curve = null)
    {
        using var ecdsa = ECDsa.Create(curve ?? ECCurve.NamedCurves.nistP256);
        var request = new CertificateRequest($"CN={subjectName}", ecdsa, HashAlgorithmName.SHA256);
        return request.CreateSelfSigned(notBefore, notAfter);
    }

    /// <summary>Creates a standalone, usable RSA key pair (a stand-in for a bare Keychain key item).</summary>
    public static RSA CreateRsaKey(int keySizeBits = 2048) => RSA.Create(keySizeBits);

    /// <summary>Creates a standalone, usable EC key pair (a stand-in for a bare Keychain key item).</summary>
    public static ECDsa CreateEcKey(ECCurve? curve = null) => ECDsa.Create(curve ?? ECCurve.NamedCurves.nistP256);

    /// <summary>Returns an independent copy of a certificate — mirrors what a real Keychain read returns.</summary>
    public static X509Certificate2 Copy(X509Certificate2 certificate) => new(certificate);

    /// <summary>Returns an independent copy of an RSA key, with private components intact.</summary>
    public static RSA Copy(RSA rsa)
    {
        var copy = RSA.Create();
        copy.ImportParameters(rsa.ExportParameters(includePrivateParameters: true));
        return copy;
    }

    /// <summary>Returns an independent copy of an EC key, with private components intact.</summary>
    public static ECDsa Copy(ECDsa ecdsa)
    {
        var copy = ECDsa.Create();
        copy.ImportParameters(ecdsa.ExportParameters(includePrivateParameters: true));
        return copy;
    }
}
