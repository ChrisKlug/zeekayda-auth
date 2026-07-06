using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace ZeeKayDa.Auth.Windows.Tests.Fixtures;

/// <summary>
/// Fabricates self-signed test certificates in memory, with a controllable <c>NotBefore</c>/
/// <c>NotAfter</c> and private-key presence — no real Windows Certificate Store needed, so rotation
/// and descriptor-building logic can be unit-tested on any OS.
/// </summary>
internal static class TestCertificateFactory
{
    public static X509Certificate2 CreateRsaSelfSigned(
        string subjectName, DateTimeOffset notBefore, DateTimeOffset notAfter,
        int keySizeBits = 2048, bool withPrivateKey = true)
    {
        using var rsa = RSA.Create(keySizeBits);
        var request = new CertificateRequest($"CN={subjectName}", rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        var certificate = request.CreateSelfSigned(notBefore, notAfter);

        return withPrivateKey ? certificate : StripPrivateKey(certificate);
    }

    public static X509Certificate2 CreateEcSelfSigned(
        string subjectName, DateTimeOffset notBefore, DateTimeOffset notAfter,
        ECCurve? curve = null, HashAlgorithmName? hashAlgorithm = null, bool withPrivateKey = true)
    {
        using var ecdsa = ECDsa.Create(curve ?? ECCurve.NamedCurves.nistP256);
        var request = new CertificateRequest($"CN={subjectName}", ecdsa, hashAlgorithm ?? HashAlgorithmName.SHA256);
        var certificate = request.CreateSelfSigned(notBefore, notAfter);

        return withPrivateKey ? certificate : StripPrivateKey(certificate);
    }

    /// <summary>Returns an independent copy of <paramref name="certificate"/> — mirrors what a real store read returns.</summary>
    public static X509Certificate2 Copy(X509Certificate2 certificate) => new(certificate);

    private static X509Certificate2 StripPrivateKey(X509Certificate2 certificateWithPrivateKey)
    {
        using (certificateWithPrivateKey)
        {
            return X509CertificateLoader.LoadCertificate(certificateWithPrivateKey.Export(X509ContentType.Cert));
        }
    }
}
