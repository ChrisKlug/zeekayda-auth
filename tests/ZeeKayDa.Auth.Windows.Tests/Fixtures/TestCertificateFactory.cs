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

    /// <summary>
    /// Fabricates a certificate whose subject public key is neither RSA nor EC — an Ed25519 key,
    /// which .NET surfaces through neither <c>GetRSAPublicKey()</c> nor <c>GetECDsaPublicKey()</c>.
    /// The certificate is signed with a throwaway RSA key; only the subject key algorithm matters.
    /// </summary>
    public static X509Certificate2 CreateUnsupportedKeyTypeSelfSigned(
        string subjectName, DateTimeOffset notBefore, DateTimeOffset notAfter)
    {
        using var signingKey = RSA.Create(2048);
        var subject = new X500DistinguishedName($"CN={subjectName}");
        var ed25519PublicKey = new PublicKey(
            new Oid("1.3.101.112"), parameters: null, keyValue: new AsnEncodedData(new byte[32]));
        var request = new CertificateRequest(subject, ed25519PublicKey, HashAlgorithmName.SHA256);

        return request.Create(
            subject,
            X509SignatureGenerator.CreateForRSA(signingKey, RSASignaturePadding.Pkcs1),
            notBefore,
            notAfter,
            serialNumber: [1]);
    }

    /// <summary>
    /// Fabricates a DSA certificate <em>with</em> a private key. DSA is the one asymmetric algorithm
    /// .NET can attach to a certificate that neither <c>GetRSAPrivateKey()</c> nor
    /// <c>GetECDsaPrivateKey()</c> understands, so the result reports <c>HasPrivateKey = true</c>
    /// while both private-key accessors return <see langword="null"/> — the same shape a certificate
    /// whose CNG key ACL denies this process presents. The key is never used to sign anything, and
    /// 1024 bits is the only size every platform's DSA implementation will generate. macOS can import
    /// DSA keys but not generate them, so callers must skip there.
    /// </summary>
    public static X509Certificate2 CreateDsaSelfSigned(
        string subjectName, DateTimeOffset notBefore, DateTimeOffset notAfter)
    {
        using var signingKey = RSA.Create(2048);
        using var dsa = DSA.Create(1024);
        var subject = new X500DistinguishedName($"CN={subjectName}");
        var request = new CertificateRequest(subject, new PublicKey(dsa), HashAlgorithmName.SHA256);
        using var certificate = request.Create(
            subject,
            X509SignatureGenerator.CreateForRSA(signingKey, RSASignaturePadding.Pkcs1),
            notBefore,
            notAfter,
            serialNumber: [2]);

        return certificate.CopyWithPrivateKey(dsa);
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
