using System.Security.Cryptography;
using System.Security.Cryptography.Pkcs;
using System.Security.Cryptography.X509Certificates;

namespace ZeeKayDa.Auth.FileSystem.Tests.Fixtures;

/// <summary>
/// Hand-builds PKCS#12 bundles in shapes a real exporter can produce but the convenience APIs never
/// do, so the read path can be tested against them.
/// </summary>
/// <remarks>
/// Every shape here is legal PKCS#12. <c>X509Certificate2.Export</c> only ever emits one — a single
/// certificate, MAC-protected, in an encrypted safe — so a bundle carrying a chain, or one whose
/// certificate safe is unencrypted, cannot be produced with it. <see cref="Pkcs12Builder"/> is how a
/// test reaches the cases an operator's own tooling can hand the provider.
/// </remarks>
internal static class AdversarialPkcs12Factory
{
    private static readonly PbeParameters Pbe =
        new(PbeEncryptionAlgorithm.Aes256Cbc, HashAlgorithmName.SHA256, 100_000);

    /// <summary>
    /// A bundle whose chain certificate is stored <em>before</em> the signing certificate, with the
    /// signing certificate paired to the key by <c>localKeyId</c>. PKCS#12 imposes no bag ordering,
    /// so "the first certificate in the file" is not the one that signs.
    /// </summary>
    /// <returns>The bundle, and the subject name of the certificate that actually signs.</returns>
    public static (byte[] Bundle, string SigningSubject, RSAParameters SigningPublicKey) ChainCertificateFirst(
        string password, DateTimeOffset notBefore, DateTimeOffset notAfter)
    {
        using var caKey = RSA.Create(2048);
        var caRequest = new CertificateRequest(
            "CN=test-chain-ca", caKey, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        caRequest.CertificateExtensions.Add(new X509BasicConstraintsExtension(true, false, 0, true));
        using var ca = caRequest.CreateSelfSigned(notBefore.AddDays(-1), notAfter.AddDays(1));
        using var caPublicOnly = X509CertificateLoader.LoadCertificate(ca.Export(X509ContentType.Cert));

        using var leafKey = RSA.Create(2048);
        var leafRequest = new CertificateRequest(
            "CN=test-signing-leaf", leafKey, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        leafRequest.CertificateExtensions.Add(new X509BasicConstraintsExtension(false, false, 0, true));
        using var leaf = leafRequest.Create(ca, notBefore, notAfter, [1, 2, 3, 4]);

        var localKeyId = new byte[] { 0xAA, 0xBB };

        var certificates = new Pkcs12SafeContents();
        certificates.AddCertificate(caPublicOnly);
        certificates.AddCertificate(leaf).Attributes.Add(new Pkcs9LocalKeyId(localKeyId));

        var keys = new Pkcs12SafeContents();
        keys.AddShroudedKey(leafKey, password, Pbe).Attributes.Add(new Pkcs9LocalKeyId(localKeyId));

        var builder = new Pkcs12Builder();
        builder.AddSafeContentsEncrypted(certificates, password, Pbe);
        builder.AddSafeContentsUnencrypted(keys);
        builder.SealWithMac(password, HashAlgorithmName.SHA256, 100_000);

        return (builder.Encode(), "CN=test-signing-leaf", leafKey.ExportParameters(false));
    }

    /// <summary>
    /// A bundle whose certificate safe is <em>unencrypted</em> while its key bag is shrouded, sealed
    /// with a MAC under <paramref name="macPassword"/>. Reaching the certificate needs no password at
    /// all, so only the MAC can tell whether the file is the one the operator configured.
    /// </summary>
    public static byte[] UnencryptedCertificateSafe(
        string macPassword, string subjectName, DateTimeOffset notBefore, DateTimeOffset notAfter)
    {
        using var key = RSA.Create(2048);
        var request = new CertificateRequest(
            $"CN={subjectName}", key, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        using var certificate = request.CreateSelfSigned(notBefore, notAfter);

        var localKeyId = new byte[] { 0x01 };

        var certificates = new Pkcs12SafeContents();
        certificates.AddCertificate(certificate).Attributes.Add(new Pkcs9LocalKeyId(localKeyId));

        var keys = new Pkcs12SafeContents();
        keys.AddShroudedKey(key, macPassword, Pbe).Attributes.Add(new Pkcs9LocalKeyId(localKeyId));

        var builder = new Pkcs12Builder();
        builder.AddSafeContentsUnencrypted(certificates);
        builder.AddSafeContentsUnencrypted(keys);
        builder.SealWithMac(macPassword, HashAlgorithmName.SHA256, 100_000);

        return builder.Encode();
    }

    /// <summary>
    /// A bundle sealed with no MAC at all, so nothing in it can be authenticated against a password.
    /// </summary>
    public static byte[] NoIntegrityProtection(
        string subjectName, DateTimeOffset notBefore, DateTimeOffset notAfter)
    {
        using var key = RSA.Create(2048);
        var request = new CertificateRequest(
            $"CN={subjectName}", key, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        using var certificate = request.CreateSelfSigned(notBefore, notAfter);

        var certificates = new Pkcs12SafeContents();
        certificates.AddCertificate(certificate);

        var builder = new Pkcs12Builder();
        builder.AddSafeContentsUnencrypted(certificates);
        builder.SealWithoutIntegrity();

        return builder.Encode();
    }

    /// <summary>
    /// A bundle carrying two complete keypairs, each certificate paired to its own key. Both are
    /// legitimately "the certificate with a key", so which one signs is genuinely ambiguous.
    /// </summary>
    public static byte[] TwoPairedKeypairs(
        string password, DateTimeOffset notBefore, DateTimeOffset notAfter)
    {
        var certificates = new Pkcs12SafeContents();
        var keys = new Pkcs12SafeContents();

        foreach (var (subject, id) in new[] { ("first", (byte)0x01), ("second", (byte)0x02) })
        {
            using var key = RSA.Create(2048);
            using var certificate = new CertificateRequest(
                $"CN={subject}", key, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1)
                .CreateSelfSigned(notBefore, notAfter);

            certificates.AddCertificate(certificate).Attributes.Add(new Pkcs9LocalKeyId([id]));
            keys.AddShroudedKey(key, password, Pbe).Attributes.Add(new Pkcs9LocalKeyId([id]));
        }

        var builder = new Pkcs12Builder();
        builder.AddSafeContentsEncrypted(certificates, password, Pbe);
        builder.AddSafeContentsUnencrypted(keys);
        builder.SealWithMac(password, HashAlgorithmName.SHA256, 100_000);

        return builder.Encode();
    }

    /// <summary>
    /// A bundle holding one certificate, whose key bag carries a <c>localKeyId</c> the certificate
    /// does not. A lone certificate is unambiguous regardless.
    /// </summary>
    public static byte[] SingleCertificateWithUnmatchedKeyId(
        string password, DateTimeOffset notBefore, DateTimeOffset notAfter)
    {
        using var key = RSA.Create(2048);
        using var certificate = new CertificateRequest(
            "CN=unmatched-key-id", key, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1)
            .CreateSelfSigned(notBefore, notAfter);

        var certificates = new Pkcs12SafeContents();
        certificates.AddCertificate(certificate);

        var keys = new Pkcs12SafeContents();
        keys.AddShroudedKey(key, password, Pbe).Attributes.Add(new Pkcs9LocalKeyId([0x99]));

        var builder = new Pkcs12Builder();
        builder.AddSafeContentsEncrypted(certificates, password, Pbe);
        builder.AddSafeContentsUnencrypted(keys);
        builder.SealWithMac(password, HashAlgorithmName.SHA256, 100_000);

        return builder.Encode();
    }

    /// <summary>
    /// The shape <c>openssl pkcs12 -export -nokeys</c> produces for a chain: no key bag at all, the
    /// issuer's certificate unmarked, and the leaf carrying the <c>localKeyId</c> of the key that was
    /// stripped. The right shape for a published-only slot.
    /// </summary>
    /// <returns>The bundle, and the public key of the certificate that should be selected.</returns>
    public static (byte[] Bundle, RSAParameters ExpectedPublicKey) CertificateOnlyChainWithMarkedLeaf(
        string password, DateTimeOffset notBefore, DateTimeOffset notAfter)
    {
        var (ca, leaf, leafKey) = BuildChain(notBefore, notAfter);
        using (ca)
        using (leaf)
        using (leafKey)
        {
            var certificates = new Pkcs12SafeContents();
            certificates.AddCertificate(ca);
            certificates.AddCertificate(leaf).Attributes.Add(new Pkcs9LocalKeyId([0xAA]));

            var builder = new Pkcs12Builder();
            builder.AddSafeContentsEncrypted(certificates, password, Pbe);
            builder.SealWithMac(password, HashAlgorithmName.SHA256, 100_000);

            return (builder.Encode(), leafKey.ExportParameters(false));
        }
    }

    /// <summary>
    /// A bundle that does hold a private key, unmarked, alongside a marked <em>chain</em> certificate
    /// — so the marked certificate is not the one the key belongs to. Selecting on the mark alone
    /// would publish the issuer's key while the signer opens the leaf's.
    /// </summary>
    public static byte[] UnmarkedKeyBagWithMarkedChainCertificate(
        string password, DateTimeOffset notBefore, DateTimeOffset notAfter)
    {
        var (ca, leaf, leafKey) = BuildChain(notBefore, notAfter);
        using (ca)
        using (leaf)
        using (leafKey)
        {
            var certificates = new Pkcs12SafeContents();
            certificates.AddCertificate(ca).Attributes.Add(new Pkcs9LocalKeyId([0xAA]));
            certificates.AddCertificate(leaf);

            var keys = new Pkcs12SafeContents();
            keys.AddShroudedKey(leafKey, password, Pbe);

            var builder = new Pkcs12Builder();
            builder.AddSafeContentsEncrypted(certificates, password, Pbe);
            builder.AddSafeContentsUnencrypted(keys);
            builder.SealWithMac(password, HashAlgorithmName.SHA256, 100_000);

            return builder.Encode();
        }
    }

    /// <summary>
    /// A bundle whose key bag names a <c>localKeyId</c> no certificate carries, with more than one
    /// certificate present — so the key's own certificate is not in the file.
    /// </summary>
    public static byte[] KeyIdMatchingNoCertificate(
        string password, DateTimeOffset notBefore, DateTimeOffset notAfter)
    {
        var (ca, leaf, leafKey) = BuildChain(notBefore, notAfter);
        using (ca)
        using (leaf)
        using (leafKey)
        {
            var certificates = new Pkcs12SafeContents();
            certificates.AddCertificate(ca);
            certificates.AddCertificate(leaf);

            var keys = new Pkcs12SafeContents();
            keys.AddShroudedKey(leafKey, password, Pbe).Attributes.Add(new Pkcs9LocalKeyId([0xFE]));

            var builder = new Pkcs12Builder();
            builder.AddSafeContentsEncrypted(certificates, password, Pbe);
            builder.AddSafeContentsUnencrypted(keys);
            builder.SealWithMac(password, HashAlgorithmName.SHA256, 100_000);

            return builder.Encode();
        }
    }

    private static (X509Certificate2 Ca, X509Certificate2 Leaf, RSA LeafKey) BuildChain(
        DateTimeOffset notBefore, DateTimeOffset notAfter)
    {
        using var caKey = RSA.Create(2048);
        var caRequest = new CertificateRequest(
            "CN=test-chain-ca", caKey, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        caRequest.CertificateExtensions.Add(new X509BasicConstraintsExtension(true, false, 0, true));
        using var caWithKey = caRequest.CreateSelfSigned(notBefore.AddDays(-1), notAfter.AddDays(1));
        var ca = X509CertificateLoader.LoadCertificate(caWithKey.Export(X509ContentType.Cert));

        var leafKey = RSA.Create(2048);
        var leafRequest = new CertificateRequest(
            "CN=test-signing-leaf", leafKey, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        leafRequest.CertificateExtensions.Add(new X509BasicConstraintsExtension(false, false, 0, true));
        var leaf = leafRequest.Create(caWithKey, notBefore, notAfter, [1, 2, 3, 4]);

        return (ca, leaf, leafKey);
    }

    /// <summary>
    /// A bundle carrying two certificates and no key bag, so nothing identifies which one signs.
    /// </summary>
    public static byte[] TwoCertificatesNoKey(
        string password, DateTimeOffset notBefore, DateTimeOffset notAfter)
    {
        using var firstKey = RSA.Create(2048);
        using var first = new CertificateRequest("CN=first", firstKey, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1)
            .CreateSelfSigned(notBefore, notAfter);
        using var secondKey = RSA.Create(2048);
        using var second = new CertificateRequest("CN=second", secondKey, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1)
            .CreateSelfSigned(notBefore, notAfter);

        var certificates = new Pkcs12SafeContents();
        certificates.AddCertificate(first);
        certificates.AddCertificate(second);

        var builder = new Pkcs12Builder();
        builder.AddSafeContentsEncrypted(certificates, password, Pbe);
        builder.SealWithMac(password, HashAlgorithmName.SHA256, 100_000);

        return builder.Encode();
    }
}
