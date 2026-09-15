using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace ZeeKayDa.Auth.Samples.IdentityServer;

/// <summary>
/// Makes sure a PEM signing key exists, generating one on first run. A real deployment provisions
/// the file out of band; generating it here only keeps the sample runnable without setup.
/// </summary>
public static class SigningKeyFile
{
    public static string Ensure(string path)
    {
        if (File.Exists(path))
            return path;

        Directory.CreateDirectory(Path.GetDirectoryName(Path.GetFullPath(path))!);

        using var rsa = RSA.Create(2048);
        var request = new CertificateRequest(
            "CN=ZeeKayDa sample signing key", rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        using var certificate = request.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddYears(1));

        var pem = certificate.ExportCertificatePem() + Environment.NewLine + rsa.ExportPkcs8PrivateKeyPem();

        // The framework refuses a key file anyone but its owner can read, so it is created that way
        // rather than tightened afterwards.
        var options = new FileStreamOptions { Mode = FileMode.CreateNew, Access = FileAccess.Write };
        if (!OperatingSystem.IsWindows())
            options.UnixCreateMode = UnixFileMode.UserRead | UnixFileMode.UserWrite;

        using var stream = new FileStream(path, options);
        using var writer = new StreamWriter(stream);
        writer.Write(pem);

        return path;
    }
}
