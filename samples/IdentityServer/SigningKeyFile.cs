using System.Runtime.Versioning;
using System.Security.AccessControl;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Security.Principal;

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

        // The framework refuses a key file anyone but its owner can read, so it is created that way —
        // never written first and tightened afterwards, which would leave the key briefly exposed.
        using var stream = OperatingSystem.IsWindows() ? CreateOwnerOnlyWindows(path) : CreateOwnerOnlyUnix(path);
        using var writer = new StreamWriter(stream);
        writer.Write(pem);

        return path;
    }

    [UnsupportedOSPlatform("windows")]
    private static FileStream CreateOwnerOnlyUnix(string path) =>
        new(path, new FileStreamOptions
        {
            Mode = FileMode.CreateNew,
            Access = FileAccess.Write,
            UnixCreateMode = UnixFileMode.UserRead | UnixFileMode.UserWrite,
        });

    // A protected ACL granting only the current user, so nothing is inherited from the folder —
    // an inherited Users or Authenticated Users rule would make the framework reject the file.
    [SupportedOSPlatform("windows")]
    private static FileStream CreateOwnerOnlyWindows(string path)
    {
        var security = new FileSecurity();
        security.SetAccessRuleProtection(isProtected: true, preserveInheritance: false);
        security.AddAccessRule(new FileSystemAccessRule(
            WindowsIdentity.GetCurrent().User!, FileSystemRights.FullControl, AccessControlType.Allow));

        return new FileInfo(path).Create(
            FileMode.CreateNew, FileSystemRights.Write, FileShare.None, bufferSize: 4096, FileOptions.None, security);
    }
}
