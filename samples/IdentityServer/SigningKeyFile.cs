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

        // The folder is owner-only too: anyone who could write to it could swap the key before a restart.
        var directory = Path.GetDirectoryName(Path.GetFullPath(path))!;
        if (!Directory.Exists(directory))
        {
            if (OperatingSystem.IsWindows())
                CreateOwnerOnlyDirectoryWindows(directory);
            else
                CreateOwnerOnlyDirectoryUnix(directory);
        }

        // Written beside the key and renamed into place, because more than one host can start at
        // once and the check above is not a lock. A rename is atomic, so a racing host sees either
        // no key or a whole one — never the empty file a plain create-then-write leaves behind.
        var pending = Path.Join(directory, Path.GetRandomFileName());
        try
        {
            WriteNewKey(pending);
            Publish(pending, path);
        }
        finally
        {
            File.Delete(pending);
        }

        return path;
    }

    private static void WriteNewKey(string path)
    {
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
    }

    // Internal rather than private so the losing half of the race can be driven directly,
    // without depending on thread scheduling to produce it.
    internal static void Publish(string pending, string path)
    {
        try
        {
            File.Move(pending, path, overwrite: false);
        }
        catch (IOException) when (File.Exists(path))
        {
            // Another host got there first. Its key is complete and owner-only, so it is the key;
            // ours is discarded, and both hosts sign with the same one.
        }
    }

    [UnsupportedOSPlatform("windows")]
    private static void CreateOwnerOnlyDirectoryUnix(string directory) =>
        Directory.CreateDirectory(directory, UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute);

    [SupportedOSPlatform("windows")]
    private static void CreateOwnerOnlyDirectoryWindows(string directory)
    {
        var security = new DirectorySecurity();
        security.SetAccessRuleProtection(isProtected: true, preserveInheritance: false);
        security.AddAccessRule(new FileSystemAccessRule(
            WindowsIdentity.GetCurrent().User!,
            FileSystemRights.FullControl,
            InheritanceFlags.ContainerInherit | InheritanceFlags.ObjectInherit,
            PropagationFlags.None,
            AccessControlType.Allow));

        new DirectoryInfo(directory).Create(security);
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
