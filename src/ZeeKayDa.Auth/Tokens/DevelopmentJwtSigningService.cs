using System.Runtime.InteropServices;
using System.Runtime.Versioning;
using System.Security.Cryptography;
using Microsoft.Extensions.Options;

namespace ZeeKayDa.Auth.Tokens;

/// <summary>
/// A development-only <see cref="IJwtSigningService"/> that generates an ephemeral RSA key on
/// startup, with optional persistence to a local file so that tokens survive application restarts.
/// </summary>
/// <remarks>
/// <para>
/// This provider is not suitable for production. It is registered via
/// <c>AddDevelopmentJwtSigningKeys()</c>.
/// </para>
/// <para>
/// The environment gate (hard fail outside Development) and startup warning are enforced by
/// <c>DevelopmentSigningKeyWarningService</c> (an <c>IHostedService</c> registered alongside
/// this provider). This provider's only responsibility is loading the key material.
/// </para>
/// </remarks>
internal sealed class DevelopmentJwtSigningService
    : JwtSigningService<DevelopmentSigningKeyOptions>
{
    // Minimum RSA key size per NIST SP 800-57 Part 1 Rev. 5 §5.6.1 Table 2.
    private const int MinimumRsaKeySize = 3072;

    // Key file name within the persistence directory.
    private const string KeyFileName = "dev-signing-key.pem";

    private readonly IOptions<DevelopmentSigningKeyOptions> _devOptions;

    public DevelopmentJwtSigningService(
        IOptions<DevelopmentSigningKeyOptions> devOptions,
        TimeProvider timeProvider)
        : base(devOptions, timeProvider)
    {
        ArgumentNullException.ThrowIfNull(devOptions);
        _devOptions = devOptions;
    }

    /// <inheritdoc/>
    protected override ValueTask<SigningKeySet> LoadKeysAsync(CancellationToken cancellationToken)
    {
        var persistDir = _devOptions.Value.PersistToDirectory;
        var rsa = persistDir is not null
            ? LoadOrGeneratePersistedKey(persistDir)
            : GenerateEphemeralKey();

        var kid = ComputeKid(rsa);
        var rsaParams = rsa.ExportParameters(false);
        var descriptor = new SigningKeyDescriptor(kid, SigningAlgorithm.RS256, rsaParams);
        var entry = new SigningKeyEntry(descriptor, 0);
        var set = new SigningKeySet([entry], [rsa]);

        return ValueTask.FromResult(set);
    }

    private static RSA GenerateEphemeralKey() => RSA.Create(MinimumRsaKeySize);

    private static RSA LoadOrGeneratePersistedKey(string directory)
    {
        EnsureDirectorySafe(directory);

        var keyPath = Path.Combine(directory, KeyFileName);

        if (File.Exists(keyPath))
            return LoadKeyFromFile(keyPath);

        var rsa = RSA.Create(MinimumRsaKeySize);
        try
        {
            WriteKeyToFile(keyPath, rsa);
            return rsa;
        }
        catch
        {
            rsa.Dispose();
            throw;
        }
    }

    private static RSA LoadKeyFromFile(string keyPath)
    {
        ValidateNoSymlink(keyPath);

        if (!RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
            ValidateFilePermissions(keyPath);

        var pem = File.ReadAllText(keyPath);
        var rsa = RSA.Create();
        try
        {
            rsa.ImportFromPem(pem);
            return rsa;
        }
        catch
        {
            rsa.Dispose();
            throw;
        }
    }

    private static void WriteKeyToFile(string keyPath, RSA rsa)
    {
        var pem = rsa.ExportRSAPrivateKeyPem();

        if (RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
            WriteKeyFileWindows(keyPath, pem);
        else
            WriteKeyFileUnix(keyPath, pem);
    }

    [UnsupportedOSPlatform("windows")]
    private static void WriteKeyFileUnix(string keyPath, string pem)
    {
        // Create with 0600 atomically — no create-then-chmod window.
        var options = new FileStreamOptions
        {
            Mode = FileMode.CreateNew,
            Access = FileAccess.Write,
            Share = FileShare.None,
            Options = FileOptions.None,
            UnixCreateMode = UnixFileMode.UserRead | UnixFileMode.UserWrite,
        };

        using var stream = new FileStream(keyPath, options);
        using var writer = new StreamWriter(stream);
        writer.Write(pem);
    }

    [SupportedOSPlatform("windows")]
    private static void WriteKeyFileWindows(string keyPath, string pem)
    {
        // Write with default permissions, then apply restrictive ACL.
        File.WriteAllText(keyPath, pem);
        WindowsFilePermissions.SetRestrictiveAcl(keyPath);
    }

    private static void EnsureDirectorySafe(string directory)
    {
        if (RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
        {
            EnsureDirectorySafeWindows(directory);
        }
        else
        {
            EnsureDirectoryUnix(directory);
        }
    }

    [SupportedOSPlatform("windows")]
    private static void EnsureDirectorySafeWindows(string directory)
    {
        Directory.CreateDirectory(directory);
        WindowsFilePermissions.SetRestrictiveDirectoryAcl(directory);
    }

    [UnsupportedOSPlatform("windows")]
    private static void EnsureDirectoryUnix(string directory)
    {
        if (Directory.Exists(directory))
        {
            ValidateDirectoryPermissions(directory);
            return;
        }

        // Create with 0700 permissions.
        Directory.CreateDirectory(directory);

        var mode = UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute;
        File.SetUnixFileMode(directory, mode);
    }

    [UnsupportedOSPlatform("windows")]
    private static void ValidateDirectoryPermissions(string directory)
    {
        var mode = File.GetUnixFileMode(directory);

        var groupOrOtherBits =
            UnixFileMode.GroupRead | UnixFileMode.GroupWrite | UnixFileMode.GroupExecute
            | UnixFileMode.OtherRead | UnixFileMode.OtherWrite | UnixFileMode.OtherExecute;

        if ((mode & groupOrOtherBits) != 0)
        {
            throw new ZeeKayDaConfigurationException(
                new ZeeKayDaConfigurationFailure(
                    "signing.dev_keys.directory_too_permissive",
                    $"Signing key directory '{directory}' has permissions broader than 0700. " +
                    "This indicates the directory may be accessible by other users. " +
                    "Restrict permissions to 0700 (owner read/write/execute only) before proceeding."));
        }
    }

    [UnsupportedOSPlatform("windows")]
    private static void ValidateFilePermissions(string keyPath)
    {
        var mode = File.GetUnixFileMode(keyPath);

        var groupOrOtherBits =
            UnixFileMode.GroupRead | UnixFileMode.GroupWrite | UnixFileMode.GroupExecute
            | UnixFileMode.OtherRead | UnixFileMode.OtherWrite | UnixFileMode.OtherExecute;

        if ((mode & groupOrOtherBits) != 0)
        {
            throw new ZeeKayDaConfigurationException(
                new ZeeKayDaConfigurationFailure(
                    "signing.dev_keys.file_too_permissive",
                    $"Signing key file '{keyPath}' has permissions broader than 0600. " +
                    "The key file is treated as compromised. " +
                    "Delete the file and restart the application to generate a new key."));
        }
    }

    private static void ValidateNoSymlink(string keyPath)
    {
        var info = new FileInfo(keyPath);
        if (info.LinkTarget is not null)
        {
            throw new ZeeKayDaConfigurationException(
                new ZeeKayDaConfigurationFailure(
                    "signing.dev_keys.symlink_detected",
                    $"Signing key path '{keyPath}' resolves through a symlink. " +
                    "Symlinks are not permitted for key files to prevent redirect attacks. " +
                    "Remove the symlink and restart the application."));
        }
    }

    private static string ComputeKid(RSA rsa)
    {
        // Derive a stable kid from the public key's SHA-256 thumbprint (base64url-encoded).
        var publicKeyBytes = rsa.ExportSubjectPublicKeyInfo();
        var hash = SHA256.HashData(publicKeyBytes);
        return Convert.ToBase64String(hash)
            .TrimEnd('=')
            .Replace('+', '-')
            .Replace('/', '_');
    }
}
