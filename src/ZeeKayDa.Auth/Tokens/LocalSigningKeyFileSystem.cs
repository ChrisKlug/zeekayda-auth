using System.Diagnostics;
using System.Diagnostics.CodeAnalysis;
using System.Runtime.InteropServices;
using System.Runtime.Versioning;
using System.Security.AccessControl;
using System.Security.Principal;

namespace ZeeKayDa.Auth.Tokens;

/// <summary>Stores the development signing key owner-only, refusing a symlink or, on Unix, a broader mode on read.</summary>
/// <remarks>
/// Protects a local key on a developer machine only: no ancestor walk, and no ACL re-check on Windows.
/// </remarks>
internal sealed class LocalSigningKeyFileSystem : IDevelopmentSigningKeyFileSystem
{
    private static readonly TimeSpan LockRetryInterval = TimeSpan.FromMilliseconds(50);

    private const UnixFileMode GroupOrOtherBits =
        UnixFileMode.GroupRead | UnixFileMode.GroupWrite | UnixFileMode.GroupExecute
        | UnixFileMode.OtherRead | UnixFileMode.OtherWrite | UnixFileMode.OtherExecute;

    /// <inheritdoc/>
    public void EnsureDirectorySafe(string directory)
    {
        var createsDirectory = !Directory.Exists(directory);

        if (RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
            EnsureDirectorySafeWindows(directory);
        else
            EnsureDirectorySafeUnix(directory);

        // The default directory sits under the content root, inside the host's source tree. A
        // directory the host made is the host's to manage, so only one created here is marked.
        if (createsDirectory)
            IgnoreContentsInGit(directory);
    }

    /// <summary>How long a host waits for the lock before failing; a lock held this long is not a host taking its turn.</summary>
    internal TimeSpan LockTimeout { get; init; } = TimeSpan.FromSeconds(30);

    /// <inheritdoc/>
    public async ValueTask WriteKeyFileAsync(string keyPath, ReadOnlyMemory<char> pem, CancellationToken cancellationToken)
    {
        // Exactly one host creates the key: on Unix File.Move's no-overwrite is a check then a rename,
        // which two hosts can both pass.
        await using var turn = await TakeTurnAsync(keyPath + ".lock", cancellationToken).ConfigureAwait(false);

        // Refused before anything is written: File.Exists reports a dangling symlink as present on
        // Unix and a directory as absent, so neither would otherwise get a useful error.
        if (Directory.Exists(keyPath) || new FileInfo(keyPath).LinkTarget is not null)
        {
            throw new ZeeKayDaConfigurationException(
                new ZeeKayDaConfigurationFailure(
                    "signing.dev_keys.key_path_not_a_file",
                    $"Signing key path '{keyPath}' is a directory or a symlink, not a key file. " +
                    "Remove it and restart the application to generate a new key."));
        }

        if (File.Exists(keyPath))
            return;

        // Renamed into place, so no host reads a half-written key.
        var pending = Path.Join(
            Path.GetDirectoryName(Path.GetFullPath(keyPath)),
            $"{Path.GetFileName(keyPath)}.{Path.GetRandomFileName()}.pending");
        try
        {
            if (RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
                await WriteKeyFileWindowsAsync(pending, pem, cancellationToken).ConfigureAwait(false);
            else
                await WriteKeyFileUnixAsync(pending, pem, cancellationToken).ConfigureAwait(false);

            PublishPending(pending, keyPath);
        }
        finally
        {
            File.Delete(pending);
        }
    }

    /// <summary>Moves the written pending file to the key's name; replaced by tests to observe that instant.</summary>
    internal Action<string, string> PublishPending { get; init; } = Publish;

    /// <summary>
    /// Opens <paramref name="lockPath"/> exclusively, across processes, waiting while another host holds it.
    /// Never deleted: deleting it while another waits would let a third open a fresh one.
    /// </summary>
    private async Task<FileStream> TakeTurnAsync(string lockPath, CancellationToken cancellationToken)
    {
        var waited = Stopwatch.StartNew();
        while (true)
        {
            try
            {
                return RuntimeInformation.IsOSPlatform(OSPlatform.Windows)
                    ? new FileStream(lockPath, FileMode.OpenOrCreate, FileAccess.ReadWrite, FileShare.None)
                    : OpenLockUnix(lockPath);
            }
            catch (IOException ex) when (waited.Elapsed >= LockTimeout)
            {
                throw new ZeeKayDaConfigurationException(
                    new ZeeKayDaConfigurationFailure(
                        "signing.dev_keys.lock_timeout",
                        $"Could not take the signing key lock '{lockPath}' within {LockTimeout.TotalSeconds:0} seconds. " +
                        "Another process may be holding it, or the file cannot be opened. " +
                        "Stop other hosts sharing the key folder, check the file's permissions, and restart."),
                    ex);
            }
            catch (IOException)
            {
                await Task.Delay(LockRetryInterval, cancellationToken).ConfigureAwait(false);
            }
        }
    }

    // Owner-only like every other file here, though it holds nothing: on Windows it inherits the
    // folder's owner-only ACL, and on Unix the mode is set at creation.
    [UnsupportedOSPlatform("windows")]
    private static FileStream OpenLockUnix(string lockPath) =>
        new(lockPath, new FileStreamOptions
        {
            Mode = FileMode.OpenOrCreate,
            Access = FileAccess.ReadWrite,
            Share = FileShare.None,
            UnixCreateMode = UnixFileMode.UserRead | UnixFileMode.UserWrite,
        });

    // Internal so a test can drive the losing half of the race directly.
    internal static void Publish(string pending, string keyPath)
    {
        try
        {
            File.Move(pending, keyPath, overwrite: false);
        }
        catch (IOException) when (File.Exists(keyPath))
        {
            // Another host's key is already there; it stays, and this one is discarded.
        }
    }

    /// <inheritdoc/>
    public async ValueTask<KeyFileContent> ReadKeyFileAsync(string keyPath, CancellationToken cancellationToken)
    {
        // The mode is checked on the open handle; the symlink check re-reads the path, a window the BCL
        // has no O_NOFOLLOW to close.
        using var stream = File.Open(keyPath, FileMode.Open, FileAccess.Read, FileShare.Read);

        if (new FileInfo(stream.Name).LinkTarget is not null)
        {
            throw new ZeeKayDaConfigurationException(
                new ZeeKayDaConfigurationFailure(
                    "signing.dev_keys.symlink_detected",
                    $"Signing key path '{stream.Name}' is a symlink. " +
                    "Symlinks are not permitted for key files to prevent redirect attacks. " +
                    "Remove the symlink and restart the application."));
        }

        if (!RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
            ValidateFilePermissionsUnix(stream, keyPath);

        var bytes = new byte[stream.Length];
        await stream.ReadExactlyAsync(bytes, cancellationToken).ConfigureAwait(false);
        return new KeyFileContent(bytes);
    }

    // File.Exists alone reports a dangling symlink as present on Unix, which would send the caller to
    // load a key that is not there instead of to the write that refuses the link by name.
    /// <inheritdoc/>
    public bool FileExists(string path) =>
        File.Exists(path) && new FileInfo(path).ResolveLinkTarget(returnFinalTarget: true) is null or { Exists: true };

    private static void IgnoreContentsInGit(string directory)
    {
        var ignoreFile = Path.Join(directory, ".gitignore");
        try
        {
            using var stream = new FileStream(ignoreFile, FileMode.CreateNew, FileAccess.Write, FileShare.None);
            stream.Write("*\n"u8);
        }
        catch (IOException) when (File.Exists(ignoreFile))
        {
            // Another host created the directory at the same moment and wrote it first.
        }
    }

    [ExcludeFromCodeCoverage(Justification = "Windows-only, so unreachable on the Linux runner whose coverage artifact feeds the regression gate. LocalSigningKeyFileSystemTests covers this on the windows-latest runner.")]
    [SupportedOSPlatform("windows")]
    private static void EnsureDirectorySafeWindows(string directory)
    {
        Directory.CreateDirectory(directory);
        ApplyRestrictiveDirectoryAclWindows(directory);
    }

    [UnsupportedOSPlatform("windows")]
    private static void EnsureDirectorySafeUnix(string directory)
    {
        var fullPath = Path.GetFullPath(directory);

        // Checked after creating too: a directory someone else made between the existence check
        // and mkdir is left as they made it, and must pass the same rule as one that already existed.
        if (!Directory.Exists(fullPath))
            CreateDirectoryChainOwnerOnlyUnix(fullPath);

        if ((File.GetUnixFileMode(fullPath) & GroupOrOtherBits) != 0)
        {
            throw new ZeeKayDaConfigurationException(
                new ZeeKayDaConfigurationFailure(
                    "signing.dev_keys.directory_too_permissive",
                    $"Signing key directory '{fullPath}' has permissions broader than 0700. " +
                    "This indicates the directory may be accessible by other users. " +
                    "Restrict permissions to 0700 (owner read/write/execute only) before proceeding."));
        }
    }

    /// <summary>
    /// Creates <paramref name="directory"/> and its missing parents as <c>0700</c>, one at a time, since
    /// <c>Directory.CreateDirectory</c> modes only the last component.
    /// </summary>
    [UnsupportedOSPlatform("windows")]
    private static void CreateDirectoryChainOwnerOnlyUnix(string directory)
    {
        var missing = new List<string>();

        for (var current = directory; !string.IsNullOrEmpty(current); current = Path.GetDirectoryName(current))
        {
            if (Directory.Exists(current))
                break;

            missing.Add(current);
        }

        // Deepest-last, so each parent exists before its child is created.
        missing.Reverse();

        var ownerOnly = UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute;
        foreach (var component in missing)
            Directory.CreateDirectory(component, ownerOnly);
    }

    [ExcludeFromCodeCoverage(Justification = "Windows-only, so unreachable on the Linux runner whose coverage artifact feeds the regression gate. LocalSigningKeyFileSystemTests covers this on the windows-latest runner.")]
    [SupportedOSPlatform("windows")]
    private static async ValueTask WriteKeyFileWindowsAsync(string keyPath, ReadOnlyMemory<char> pem, CancellationToken cancellationToken)
    {
        await using var stream = new FileStream(keyPath, FileMode.CreateNew, FileAccess.Write, FileShare.None, bufferSize: 4096, useAsync: true);
        await using var writer = new StreamWriter(stream);
        await writer.WriteAsync(pem, cancellationToken).ConfigureAwait(false);
        ApplyRestrictiveFileAclWindows(keyPath);
    }

    [UnsupportedOSPlatform("windows")]
    private static async ValueTask WriteKeyFileUnixAsync(string keyPath, ReadOnlyMemory<char> pem, CancellationToken cancellationToken)
    {
        // 0600 applied atomically at creation — no create-then-chmod window.
        var options = new FileStreamOptions
        {
            Mode = FileMode.CreateNew,
            Access = FileAccess.Write,
            Share = FileShare.None,
            Options = FileOptions.Asynchronous,
            UnixCreateMode = UnixFileMode.UserRead | UnixFileMode.UserWrite,
        };

        await using var stream = new FileStream(keyPath, options);
        await using var writer = new StreamWriter(stream);
        await writer.WriteAsync(pem, cancellationToken).ConfigureAwait(false);
    }

    [UnsupportedOSPlatform("windows")]
    private static void ValidateFilePermissionsUnix(FileStream stream, string keyPath)
    {
        if ((File.GetUnixFileMode(stream.SafeFileHandle) & GroupOrOtherBits) != 0)
        {
            throw new ZeeKayDaConfigurationException(
                new ZeeKayDaConfigurationFailure(
                    "signing.dev_keys.file_too_permissive",
                    $"Signing key file '{keyPath}' has permissions broader than 0600. " +
                    "The key file is treated as compromised. " +
                    "Delete the file and restart the application to generate a new key."));
        }
    }

    [ExcludeFromCodeCoverage(Justification = "Windows-only, so unreachable on the Linux runner whose coverage artifact feeds the regression gate. LocalSigningKeyFileSystemTests covers this on the windows-latest runner.")]
    [SupportedOSPlatform("windows")]
    private static void ApplyRestrictiveFileAclWindows(string filePath)
    {
        var security = new FileSecurity();
        security.SetAccessRuleProtection(isProtected: true, preserveInheritance: false);

        var currentUser = WindowsIdentity.GetCurrent().User!;
        security.AddAccessRule(new FileSystemAccessRule(
            currentUser,
            FileSystemRights.FullControl,
            AccessControlType.Allow));

        new FileInfo(filePath).SetAccessControl(security);
    }

    [ExcludeFromCodeCoverage(Justification = "Windows-only, so unreachable on the Linux runner whose coverage artifact feeds the regression gate. LocalSigningKeyFileSystemTests covers this on the windows-latest runner.")]
    [SupportedOSPlatform("windows")]
    private static void ApplyRestrictiveDirectoryAclWindows(string directoryPath)
    {
        var security = new DirectorySecurity();
        security.SetAccessRuleProtection(isProtected: true, preserveInheritance: false);

        var currentUser = WindowsIdentity.GetCurrent().User!;
        security.AddAccessRule(new FileSystemAccessRule(
            currentUser,
            FileSystemRights.FullControl,
            InheritanceFlags.ContainerInherit | InheritanceFlags.ObjectInherit,
            PropagationFlags.None,
            AccessControlType.Allow));

        new DirectoryInfo(directoryPath).SetAccessControl(security);
    }
}
