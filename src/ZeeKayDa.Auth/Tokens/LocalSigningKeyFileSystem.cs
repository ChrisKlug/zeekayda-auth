using System.Diagnostics.CodeAnalysis;
using System.Runtime.InteropServices;
using System.Runtime.Versioning;
using System.Security.AccessControl;
using System.Security.Principal;

namespace ZeeKayDa.Auth.Tokens;

/// <summary>
/// Stores the persisted development signing key with .NET's own file APIs: owner-only on creation,
/// and refused on read if it is a symlink or, on Unix, if its mode lets anyone else reach it.
/// </summary>
/// <remarks>
/// The key only works in <c>Development</c>, so this protects a local key on a developer machine.
/// It does not walk ancestor directories for foreign owners or symlinks; the production file
/// provider in <c>ZeeKayDa.Auth.FileSystem</c> does. On Windows the ACL is set at creation and not
/// re-checked on read.
/// </remarks>
internal sealed class LocalSigningKeyFileSystem : IDevelopmentSigningKeyFileSystem
{
    // Generating and writing one key takes well under a second; a lock held this long is not a
    // host taking its turn, and failing beats waiting forever.
    private static readonly TimeSpan LockTimeout = TimeSpan.FromSeconds(30);

    private static readonly TimeSpan LockRetryInterval = TimeSpan.FromMilliseconds(50);

    private const UnixFileMode GroupOrOtherBits =
        UnixFileMode.GroupRead | UnixFileMode.GroupWrite | UnixFileMode.GroupExecute
        | UnixFileMode.OtherRead | UnixFileMode.OtherWrite | UnixFileMode.OtherExecute;

    /// <inheritdoc/>
    public void EnsureDirectorySafe(string directory)
    {
        if (RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
            EnsureDirectorySafeWindows(directory);
        else
            EnsureDirectorySafeUnix(directory);
    }

    /// <inheritdoc/>
    public async ValueTask<bool> WriteKeyFileAsync(string keyPath, ReadOnlyMemory<char> pem, CancellationToken cancellationToken)
    {
        // Hosts sharing the folder take turns on a lock file beside the key, and check for a key
        // under it, so exactly one creates the key: on Unix File.Move's no-overwrite is a check then
        // a rename, which two hosts can both pass.
        await using var turn = await TakeTurnAsync(keyPath + ".lock", cancellationToken).ConfigureAwait(false);
        if (File.Exists(keyPath))
            return false;

        // Written beside the key and renamed into place, so a host loading the key never reads a
        // half-written file.
        var pending = Path.Join(
            Path.GetDirectoryName(Path.GetFullPath(keyPath)),
            $"{Path.GetFileName(keyPath)}.{Path.GetRandomFileName()}.pending");
        try
        {
            if (RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
                await WriteKeyFileWindowsAsync(pending, pem, cancellationToken).ConfigureAwait(false);
            else
                await WriteKeyFileUnixAsync(pending, pem, cancellationToken).ConfigureAwait(false);

            return PublishPending(pending, keyPath);
        }
        finally
        {
            File.Delete(pending);
        }
    }

    /// <summary>
    /// The step that moves a fully written pending file to the key's name. Replaceable by tests only,
    /// so they can see the pending file at the instant it is published rather than after the fact.
    /// </summary>
    internal Func<string, string, bool> PublishPending { get; init; } = Publish;

    /// <summary>
    /// Opens <paramref name="lockPath"/> exclusively, waiting while another host holds it. An
    /// exclusive open is an <c>flock</c> on Unix and a share mode on Windows, so it excludes other
    /// processes as well as other threads. The file is never deleted: a host deleting it while
    /// another waits would let a third open a fresh one alongside.
    /// </summary>
    private static async Task<FileStream> TakeTurnAsync(string lockPath, CancellationToken cancellationToken)
    {
        var deadline = DateTime.UtcNow + LockTimeout;
        while (true)
        {
            try
            {
                return RuntimeInformation.IsOSPlatform(OSPlatform.Windows)
                    ? new FileStream(lockPath, FileMode.OpenOrCreate, FileAccess.ReadWrite, FileShare.None)
                    : OpenLockUnix(lockPath);
            }
            catch (IOException) when (DateTime.UtcNow < deadline)
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

    // Internal rather than private so the losing half of the race can be driven directly,
    // without depending on thread scheduling to produce it.
    internal static bool Publish(string pending, string keyPath)
    {
        try
        {
            File.Move(pending, keyPath, overwrite: false);
            return true;
        }
        catch (IOException) when (File.Exists(keyPath))
        {
            return false;
        }
    }

    /// <inheritdoc/>
    public async ValueTask<KeyFileContent> ReadKeyFileAsync(string keyPath, CancellationToken cancellationToken)
    {
        // The mode is checked on the open handle, so the file checked is the file read. The symlink
        // check re-reads the path, which leaves a window a swapped link could pass: the BCL has no
        // O_NOFOLLOW to close it.
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

    /// <inheritdoc/>
    public bool FileExists(string path) => File.Exists(path);

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
    /// Creates <paramref name="directory"/> and every missing component above it as <c>0700</c>.
    /// </summary>
    /// <remarks>
    /// Not a bare <c>Directory.CreateDirectory</c>: that applies the umask to every component, and
    /// its <c>UnixFileMode</c> overload modes only the last one. Created one component at a time
    /// with the mode, none of them ever exists at the umask.
    /// </remarks>
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
