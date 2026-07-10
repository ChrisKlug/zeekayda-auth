using System.Diagnostics.CodeAnalysis;
using System.Runtime.InteropServices;
using System.Runtime.Versioning;
using System.Security.AccessControl;
using System.Security.Principal;

namespace ZeeKayDa.Auth.Tokens;

/// <summary>
/// Provides interop access to <c>getuid()</c>, <c>stat()</c>, and <c>lstat()</c> for directory
/// ownership validation on Unix platforms.
/// </summary>
/// <remarks>
/// <para>
/// The current process UID from <c>getuid()</c> is compared against the directory owner UID
/// obtained from <c>stat()</c> (<see cref="GetOwnerUid"/>) to detect attacker-controlled
/// directories that pass the <c>0700</c> permission check but are owned by a different user.
/// <see cref="GetLinkOwnerUid"/> uses <c>lstat()</c> instead wherever a path component might
/// itself be a symlink and the owner of the *link entry*, not whatever it points at, is the
/// signal needed — see its own remarks for why the distinction is security-critical.
/// </para>
/// <para>
/// Two native stat structs are declared — one for macOS/BSD and one for Linux 64-bit — because
/// the kernel ABI differs between platforms. Only the fields up to <c>st_uid</c> are bound;
/// the remainder of each struct is covered by blittable scalar padding sized to the full struct
/// on each OS. The same structs back both the <c>stat()</c> and <c>lstat()</c> bindings, since
/// both syscalls fill an identical <c>struct stat</c> layout — they differ only in whether the
/// kernel dereferences a trailing symlink before populating it.
/// </para>
/// <para>
/// <c>[LibraryImport]</c> is used in preference to <c>[DllImport]</c> because the source
/// generator produces fully managed marshaling code at build time, which is the .NET 7+
/// recommended pattern for new interop.
/// </para>
/// </remarks>
[ExcludeFromCodeCoverage(Justification = "Platform-specific OS APIs cannot all be exercised on a single OS. Tests inject a fake IDevelopmentSigningKeyFileSystem instead.")]
internal static partial class PosixInterop
{
    /// <summary>Returns the real UID of the calling process.</summary>
    [LibraryImport("libc", EntryPoint = "getuid")]
    [UnsupportedOSPlatform("windows")]
    internal static partial uint GetCurrentUid();

    /// <summary>
    /// Returns the UID of the owner of the file or directory at <paramref name="path"/>,
    /// or <see langword="null"/> if <c>stat()</c> fails.
    /// </summary>
    [UnsupportedOSPlatform("windows")]
    internal static uint? GetOwnerUid(string path)
    {
        if (RuntimeInformation.IsOSPlatform(OSPlatform.OSX))
        {
            // macOS arm64 only — .NET 9 dropped macOS x64 support, so only arm64 is reachable.
            return NativeStatMacOs(path, out var macBuf) == 0 ? macBuf.st_uid : null;
        }

        if (RuntimeInformation.OSArchitecture == Architecture.X64)
            return NativeStatLinuxX64(path, out var x64Buf) == 0 ? x64Buf.st_uid : null;

        // arm64 and riscv64 share the same stat ABI on Linux.
        if (RuntimeInformation.OSArchitecture is Architecture.Arm64 or Architecture.RiscV64)
            return NativeStatLinuxArm64(path, out var arm64Buf) == 0 ? arm64Buf.st_uid : null;

        // Unknown architecture (e.g. s390x has a different struct layout): fail closed
        // rather than reading st_uid from an incorrect offset.
        return null;
    }

    [LibraryImport("libc", EntryPoint = "stat", StringMarshalling = StringMarshalling.Utf8, SetLastError = true)]
    [UnsupportedOSPlatform("windows")]
    private static partial int NativeStatMacOs(string path, out StatMacOs buf);

    [LibraryImport("libc", EntryPoint = "stat", StringMarshalling = StringMarshalling.Utf8, SetLastError = true)]
    [UnsupportedOSPlatform("windows")]
    private static partial int NativeStatLinuxX64(string path, out StatLinuxX64 buf);

    [LibraryImport("libc", EntryPoint = "stat", StringMarshalling = StringMarshalling.Utf8, SetLastError = true)]
    [UnsupportedOSPlatform("windows")]
    private static partial int NativeStatLinuxArm64(string path, out StatLinuxArm64 buf);

    /// <summary>
    /// Returns the UID of the owner of the directory entry at <paramref name="path"/> itself — if
    /// that entry is a symlink, the symlink object's own owner, <strong>not</strong> the owner of
    /// whatever it points at — or <see langword="null"/> if <c>lstat()</c> fails.
    /// </summary>
    /// <remarks>
    /// Deliberately distinct from <see cref="GetOwnerUid"/>, which calls <c>stat()</c> and therefore
    /// follows a symlink to report the *target's* owner. That distinction matters wherever a caller
    /// uses ownership as a trust signal for a path component that might itself be a symlink (e.g.
    /// <c>FileSigningKeyReader.ValidateNoUntrustedSymlinkedAncestorUnix</c> in
    /// <c>ZeeKayDa.Auth.FileSystem</c>, via <c>InternalsVisibleTo</c>): an unprivileged attacker can
    /// create a symlink that *points at* a root-owned directory, and <c>stat()</c> on that link would
    /// then wrongly report the target's root ownership rather than the attacker's own ownership of
    /// the link they just created. <c>lstat()</c> reports the link entry's own owner regardless of
    /// what it points at, which is the only sound signal for "could an unprivileged local attacker
    /// have created or replaced this specific directory entry."
    /// </remarks>
    [UnsupportedOSPlatform("windows")]
    internal static uint? GetLinkOwnerUid(string path)
    {
        if (RuntimeInformation.IsOSPlatform(OSPlatform.OSX))
            return NativeLstatMacOs(path, out var macBuf) == 0 ? macBuf.st_uid : null;

        if (RuntimeInformation.OSArchitecture == Architecture.X64)
            return NativeLstatLinuxX64(path, out var x64Buf) == 0 ? x64Buf.st_uid : null;

        if (RuntimeInformation.OSArchitecture is Architecture.Arm64 or Architecture.RiscV64)
            return NativeLstatLinuxArm64(path, out var arm64Buf) == 0 ? arm64Buf.st_uid : null;

        return null;
    }

    [LibraryImport("libc", EntryPoint = "lstat", StringMarshalling = StringMarshalling.Utf8, SetLastError = true)]
    [UnsupportedOSPlatform("windows")]
    private static partial int NativeLstatMacOs(string path, out StatMacOs buf);

    [LibraryImport("libc", EntryPoint = "lstat", StringMarshalling = StringMarshalling.Utf8, SetLastError = true)]
    [UnsupportedOSPlatform("windows")]
    private static partial int NativeLstatLinuxX64(string path, out StatLinuxX64 buf);

    [LibraryImport("libc", EntryPoint = "lstat", StringMarshalling = StringMarshalling.Utf8, SetLastError = true)]
    [UnsupportedOSPlatform("windows")]
    private static partial int NativeLstatLinuxArm64(string path, out StatLinuxArm64 buf);

    /// <summary>
    /// macOS / BSD stat struct (arm64, 144 bytes total). Fields in native ABI order.
    /// Layout: dev(4) mode(2) nlink(2) ino(8) uid(4) gid(4) + 120 bytes padding.
    /// Padding uses blittable scalar fields so the struct is compatible with [LibraryImport].
    /// </summary>
    [StructLayout(LayoutKind.Sequential)]
    internal struct StatMacOs
    {
        internal int st_dev;       // offset  0, 4 bytes
        internal ushort st_mode;   // offset  4, 2 bytes
        internal ushort st_nlink;  // offset  6, 2 bytes
        internal ulong st_ino;     // offset  8, 8 bytes
        internal uint st_uid;      // offset 16, 4 bytes ← we need this
        internal uint st_gid;      // offset 20, 4 bytes
        // 120 bytes padding → total 144 bytes (15 × 8)
        private ulong _p0, _p1, _p2, _p3, _p4, _p5, _p6, _p7, _p8, _p9, _p10, _p11, _p12, _p13, _p14;
    }

    /// <summary>
    /// Linux x64 stat struct (144 bytes total). Fields in native ABI order.
    /// Layout: dev(8) ino(8) nlink(8) mode(4) uid(4) gid(4) + 108 bytes padding.
    /// Padding uses blittable scalar fields so the struct is compatible with [LibraryImport].
    /// </summary>
    [StructLayout(LayoutKind.Sequential)]
    internal struct StatLinuxX64
    {
        internal ulong st_dev;     // offset  0, 8 bytes
        internal ulong st_ino;     // offset  8, 8 bytes
        internal ulong st_nlink;   // offset 16, 8 bytes
        internal uint st_mode;     // offset 24, 4 bytes
        internal uint st_uid;      // offset 28, 4 bytes ← we need this
        internal uint st_gid;      // offset 32, 4 bytes
        // 108 bytes padding → total 144 bytes (4 + 13 × 8)
        private uint _p0;          // offset 36, 4 bytes (aligns next field to 8-byte boundary)
        private ulong _p1, _p2, _p3, _p4, _p5, _p6, _p7, _p8, _p9, _p10, _p11, _p12, _p13; // offset 40, 104 bytes
    }

    /// <summary>
    /// Linux arm64 stat struct (128 bytes total). Fields in native ABI order.
    /// Layout: dev(8) ino(8) mode(4) nlink(4) uid(4) gid(4) + 96 bytes padding.
    /// Padding uses blittable scalar fields so the struct is compatible with [LibraryImport].
    /// </summary>
    [StructLayout(LayoutKind.Sequential)]
    internal struct StatLinuxArm64
    {
        internal ulong st_dev;     // offset  0, 8 bytes
        internal ulong st_ino;     // offset  8, 8 bytes
        internal uint st_mode;     // offset 16, 4 bytes
        internal uint st_nlink;    // offset 20, 4 bytes
        internal uint st_uid;      // offset 24, 4 bytes ← we need this
        internal uint st_gid;      // offset 28, 4 bytes
        // 96 bytes padding → total 128 bytes (12 × 8)
        private ulong _p0, _p1, _p2, _p3, _p4, _p5, _p6, _p7, _p8, _p9, _p10, _p11;
    }
}

/// <summary>
/// Default <see cref="IDevelopmentSigningKeyFileSystem"/> implementation that delegates to real OS APIs.
/// On Unix, uses POSIX file-mode bits. On Windows, uses ACL-based access control.
/// </summary>
/// <remarks>
/// This class is excluded from code coverage because its platform-specific branches cannot
/// all be exercised on a single OS. Tests inject a fake <see cref="IDevelopmentSigningKeyFileSystem"/>
/// instead.
/// </remarks>
[ExcludeFromCodeCoverage(Justification = "Platform-specific OS APIs cannot all be exercised on a single OS. Tests inject a fake instead.")]
internal sealed class LocalSigningKeyFileSystem : IDevelopmentSigningKeyFileSystem
{
    /// <inheritdoc/>
    public void EnsureDirectorySafe(string directory)
    {
        if (RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
            EnsureDirectorySafeWindows(directory);
        else
            EnsureDirectorySafeUnix(directory);
    }

    /// <inheritdoc/>
    public async ValueTask WriteKeyFileAsync(string keyPath, ReadOnlyMemory<char> pem, CancellationToken cancellationToken)
    {
        if (RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
            await WriteKeyFileWindowsAsync(keyPath, pem, cancellationToken).ConfigureAwait(false);
        else
            await WriteKeyFileUnixAsync(keyPath, pem, cancellationToken).ConfigureAwait(false);
    }

    /// <inheritdoc/>
    public async ValueTask<KeyFileContent> ReadKeyFileAsync(string keyPath, CancellationToken cancellationToken)
    {
        // Open the file first, then validate and read from the same handle to close the
        // TOCTOU window. ValidateNoSymlink walks parent directories by path string after the
        // handle is open — an extremely narrow race exists there, but the open handle prevents
        // the leaf file from being swapped, which is the highest-impact attack vector.
        // Eliminating the residual parent-directory risk entirely would require openat/fstatat,
        // which are not available via the .NET BCL.
        using var stream = File.Open(keyPath, FileMode.Open, FileAccess.Read, FileShare.Read);

        ValidateNoSymlink(stream);

        if (!RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
            ValidateFilePermissionsUnix(stream, keyPath);

        // Read from the already-open handle so validation and read are on the same file descriptor.
        var bytes = new byte[stream.Length];
        await stream.ReadExactlyAsync(bytes, cancellationToken).ConfigureAwait(false);
        return new KeyFileContent(bytes);
    }

    /// <inheritdoc/>
    public bool FileExists(string path) => File.Exists(path);

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

        if (Directory.Exists(fullPath))
        {
            ValidateDirectoryPermissionsUnix(fullPath);
            ValidateDirectoryChainOwnershipUnix(fullPath);
            return;
        }

        // Note: Directory.CreateDirectory uses the process umask (typically 0755), so there is a
        // narrow window between creation and SetUnixFileMode where the directory exists with looser
        // permissions. Eliminating this would require a P/Invoke to mkdir(2) with mode 0700.
        // For this dev-only provider the window is acceptable; the key file itself is created with
        // atomic 0600 via FileStreamOptions.UnixCreateMode and is the true security boundary.
        Directory.CreateDirectory(fullPath);

        var mode = UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute;
        File.SetUnixFileMode(fullPath, mode);

        // The leaf was just created by this process so we own it. Validate ancestor directories
        // that pre-existed — an attacker who owns an ancestor can rename or replace the subtree.
        var parent = Path.GetDirectoryName(fullPath);
        if (parent is not null)
            ValidateDirectoryChainOwnershipUnix(parent);
    }

    [UnsupportedOSPlatform("windows")]
    private static void ValidateDirectoryPermissionsUnix(string directory)
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
    private static void ValidateDirectoryChainOwnershipUnix(string startDirectory)
    {
        // ADR 0011 §2: every component of the directory chain the provider creates or writes into
        // MUST be owned by the current user. Walk from startDirectory upward, checking ownership
        // on every component that exists. Stop at root-owned (uid 0) directories — those are
        // OS-managed and trusted. This prevents an attacker who owns an ancestor directory from
        // renaming or replacing the signing-key subtree even if the leaf passes all checks.
        var currentUid = PosixInterop.GetCurrentUid();
        var current = startDirectory;

        while (!string.IsNullOrEmpty(current) && current != Path.GetPathRoot(current))
        {
            if (!Directory.Exists(current))
            {
                current = Path.GetDirectoryName(current);
                continue;
            }

            var ownerUid = PosixInterop.GetOwnerUid(current);

            if (ownerUid == 0)
                break; // Root-owned: OS-managed and trusted.

            if (ownerUid is null || ownerUid.Value != currentUid)
            {
                throw new ZeeKayDaConfigurationException(
                    new ZeeKayDaConfigurationFailure(
                        "signing.dev_keys.directory_not_owned_by_current_user",
                        $"Signing key directory component '{current}' is not owned by the current user (UID {currentUid}). " +
                        "Every component of the directory path must be owned by the current user " +
                        "to prevent an attacker from controlling the signing key directory."));
            }

            current = Path.GetDirectoryName(current);
        }
    }

    [SupportedOSPlatform("windows")]
    private static async ValueTask WriteKeyFileWindowsAsync(string keyPath, ReadOnlyMemory<char> pem, CancellationToken cancellationToken)
    {
        await using var stream = new FileStream(keyPath, FileMode.Create, FileAccess.Write, FileShare.None, bufferSize: 4096, useAsync: true);
        await using var writer = new StreamWriter(stream);
        await writer.WriteAsync(pem, cancellationToken).ConfigureAwait(false);
        ApplyRestrictiveFileAclWindows(keyPath);
    }

    [UnsupportedOSPlatform("windows")]
    private static async ValueTask WriteKeyFileUnixAsync(string keyPath, ReadOnlyMemory<char> pem, CancellationToken cancellationToken)
    {
        // Create with 0600 atomically — no create-then-chmod window.
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
        // Validate permissions on the already-open handle to eliminate the TOCTOU window
        // between permission check and file read.
        var mode = File.GetUnixFileMode(stream.SafeFileHandle);

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

    private static void ValidateNoSymlink(FileStream stream)
    {
        // Inspect the open handle's path rather than the original string path.
        // On Windows, SafeFileHandle.IsInvalid would catch a broken symlink, but
        // FileSystemInfo.LinkTarget on the resolved name is the clearest cross-platform check.
        var resolvedPath = stream.Name;

        // Check the leaf file itself.
        var info = new FileInfo(resolvedPath);
        if (info.LinkTarget is not null)
        {
            throw new ZeeKayDaConfigurationException(
                new ZeeKayDaConfigurationFailure(
                    "signing.dev_keys.symlink_detected",
                    $"Signing key path '{resolvedPath}' resolves through a symlink. " +
                    "Symlinks are not permitted for key files to prevent redirect attacks. " +
                    "Remove the symlink and restart the application."));
        }

        // Walk every parent directory component to catch symlinks in the path hierarchy.
        // An attacker with directory write access could redirect a parent directory to
        // an attacker-controlled location even when the leaf file itself is not a symlink.
        var directory = Path.GetDirectoryName(resolvedPath);
        while (!string.IsNullOrEmpty(directory))
        {
            var dirInfo = new DirectoryInfo(directory);
            if (dirInfo.LinkTarget is not null)
            {
                throw new ZeeKayDaConfigurationException(
                    new ZeeKayDaConfigurationFailure(
                        "signing.dev_keys.symlink_detected",
                        $"Signing key path '{resolvedPath}' resolves through a symlinked directory '{directory}'. " +
                        "Symlinks are not permitted anywhere in the key path to prevent redirect attacks. " +
                        "Remove the symlink and restart the application."));
            }

            directory = Path.GetDirectoryName(directory);
        }
    }

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
