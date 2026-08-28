using System.Diagnostics.CodeAnalysis;
using System.Runtime.InteropServices;
using System.Runtime.Versioning;
using System.Security.AccessControl;
using System.Security.Principal;

namespace ZeeKayDa.Auth.Tokens;

/// <summary>
/// Provides interop access to <c>getuid()</c> and <c>lstat()</c> for directory ownership validation
/// on Unix platforms.
/// </summary>
/// <remarks>
/// The current process UID from <c>getuid()</c> is compared against a directory's owner UID
/// (<see cref="GetLinkOwnerUid"/>, via <c>lstat()</c>) to detect attacker-controlled directories
/// that pass the <c>0700</c> permission check but are owned by a different user.
/// <para>
/// There is deliberately no <c>stat()</c>-based counterpart. <c>stat()</c> follows a symlink and
/// reports the owner of whatever it points at, which an attacker chooses by choosing where their
/// link points — so every ownership decision in this assembly reads the link entry's own owner
/// instead, and both callers reject a symlinked component outright rather than inspecting its
/// target. A <c>stat()</c> helper existing here at all would be an invitation to reintroduce that
/// bug; it was removed in issue #586 once the last caller stopped needing it.
/// </para>
/// Separate native stat-buffer structs are declared for macOS/BSD and Linux 64-bit because the kernel ABI
/// differs between platforms; only the fields up to <c>st_uid</c> are bound, with the rest covered
/// by blittable padding.
/// </remarks>
[ExcludeFromCodeCoverage(Justification = "Each architecture-specific lstat branch is reachable only on the one architecture whose ABI it binds, so no single runner can cover them all. LocalSigningKeyFileSystemTests exercises whichever branch the runner's architecture selects.")]
internal static partial class PosixInterop
{
    /// <summary>Returns the real UID of the calling process.</summary>
    [LibraryImport("libc", EntryPoint = "getuid")]
    [UnsupportedOSPlatform("windows")]
    internal static partial uint GetCurrentUid();

    /// <summary>
    /// Returns the UID of the owner of the directory entry at <paramref name="path"/> itself — if
    /// that entry is a symlink, the symlink object's own owner, <strong>not</strong> the owner of
    /// whatever it points at — or <see langword="null"/> if <c>lstat()</c> fails.
    /// </summary>
    /// <remarks>
    /// Deliberately <c>lstat()</c> and never <c>stat()</c>, which follows a symlink to report the
    /// *target's* owner. An unprivileged attacker can create a symlink that points at a root-owned
    /// directory, and <c>stat()</c> on that link would wrongly report root ownership rather than the
    /// attacker's own ownership of the link they created. <c>lstat()</c> reports the link entry's own
    /// owner regardless of what it points at.
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
        // Open first, then validate and read from the same handle, closing the TOCTOU window for
        // the leaf file. A narrow residual race remains for parent-directory swaps, which would
        // require openat/fstatat (not available via the .NET BCL) to close entirely.
        using var stream = File.Open(keyPath, FileMode.Open, FileAccess.Read, FileShare.Read);

        ValidateNoSymlink(stream);

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

        if (Directory.Exists(fullPath))
        {
            ValidateDirectoryPermissionsUnix(fullPath);
            ValidateDirectoryChainOwnershipUnix(fullPath);
            return;
        }

        // A component that exists but is not a directory has to be caught here: the walk below only
        // sees ancestors, and CreateDirectory would otherwise surface it as a raw IOException.
        ValidateAbsentComponentUnix(fullPath);

        // Ancestors are validated *before* anything is created. Creating first and validating after
        // still rejects the configuration, but leaves a directory behind at whatever location the
        // rejected path pointed at — which, for the attacker-planted shapes this walk exists to
        // catch, is a location the attacker chose.
        var parent = Path.GetDirectoryName(fullPath);
        if (parent is not null)
            ValidateDirectoryChainOwnershipUnix(parent);

        CreateDirectoryChainOwnerOnlyUnix(fullPath);

        // Re-validated after creation, against the path that now exists. The walk above ran when
        // some of these components did not exist yet, and an attacker racing to create one first
        // would have had it skipped by the "does not exist, keep walking" branch — leaving an
        // ancestor they own beneath a directory this method reported as safe.
        ValidateDirectoryChainOwnershipUnix(fullPath);
    }

    /// <summary>
    /// Creates <paramref name="directory"/> and every missing component above it, restricting each
    /// one to the owner.
    /// </summary>
    /// <remarks>
    /// <para>
    /// Deliberately not a bare <c>Directory.CreateDirectory</c>. That applies the process umask to
    /// every component it creates, and the obvious follow-up — chmod the leaf — leaves the
    /// *intermediate* directories at whatever the umask produced. Under Ubuntu's default umask of
    /// 002 that is <c>0775</c>, so the provider would create a group-writable component and then
    /// reject it on the next startup via <see cref="ChainVerdict.WritableByOthers"/>: an application that
    /// starts once, writes a key, and can never start again — and in the meantime a component of the
    /// signing key path really is group-writable.
    /// </para>
    /// <para>
    /// The <c>UnixFileMode</c> overload only modes the <em>final</em> directory of whatever it
    /// creates, which is why it cannot replace this loop — but it is exactly right for one component
    /// at a time, and that is how it is used here. Creating with the mode rather than creating and
    /// then chmod'ing also closes a window: between a bare <c>CreateDirectory</c> and a following
    /// <c>SetUnixFileMode</c>, the component sits at the umask, and <c>SetUnixFileMode</c> follows a
    /// symlink — so an attacker who won that race by planting a link at the next component could
    /// redirect the chmod onto a directory of ours. The overload applies the mode at creation and
    /// does not touch an entry it did not create.
    /// </para>
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
        // Walks from startDirectory upward, checking every existing component, so an attacker who
        // controls an ancestor cannot rename or replace the signing-key subtree even if the leaf
        // passes all checks. Stops at the first root-owned entry, which is OS-managed and trusted.
        //
        // Ownership is read with lstat, never stat. stat() follows a symlink and reports the owner
        // of whatever it points at, so an attacker's own symlink pointed at any root-owned directory
        // (/tmp will do) would report uid 0, stop the walk, and take every component above it out of
        // the check as well — while never being flagged as foreign-owned itself. lstat() reports the
        // link entry's own owner, which is the half an attacker can repoint after validation.
        //
        // Because a symlinked component is then rejected outright, there is no need to also stat()
        // the target: a link the current user owns is refused whatever it points at. That mirrors
        // ValidateNoUntrustedSymlinkedAncestorUnix on the read path, so a directory this method
        // accepts is one ReadKeyFileAsync will accept too — a config that starts once but cannot
        // start again is worse than one that is refused up front.
        var currentUid = PosixInterop.GetCurrentUid();
        var current = startDirectory;

        while (!string.IsNullOrEmpty(current) && current != Path.GetPathRoot(current))
        {
            if (!Directory.Exists(current))
            {
                ValidateAbsentComponentUnix(current);
                current = Path.GetDirectoryName(current);
                continue;
            }

            var verdict = JudgeComponent(
                File.GetUnixFileMode(current),
                PosixInterop.GetLinkOwnerUid(current),
                currentUid,
                IsSymlinkedDirectory(current));

            if (verdict is ChainVerdict.TrustedRootOwned)
                break;

            if (verdict is not ChainVerdict.Accept)
                throw ComponentFailure(verdict, current, currentUid);

            current = Path.GetDirectoryName(current);
        }
    }

    /// <summary>The outcome of judging one component of the signing key directory chain.</summary>
    internal enum ChainVerdict
    {
        /// <summary>The component is the current user's, and safe to walk past.</summary>
        Accept,

        /// <summary>Root owns the entry: OS-managed, trusted, and the walk stops here.</summary>
        TrustedRootOwned,

        /// <summary>Group or other can write to it, and it is not sticky.</summary>
        WritableByOthers,

        /// <summary>Ownership could not be read at all.</summary>
        OwnershipUndetermined,

        /// <summary>Some other user owns the entry.</summary>
        NotOwnedByCurrentUser,

        /// <summary>The current user owns it, but it is a symlink.</summary>
        Symlink,
    }

    /// <summary>
    /// Decides the fate of one chain component from the four facts that matter, with no file-system
    /// access of its own.
    /// </summary>
    /// <remarks>
    /// Extracted as a pure function because the interesting branches cannot be staged unprivileged:
    /// a component owned by a <em>different non-root</em> user needs root to <c>chown</c> with, a
    /// symlink's owner is fixed at <c>symlink(2)</c> so a foreign-owned link entry needs
    /// <c>CAP_CHOWN</c>, an unreadable ownership has no unprivileged trigger, and a root-owned
    /// world-writable directory is a misconfiguration no test should create. Against real
    /// directories those branches could only ever be reasoned about; here they are asserted.
    /// <para>
    /// <strong>Order matters and is part of the contract.</strong> Writability is judged
    /// <em>before</em> the root-owned trust break, because "root planted it" says nothing about who
    /// can <em>rename</em> it — POSIX grants rename and unlink from the directory's own write bit, so
    /// a root-owned <c>0777</c> non-sticky directory is replaceable by any local user. The sticky bit
    /// exempts it, since sticky restricts rename and unlink to each entry's own owner.
    /// </para>
    /// </remarks>
    internal static ChainVerdict JudgeComponent(
        UnixFileMode mode, uint? linkOwnerUid, uint currentUid, bool isSymlink)
    {
        var writableByOthers = (mode & (UnixFileMode.GroupWrite | UnixFileMode.OtherWrite)) != 0;
        var sticky = (mode & UnixFileMode.StickyBit) != 0;

        if (writableByOthers && !sticky)
            return ChainVerdict.WritableByOthers;

        if (linkOwnerUid is null)
            return ChainVerdict.OwnershipUndetermined;

        if (linkOwnerUid.Value == 0)
            return ChainVerdict.TrustedRootOwned;

        if (linkOwnerUid.Value != currentUid)
            return ChainVerdict.NotOwnedByCurrentUser;

        return isSymlink ? ChainVerdict.Symlink : ChainVerdict.Accept;
    }

    /// <summary>
    /// Guards the "component does not exist, keep walking upward" branch. A genuinely absent
    /// component is fine — the walk simply continues past it — but an entry that exists and is not a
    /// directory is not, and skipping it silently would be the one fail-open step in an otherwise
    /// fail-closed walk.
    /// </summary>
    /// <remarks>
    /// <see cref="Path.Exists(string)"/> alone is the whole test: it reports <see langword="true"/>
    /// for a regular file, a FIFO, a socket, a device node, and — verified, not assumed — for a
    /// dangling symlink and a broken symlink chain, none of which can be a legitimate ancestor. A
    /// permission-denied stat reads as absent and the walk continues, which is safe: EACCES implies
    /// a non-searchable ancestor, and the walk checks that ancestor itself on the next iteration.
    /// </remarks>
    [UnsupportedOSPlatform("windows")]
    private static void ValidateAbsentComponentUnix(string directory)
    {
        if (!Path.Exists(directory))
            return;

        if (Directory.Exists(directory))
            return;

        throw ChainFailure(
            "signing.dev_keys.directory_component_not_a_directory",
            $"Signing key directory component '{directory}' exists but is not a directory. " +
            "Every component of the directory path must be a real directory owned by the current user.");
    }

    /// <summary>Turns a rejecting <see cref="ChainVerdict"/> into the failure an operator sees.</summary>
    private static ZeeKayDaConfigurationException ComponentFailure(
        ChainVerdict verdict, string directory, uint currentUid) => verdict switch
        {
            ChainVerdict.WritableByOthers => ChainFailure(
                "signing.dev_keys.directory_component_writable_by_others",
                $"Signing key directory component '{directory}' is writable by group or other, and is not sticky. " +
                "Any user with write access to it can rename or replace the signing key directory. " +
                $"Run 'chmod g-w,o-w {directory}', or configure a signing key directory outside it. " +
                "On a file system that cannot represent Unix permissions — a Windows drive mounted under " +
                "WSL, or some network mounts — configure a directory on a native Linux file system instead."),

            // lstat failed, or the architecture's struct layout is unbound (see PosixInterop). Fail
            // closed, and say so — reporting this as "not owned by the current user" would send an
            // operator to check an ownership that was never actually read.
            ChainVerdict.OwnershipUndetermined => ChainFailure(
                "signing.dev_keys.directory_ownership_undetermined",
                $"Ownership of signing key directory component '{directory}' could not be determined. " +
                "The signing key directory is treated as untrusted when its ownership cannot be read."),

            ChainVerdict.NotOwnedByCurrentUser => ChainFailure(
                "signing.dev_keys.directory_not_owned_by_current_user",
                $"Signing key directory component '{directory}' is not owned by the current user (UID {currentUid}). " +
                "Every component of the directory path must be owned by the current user " +
                "to prevent an attacker from controlling the signing key directory."),

            // Owned by the current user, but still refused: a symlink is repointable, and the read
            // path rejects it anyway — accepting it here yields a configuration that starts once and
            // then fails on every subsequent startup.
            ChainVerdict.Symlink => ChainFailure(
                "signing.dev_keys.symlink_detected",
                $"Signing key directory component '{directory}' is a symlink. " +
                "Symlinks are not permitted anywhere in the key path to prevent redirect attacks. " +
                "Configure the signing key directory as a real path."),

            _ => throw new InvalidOperationException($"{verdict} is not a rejecting verdict."),
        };

    private static ZeeKayDaConfigurationException ChainFailure(string code, string message) =>
        new(new ZeeKayDaConfigurationFailure(code, message));

    [ExcludeFromCodeCoverage(Justification = "Windows-only, so unreachable on the Linux runner whose coverage artifact feeds the regression gate. LocalSigningKeyFileSystemTests covers this on the windows-latest runner.")]
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
        // Validated on the already-open handle to eliminate the TOCTOU window.
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
        // Inspects the open handle's resolved path — FileSystemInfo.LinkTarget is the clearest
        // cross-platform check.
        var resolvedPath = stream.Name;

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

        if (RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
            ValidateNoSymlinkedAncestorWindows(resolvedPath);
        else
            ValidateNoUntrustedSymlinkedAncestorUnix(resolvedPath);
    }

    /// <summary>
    /// Walks every ancestor directory of <paramref name="resolvedPath"/> and rejects the first
    /// symlinked one. A symlinked ancestor is as dangerous as a symlinked leaf: an attacker with
    /// write access to a parent could redirect it elsewhere. Every ancestor is checked
    /// unconditionally — Windows has no OS-owned-symlink convention to carve out, unlike the Unix
    /// walk below.
    /// </summary>
    [ExcludeFromCodeCoverage(Justification = "Windows-only, so unreachable on the Linux runner whose coverage artifact feeds the regression gate. Only partly covered on the windows-latest runner either: LocalSigningKeyFileSystemTests walks this whenever it reads a key, but its throwing branch is unexercised, because the tests that plant a symlink skip on Windows where creating one needs elevation.")]
    [SupportedOSPlatform("windows")]
    private static void ValidateNoSymlinkedAncestorWindows(string resolvedPath)
    {
        var directory = Path.GetDirectoryName(resolvedPath);
        while (!string.IsNullOrEmpty(directory))
        {
            if (IsSymlinkedDirectory(directory))
                throw SymlinkedAncestorDetected(resolvedPath, directory);

            directory = Path.GetDirectoryName(directory);
        }
    }

    /// <summary>
    /// Walks <paramref name="resolvedPath"/>'s ancestor directories, rejecting the first
    /// non-root-owned symlinked one — a root-owned ancestor is trusted regardless of whether it is
    /// itself a symlink, since an attacker without root cannot plant or replace a root-owned
    /// directory entry. macOS ships <c>/tmp</c>, <c>/var</c>, and <c>/etc</c> as symlinks to
    /// <c>/private/...</c>, so the blanket "any symlinked ancestor is unsafe" rule the Windows walk
    /// above applies would reject a key under any of those paths on a platform where this dev-only
    /// provider is routinely used. The walk stops at the first root-owned entry, since everything
    /// above it is equally OS-managed.
    /// </summary>
    /// <remarks>
    /// Mirrors <c>FileSigningKeyReader.ValidateNoUntrustedSymlinkedAncestorUnix</c>, which carries
    /// the same trust anchor for the same reason.
    /// </remarks>
    [UnsupportedOSPlatform("windows")]
    private static void ValidateNoUntrustedSymlinkedAncestorUnix(string resolvedPath)
    {
        var directory = Path.GetDirectoryName(resolvedPath);
        while (!string.IsNullOrEmpty(directory))
        {
            if (IsRootOwnedDirectoryEntry(directory))
                break;

            if (IsSymlinkedDirectory(directory))
                throw SymlinkedAncestorDetected(resolvedPath, directory);

            directory = Path.GetDirectoryName(directory);
        }
    }

    /// <summary>
    /// Whether <paramref name="directoryPath"/>'s own directory entry — not the target it resolves
    /// to, if it is itself a symlink — is owned by root (uid 0).
    /// </summary>
    /// <remarks>
    /// Uses <see cref="PosixInterop.GetLinkOwnerUid"/> (<c>lstat</c>), never a <c>stat</c>-based
    /// owner lookup: <c>stat()</c> follows a symlink and reports the target's owner, which an
    /// attacker controls by choosing where their symlink points — pointing it at root-owned
    /// <c>/tmp</c> would wrongly read as root-owned and short-circuit this check. <c>lstat()</c>
    /// reports the link entry's own owner.
    /// </remarks>
    [UnsupportedOSPlatform("windows")]
    private static bool IsRootOwnedDirectoryEntry(string directoryPath) =>
        PosixInterop.GetLinkOwnerUid(directoryPath) == 0;

    private static bool IsSymlinkedDirectory(string directoryPath) =>
        new DirectoryInfo(directoryPath).LinkTarget is not null;

    private static ZeeKayDaConfigurationException SymlinkedAncestorDetected(string resolvedPath, string symlinkedDirectory) =>
        new(new ZeeKayDaConfigurationFailure(
            "signing.dev_keys.symlink_detected",
            $"Signing key path '{resolvedPath}' resolves through a symlinked directory '{symlinkedDirectory}'. " +
            "Symlinks are not permitted anywhere in the key path to prevent redirect attacks. " +
            "Remove the symlink and restart the application."));

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
