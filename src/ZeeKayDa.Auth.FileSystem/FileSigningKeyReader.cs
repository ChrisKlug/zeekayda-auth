using System.Runtime.InteropServices;
using System.Runtime.Versioning;
using System.Security.AccessControl;
using System.Security.Principal;
using Microsoft.Extensions.Logging;
using ZeeKayDa.Auth.Logging;
using ZeeKayDa.Auth.Tokens;

namespace ZeeKayDa.Auth.FileSystem;

/// <summary>
/// Opens and validates an operator-supplied signing key file (PEM or PFX) before its contents are
/// handed to the caller for parsing.
/// </summary>
/// <remarks>
/// This provider reads files it did not create, supplied by the operator, so unlike the Windows
/// Certificate Store or local-development providers it validates rather than trusts them:
/// read-only, never writing, creating a directory, or narrowing an ACL. Each path is opened
/// <strong>exactly once</strong> per read call, and the permission check runs against that open
/// handle rather than the path string. The symlink checks cannot: they inspect the path as given,
/// because the BCL has no <c>O_NOFOLLOW</c>, so a swap between the open and those checks stays possible.
/// </remarks>
internal sealed class FileSigningKeyReader(SanitizingLogger<FileSigningKeyReader> logger)
{
    // Broader than 0600 (owner read/write only) is a hard failure for a file carrying a private key.
    private const UnixFileMode DisallowedUnixModeBits =
        UnixFileMode.GroupRead | UnixFileMode.GroupWrite | UnixFileMode.GroupExecute
        | UnixFileMode.OtherRead | UnixFileMode.OtherWrite | UnixFileMode.OtherExecute;

    // A certificate is public, so reading it protects nothing; writing it publishes an attacker's key.
    private const UnixFileMode DisallowedCertificateOnlyUnixModeBits = UnixFileMode.GroupWrite | UnixFileMode.OtherWrite;

    /// <summary>
    /// Opens, validates, and reads <paramref name="path"/> as PEM text, for use with
    /// <see cref="System.Security.Cryptography.X509Certificates.X509Certificate2.CreateFromPem(ReadOnlySpan{char}, ReadOnlySpan{char})"/>.
    /// </summary>
    /// <param name="path">The operator-supplied path to the PEM file.</param>
    /// <param name="content">What the file carries, which decides the permissions it may have.</param>
    /// <param name="cancellationToken">A token to cancel the operation.</param>
    /// <exception cref="ZeeKayDaConfigurationException">
    /// Thrown when the file does not exist, resolves through a symlink, or has permissions/ACL
    /// broader than <paramref name="content"/> allows.
    /// </exception>
    public async ValueTask<PemText> ReadPemAsync(string path, SigningFileContent content, CancellationToken cancellationToken) =>
        PemText.Decode(await ReadBytesAsync(path, content, cancellationToken).ConfigureAwait(false));

    /// <summary>
    /// Opens, validates, and reads <paramref name="path"/> as raw bytes, for use with
    /// <see cref="System.Security.Cryptography.X509Certificates.X509CertificateLoader"/>'s
    /// <c>LoadPkcs12</c>.
    /// </summary>
    /// <param name="path">The operator-supplied path to the PFX/PKCS#12 file.</param>
    /// <param name="cancellationToken">A token to cancel the operation.</param>
    /// <exception cref="ZeeKayDaConfigurationException">
    /// Thrown when the file does not exist, resolves through a symlink, or has permissions/ACL
    /// broader than allowed.
    /// </exception>
    public ValueTask<byte[]> ReadAllBytesAsync(string path, CancellationToken cancellationToken) =>
        ReadBytesAsync(path, SigningFileContent.PrivateKey, cancellationToken);

    private async ValueTask<byte[]> ReadBytesAsync(string path, SigningFileContent content, CancellationToken cancellationToken)
    {
        using var stream = OpenValidated(path, content);
        var bytes = new byte[stream.Length];
        try
        {
            await stream.ReadExactlyAsync(bytes, cancellationToken).ConfigureAwait(false);
            return bytes;
        }
        catch
        {
            bytes.AsSpan().Clear();
            throw;
        }
    }

    private FileStream OpenValidated(string path, SigningFileContent content)
    {
        var stream = OpenOrThrowMissing(path);
        try
        {
            ValidateNoSymlink(stream, path);

            if (RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
                ValidateAclWindows(stream, path, content);
            else
                ValidateModeUnix(stream, path, content);

            WarnIfPotentiallyUnsafeEnvironment(path);

            return stream;
        }
        catch
        {
            stream.Dispose();
            throw;
        }
    }

    /// <summary>
    /// <see cref="ReadPemAsync"/>, or <see langword="null"/> with a Warning when the file does not
    /// exist: a source lists a deleted file as nothing, and the ring treats the key as revoked.
    /// </summary>
    public async ValueTask<PemText?> TryReadPemAsync(string path, SigningFileContent content, CancellationToken cancellationToken)
    {
        try
        {
            return await ReadPemAsync(path, content, cancellationToken).ConfigureAwait(false);
        }
        catch (ZeeKayDaConfigurationException ex) when (ex.AggregatedFailures[0].Code == FileNotFoundCode)
        {
            WarnMissing(path);
            return null;
        }
    }

    /// <summary><see cref="ReadAllBytesAsync"/>, or <see langword="null"/> with a Warning when the file does not exist.</summary>
    public async ValueTask<byte[]?> TryReadAllBytesAsync(string path, CancellationToken cancellationToken)
    {
        try
        {
            return await ReadAllBytesAsync(path, cancellationToken).ConfigureAwait(false);
        }
        catch (ZeeKayDaConfigurationException ex) when (ex.AggregatedFailures[0].Code == FileNotFoundCode)
        {
            WarnMissing(path);
            return null;
        }
    }

    private void WarnMissing(string path) =>
        logger.LogWarning(
            "ZeeKayDa.Auth: signing key file '{Path}' does not exist, so its key is not listed; a key no longer " +
            "listed stops signing and is unpublished.",
            path);

    private const string FileNotFoundCode = "signing.file_signing.file_not_found";

    private static FileStream OpenOrThrowMissing(string path)
    {
        try
        {
            return File.Open(path, FileMode.Open, FileAccess.Read, FileShare.Read);
        }
        catch (Exception ex) when (ex is FileNotFoundException or DirectoryNotFoundException)
        {
            throw new ZeeKayDaConfigurationException(new ZeeKayDaConfigurationFailure(
                FileNotFoundCode,
                $"Signing key file '{path}' does not exist. Verify the path passed to " +
                "AddPemFileSigning/AddPfxFileSigning (or options.AddFile) is correct and readable by " +
                "the process identity."));
        }
        catch (UnauthorizedAccessException ex)
        {
            throw new ZeeKayDaConfigurationException(
                new ZeeKayDaConfigurationFailure(
                    "signing.file_signing.access_denied",
                    $"Signing key file '{path}' exists but could not be opened{ProcessIdentityHelper.FormatIdentitySuffix(ProcessIdentityHelper.TryResolveProcessIdentity())}. " +
                    "Verify the file's owner/ACL grants read access to the process identity the application " +
                    "runs as."),
                ex);
        }
    }

    private static void ValidateNoSymlink(FileStream stream, string originalPath)
    {
        var resolvedPath = stream.Name;

        var info = new FileInfo(resolvedPath);
        if (info.LinkTarget is not null)
            throw SymlinkDetected(originalPath, resolvedPath);

        if (RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
            ValidateNoSymlinkedAncestorWindows(originalPath, resolvedPath);
        else
            ValidateNoUntrustedSymlinkedAncestorUnix(originalPath, resolvedPath);
    }

    [SupportedOSPlatform("windows")]
    private static void ValidateNoSymlinkedAncestorWindows(string originalPath, string resolvedPath)
    {
        // A symlinked ancestor directory is just as dangerous as a symlinked leaf: an attacker with
        // write access to a parent directory could redirect it elsewhere. Every ancestor is checked
        // unconditionally — Windows has no OS-owned-symlink convention to carve out (see the Unix
        // check below).
        var directory = Path.GetDirectoryName(resolvedPath);
        while (!string.IsNullOrEmpty(directory))
        {
            if (IsSymlinkedDirectory(directory))
                throw SymlinkDetected(originalPath, resolvedPath, directory);

            directory = Path.GetDirectoryName(directory);
        }
    }

    /// <summary>
    /// Walks <paramref name="resolvedPath"/>'s ancestor directories, rejecting the first
    /// non-root-owned symlinked one — a root-owned ancestor is trusted regardless of whether it is
    /// itself a symlink, since an attacker without root cannot plant or replace a root-owned
    /// directory entry (macOS ships <c>/tmp</c>, <c>/var</c>, and <c>/etc</c> as symlinks to
    /// <c>/private/...</c>, and this provider is the recommended one for macOS, so a blanket
    /// "any symlinked ancestor is unsafe" rule — the Windows walk above — would make it unusable
    /// there). The walk stops at the first root-owned entry, since everything above it is equally
    /// OS-managed.
    /// </summary>
    [UnsupportedOSPlatform("windows")]
    private static void ValidateNoUntrustedSymlinkedAncestorUnix(string originalPath, string resolvedPath)
    {
        var directory = Path.GetDirectoryName(resolvedPath);
        while (!string.IsNullOrEmpty(directory))
        {
            if (IsRootOwnedDirectoryEntry(directory))
                break;

            if (IsSymlinkedDirectory(directory))
                throw SymlinkDetected(originalPath, resolvedPath, directory);

            directory = Path.GetDirectoryName(directory);
        }
    }

    /// <summary>
    /// Whether <paramref name="directoryPath"/>'s own directory entry — not the target it
    /// resolves to, if it is itself a symlink — is owned by root (uid 0).
    /// </summary>
    /// <remarks>
    /// Uses <see cref="PosixInterop.GetLinkOwnerUid"/> (<c>lstat</c>), never a <c>stat</c>-based
    /// owner lookup: <c>stat()</c> follows a symlink and reports the target's owner, which an
    /// attacker controls by choosing where their symlink points — e.g. pointing at root-owned
    /// <c>/tmp</c> would wrongly read as root-owned and short-circuit this check. <c>lstat()</c>
    /// reports the link entry's own owner.
    /// </remarks>
    [UnsupportedOSPlatform("windows")]
    private static bool IsRootOwnedDirectoryEntry(string directoryPath) =>
        PosixInterop.GetLinkOwnerUid(directoryPath) == 0;

    private static bool IsSymlinkedDirectory(string directoryPath) =>
        new DirectoryInfo(directoryPath).LinkTarget is not null;

    private static ZeeKayDaConfigurationException SymlinkDetected(
        string originalPath, string resolvedPath, string? symlinkedDirectory = null)
    {
        var detail = symlinkedDirectory is null
            ? $"'{resolvedPath}' is itself a symlink"
            : $"'{resolvedPath}' resolves through symlinked directory '{symlinkedDirectory}'";

        return new ZeeKayDaConfigurationException(new ZeeKayDaConfigurationFailure(
            "signing.file_signing.symlink_detected",
            $"Signing key file '{originalPath}' cannot be used: {detail}. Symlinks are not permitted " +
            "anywhere in a signing key file's path, to prevent redirect attacks. Replace the symlink " +
            "with the real file."));
    }

    [UnsupportedOSPlatform("windows")]
    private static void ValidateModeUnix(FileStream stream, string path, SigningFileContent content)
    {
        // Checked on the already-open handle (via SafeFileHandle) rather than the path string, so
        // this cannot be TOCTOU-raced between the open above and this check.
        var mode = File.GetUnixFileMode(stream.SafeFileHandle);

        if (content == SigningFileContent.CertificateOnly)
        {
            if ((mode & DisallowedCertificateOnlyUnixModeBits) != 0)
            {
                throw new ZeeKayDaConfigurationException(new ZeeKayDaConfigurationFailure(
                    "signing.file_signing.file_too_permissive",
                    $"Certificate file '{path}' is writable by group or other users (found {DescribeUnixMode(mode)}). " +
                    "Anyone who can write it can publish their own key. Run 'chmod 644' on the file."));
            }

            // A readable file no longer proves the process owns it, and its owner can rewrite it.
            var owner = PosixInterop.GetOwnerUid(stream.SafeFileHandle);
            if (owner is null)
            {
                throw new ZeeKayDaConfigurationException(new ZeeKayDaConfigurationFailure(
                    "signing.file_signing.file_too_permissive",
                    $"The owner of certificate file '{path}' could not be determined on this platform, so a " +
                    "separate certificate file cannot be trusted here. Use a combined certificate and key file."));
            }

            if (!IsTrustedOwner(owner, PosixInterop.GetEffectiveUid()))
            {
                throw new ZeeKayDaConfigurationException(new ZeeKayDaConfigurationFailure(
                    "signing.file_signing.file_too_permissive",
                    $"Certificate file '{path}' is owned by neither root nor the user the process runs as. " +
                    "Its owner can rewrite it and publish their own key. Change its owner with 'chown'."));
            }

            return;
        }

        if ((mode & DisallowedUnixModeBits) != 0)
        {
            throw new ZeeKayDaConfigurationException(new ZeeKayDaConfigurationFailure(
                "signing.file_signing.file_too_permissive",
                $"Signing key file '{path}' has permissions broader than 0600 (found {DescribeUnixMode(mode)}). " +
                "A file readable or writable by group or other users is treated as compromised. " +
                "Run 'chmod 600' on the file and restart the application."));
        }
    }

    /// <summary>
    /// Whether a certificate file's owner may be trusted to write it: root, or the process's own user.
    /// An owner that cannot be read is not trusted.
    /// </summary>
    internal static bool IsTrustedOwner(uint? ownerUid, uint effectiveUid) =>
        ownerUid is { } owner && (owner == 0 || owner == effectiveUid);

    [SupportedOSPlatform("windows")]
    private static void ValidateAclWindows(FileStream stream, string path, SigningFileContent content)
    {
        // GetAccessControl(FileStream) reads the DACL from the already-open handle, closing the
        // same TOCTOU window the Unix mode check closes via SafeFileHandle.
        var security = stream.GetAccessControl();
        var rules = security.GetAccessRules(includeExplicit: true, includeInherited: true, typeof(SecurityIdentifier));

        var broadAllowRules = rules
            .OfType<FileSystemAccessRule>()
            .Where(rule => rule.AccessControlType == AccessControlType.Allow)
            .Where(rule => rule.IdentityReference is SecurityIdentifier sid && IsBroadPrincipal(sid));

        if (content == SigningFileContent.CertificateOnly)
        {
            if (broadAllowRules.Any(GrantsWrite))
            {
                throw new ZeeKayDaConfigurationException(new ZeeKayDaConfigurationFailure(
                    "signing.file_signing.file_too_permissive",
                    $"Certificate file '{path}' grants a broad principal ('Everyone', 'Users', or " +
                    "'Authenticated Users') the right to write, delete, change the permissions of, or take " +
                    "ownership of it. Anyone who can replace it can publish their own key. Remove those rights."));
            }

            // An owner may always change the ACL, so an untrusted owner can grant themselves write.
            var owner = security.GetOwner(typeof(SecurityIdentifier)) as SecurityIdentifier;
            if (!IsTrustedOwner(owner, WindowsIdentity.GetCurrent().User))
            {
                throw new ZeeKayDaConfigurationException(new ZeeKayDaConfigurationFailure(
                    "signing.file_signing.file_too_permissive",
                    $"Certificate file '{path}' is owned by neither the process identity, SYSTEM, nor " +
                    "Administrators. Its owner can change its ACL and publish their own key. Change its owner."));
            }

            return;
        }

        if (broadAllowRules.Any())
        {
            throw new ZeeKayDaConfigurationException(new ZeeKayDaConfigurationFailure(
                "signing.file_signing.file_too_permissive",
                $"Signing key file '{path}' grants access to a broad principal ('Everyone', " +
                "'Users', or 'Authenticated Users'). Restrict the file's ACL to the process " +
                "identity only, with inheritance disabled, and restart the application."));
        }
    }

    // Changing the ACL or taking ownership is a write once removed: the holder can grant themselves write.
    // Delete lets the holder replace the file.
    [SupportedOSPlatform("windows")]
    private static bool GrantsWrite(FileSystemAccessRule rule) =>
        (rule.FileSystemRights & (FileSystemRights.Write | FileSystemRights.Delete | FileSystemRights.ChangePermissions | FileSystemRights.TakeOwnership)) != 0;

    /// <summary>
    /// Whether a certificate file's Windows owner may be trusted to write it: the process identity,
    /// SYSTEM, or Administrators. An owner that cannot be read is not trusted.
    /// </summary>
    [SupportedOSPlatform("windows")]
    internal static bool IsTrustedOwner(SecurityIdentifier? owner, SecurityIdentifier? processUser) =>
        owner is not null
        && (owner == processUser
            || owner.IsWellKnown(WellKnownSidType.LocalSystemSid)
            || owner.IsWellKnown(WellKnownSidType.BuiltinAdministratorsSid));

    [SupportedOSPlatform("windows")]
    private static bool IsBroadPrincipal(SecurityIdentifier sid) =>
        sid.IsWellKnown(WellKnownSidType.WorldSid)
        || sid.IsWellKnown(WellKnownSidType.BuiltinUsersSid)
        || sid.IsWellKnown(WellKnownSidType.AuthenticatedUserSid);

    private static string DescribeUnixMode(UnixFileMode mode) =>
        "0" + Convert.ToString((int)mode & 0x1FF, 8).PadLeft(3, '0');

    /// <summary>
    /// Best-effort, log-only checks for a network-filesystem volume and a group- or world-writable parent
    /// directory. Neither check fails startup: an inconclusive or unsupported check degrades to
    /// "no warning" rather than a hard failure.
    /// </summary>
    private void WarnIfPotentiallyUnsafeEnvironment(string path)
    {
        try
        {
            WarnIfNetworkVolume(path);
            WarnIfParentDirectoryWorldWritable(path);
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or PlatformNotSupportedException or ArgumentException)
        {
            // Best-effort: a failure to determine the volume type or parent-directory permissions
            // must never abort loading a key that otherwise passed the hard-fail checks above.
            logger.LogDebug(ex, "ZeeKayDa.Auth: could not evaluate the environment safety heuristics for signing key file '{Path}'.", path);
        }
    }

    private void WarnIfNetworkVolume(string path)
    {
        // DriveInfo's DriveType reliably distinguishes network shares only on Windows. On Unix,
        // every mount (including NFS) commonly reports as Fixed/Unknown via this API, so the check
        // is skipped there rather than emitting a misleading warning either way.
        if (!RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
            return;

        var root = Path.GetPathRoot(Path.GetFullPath(path));
        if (string.IsNullOrEmpty(root))
            return;

        if (root.StartsWith(@"\\", StringComparison.Ordinal) || new DriveInfo(root).DriveType == DriveType.Network)
        {
            logger.LogWarning(
                "ZeeKayDa.Auth: signing key file '{Path}' appears to be on a network volume. Storing " +
                "signing key material on a network filesystem widens its exposure beyond the local " +
                "host; prefer local storage where possible.",
                path);
        }
    }

    private void WarnIfParentDirectoryWorldWritable(string path)
    {
        var parent = Path.GetDirectoryName(Path.GetFullPath(path));
        if (string.IsNullOrEmpty(parent) || !Directory.Exists(parent))
            return;

        if (RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
        {
            WarnIfParentDirectoryWorldWritableWindows(path, parent);
        }
        else
        {
            var mode = File.GetUnixFileMode(parent);
            if ((mode & (UnixFileMode.GroupWrite | UnixFileMode.OtherWrite)) != 0)
            {
                logger.LogWarning(
                    "ZeeKayDa.Auth: the parent directory '{Directory}' of signing key file '{Path}' is " +
                    "writable by group or other users. Another local user could replace or redirect files in " +
                    "this directory. Restrict the directory's permissions.",
                    parent, path);
            }
        }
    }

    [SupportedOSPlatform("windows")]
    private void WarnIfParentDirectoryWorldWritableWindows(string path, string parent)
    {
        var security = new DirectoryInfo(parent).GetAccessControl();
        var rules = security.GetAccessRules(includeExplicit: true, includeInherited: true, typeof(SecurityIdentifier));

        var hasBroadWritableRule = rules
            .OfType<FileSystemAccessRule>()
            .Where(rule => rule.AccessControlType == AccessControlType.Allow)
            .Where(rule => rule.IdentityReference is SecurityIdentifier sid && IsBroadPrincipal(sid))
            .Any(GrantsWrite);

        if (hasBroadWritableRule)
        {
            logger.LogWarning(
                "ZeeKayDa.Auth: the parent directory '{Directory}' of signing key file '{Path}' " +
                "grants write access to a broad principal ('Everyone', 'Users', or 'Authenticated " +
                "Users'). Another local user could replace or redirect files in this directory. " +
                "Restrict the directory's ACL.",
                parent, path);
        }
    }
}
