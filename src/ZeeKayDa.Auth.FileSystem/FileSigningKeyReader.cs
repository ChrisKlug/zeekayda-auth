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
/// <strong>exactly once</strong> per read call and every check runs against that single open
/// handle rather than the path string, closing the TOCTOU window between validation and read.
/// </remarks>
internal sealed class FileSigningKeyReader
{
    // Broader than 0600 (owner read/write only) is a hard failure.
    private const UnixFileMode DisallowedUnixModeBits =
        UnixFileMode.GroupRead | UnixFileMode.GroupWrite | UnixFileMode.GroupExecute
        | UnixFileMode.OtherRead | UnixFileMode.OtherWrite | UnixFileMode.OtherExecute;

    private readonly ISanitizingLogger<FileSigningKeyReader> _logger;

    /// <summary>
    /// Initialises a new reader.
    /// </summary>
    /// <param name="logger">Used only for the best-effort, non-fatal environment warnings.</param>
    public FileSigningKeyReader(ISanitizingLogger<FileSigningKeyReader> logger)
    {
        ArgumentNullException.ThrowIfNull(logger);
        _logger = logger;
    }

    /// <summary>
    /// Opens, validates, and reads <paramref name="path"/> as PEM text, for use with
    /// <see cref="System.Security.Cryptography.X509Certificates.X509Certificate2.CreateFromPem(ReadOnlySpan{char}, ReadOnlySpan{char})"/>.
    /// </summary>
    /// <param name="path">The operator-supplied path to the combined cert+key PEM file.</param>
    /// <param name="cancellationToken">A token to cancel the operation.</param>
    /// <exception cref="ZeeKayDaConfigurationException">
    /// Thrown when the file does not exist, resolves through a symlink, or has permissions/ACL
    /// broader than allowed.
    /// </exception>
    public async ValueTask<string> ReadPemTextAsync(string path, CancellationToken cancellationToken)
    {
        using var stream = OpenValidated(path);
        using var reader = new StreamReader(stream);
        return await reader.ReadToEndAsync(cancellationToken).ConfigureAwait(false);
    }

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
    public async ValueTask<byte[]> ReadAllBytesAsync(string path, CancellationToken cancellationToken)
    {
        using var stream = OpenValidated(path);
        var bytes = new byte[stream.Length];
        await stream.ReadExactlyAsync(bytes, cancellationToken).ConfigureAwait(false);
        return bytes;
    }

    private FileStream OpenValidated(string path)
    {
        var stream = OpenOrThrowMissing(path);
        try
        {
            ValidateNoSymlink(stream, path);

            if (RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
                ValidateAclWindows(stream, path);
            else
                ValidateModeUnix(stream, path);

            WarnIfPotentiallyUnsafeEnvironment(path);

            return stream;
        }
        catch
        {
            stream.Dispose();
            throw;
        }
    }

    private static FileStream OpenOrThrowMissing(string path)
    {
        try
        {
            return File.Open(path, FileMode.Open, FileAccess.Read, FileShare.Read);
        }
        catch (Exception ex) when (ex is FileNotFoundException or DirectoryNotFoundException)
        {
            throw new ZeeKayDaConfigurationException(new ZeeKayDaConfigurationFailure(
                "signing.file_signing.file_not_found",
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
        // Inspect the open handle's resolved name, not the original path string, for the leaf file.
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
            if (new DirectoryInfo(directory).LinkTarget is not null)
                throw SymlinkDetected(originalPath, resolvedPath, directory);

            directory = Path.GetDirectoryName(directory);
        }
    }

    [UnsupportedOSPlatform("windows")]
    private static void ValidateNoUntrustedSymlinkedAncestorUnix(string originalPath, string resolvedPath)
    {
        // Unlike the Windows walk above, "any symlinked ancestor is a redirect attack" does not hold
        // on Unix: macOS ships /tmp, /var, and /etc as symlinks to /private/..., and this provider
        // is the recommended one for macOS, so rejecting those paths would make it unusable there.
        // The trust signal is ownership of the directory entry itself, not symlink-ness: an attacker
        // without root cannot plant or replace a root-owned entry, so a root-owned symlinked
        // ancestor is as trustworthy as a non-symlinked one. The walk stops at the first root-owned
        // directory, since everything above it is equally OS-managed.
        //
        // This MUST use PosixInterop.GetLinkOwnerUid (lstat), never GetOwnerUid (stat): stat()
        // follows the symlink and reports the target's owner, which an attacker controls by
        // choosing where their symlink points — e.g. pointing at root-owned /tmp would wrongly read
        // as root-owned and short-circuit this check. lstat() reports the link entry's own owner.
        var directory = Path.GetDirectoryName(resolvedPath);
        while (!string.IsNullOrEmpty(directory))
        {
            var ownerUid = PosixInterop.GetLinkOwnerUid(directory);
            if (ownerUid == 0)
                break;

            if (new DirectoryInfo(directory).LinkTarget is not null)
                throw SymlinkDetected(originalPath, resolvedPath, directory);

            directory = Path.GetDirectoryName(directory);
        }
    }

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
    private static void ValidateModeUnix(FileStream stream, string path)
    {
        // Checked on the already-open handle (via SafeFileHandle) rather than the path string, so
        // this cannot be TOCTOU-raced between the open above and this check.
        var mode = File.GetUnixFileMode(stream.SafeFileHandle);

        if ((mode & DisallowedUnixModeBits) != 0)
        {
            throw new ZeeKayDaConfigurationException(new ZeeKayDaConfigurationFailure(
                "signing.file_signing.file_too_permissive",
                $"Signing key file '{path}' has permissions broader than 0600 (found {DescribeUnixMode(mode)}). " +
                "A file readable or writable by group or other users is treated as compromised. " +
                "Run 'chmod 600' on the file and restart the application."));
        }
    }

    [SupportedOSPlatform("windows")]
    private static void ValidateAclWindows(FileStream stream, string path)
    {
        // GetAccessControl(FileStream) reads the DACL from the already-open handle, closing the
        // same TOCTOU window the Unix mode check closes via SafeFileHandle.
        var security = stream.GetAccessControl();
        var rules = security.GetAccessRules(includeExplicit: true, includeInherited: true, typeof(SecurityIdentifier));

        var hasBroadAllowRule = rules
            .OfType<FileSystemAccessRule>()
            .Where(rule => rule.AccessControlType == AccessControlType.Allow)
            .Any(rule => rule.IdentityReference is SecurityIdentifier sid && IsBroadPrincipal(sid));

        if (hasBroadAllowRule)
        {
            throw new ZeeKayDaConfigurationException(new ZeeKayDaConfigurationFailure(
                "signing.file_signing.file_too_permissive",
                $"Signing key file '{path}' grants access to a broad principal ('Everyone', " +
                "'Users', or 'Authenticated Users'). Restrict the file's ACL to the process " +
                "identity only, with inheritance disabled, and restart the application."));
        }
    }

    [SupportedOSPlatform("windows")]
    private static bool IsBroadPrincipal(SecurityIdentifier sid) =>
        sid.IsWellKnown(WellKnownSidType.WorldSid)
        || sid.IsWellKnown(WellKnownSidType.BuiltinUsersSid)
        || sid.IsWellKnown(WellKnownSidType.AuthenticatedUserSid);

    private static string DescribeUnixMode(UnixFileMode mode) =>
        "0" + Convert.ToString((int)mode & 0x1FF, 8).PadLeft(3, '0');

    /// <summary>
    /// Best-effort, log-only checks for a network-filesystem volume and a world-writable parent
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
            _logger.LogDebug(ex, "ZeeKayDa.Auth: could not evaluate the environment safety heuristics for signing key file '{Path}'.", path);
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
            _logger.LogWarning(
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
            if ((mode & UnixFileMode.OtherWrite) != 0)
            {
                _logger.LogWarning(
                    "ZeeKayDa.Auth: the parent directory '{Directory}' of signing key file '{Path}' is " +
                    "world-writable. Another local user could replace or redirect files in this " +
                    "directory. Restrict the directory's permissions.",
                    parent, path);
            }
        }
    }

    [SupportedOSPlatform("windows")]
    private void WarnIfParentDirectoryWorldWritableWindows(string path, string parent)
    {
        var security = new DirectoryInfo(parent).GetAccessControl();
        var rules = security.GetAccessRules(includeExplicit: true, includeInherited: true, typeof(SecurityIdentifier));

        const FileSystemRights WriteRights = FileSystemRights.Write | FileSystemRights.WriteData | FileSystemRights.CreateFiles;

        var hasBroadWritableRule = rules
            .OfType<FileSystemAccessRule>()
            .Where(rule => rule.AccessControlType == AccessControlType.Allow)
            .Where(rule => rule.IdentityReference is SecurityIdentifier sid && IsBroadPrincipal(sid))
            .Any(rule => (rule.FileSystemRights & WriteRights) != 0);

        if (hasBroadWritableRule)
        {
            _logger.LogWarning(
                "ZeeKayDa.Auth: the parent directory '{Directory}' of signing key file '{Path}' " +
                "grants write access to a broad principal ('Everyone', 'Users', or 'Authenticated " +
                "Users'). Another local user could replace or redirect files in this directory. " +
                "Restrict the directory's ACL.",
                parent, path);
        }
    }
}
