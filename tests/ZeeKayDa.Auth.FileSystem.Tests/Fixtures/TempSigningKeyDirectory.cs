using System.Runtime.Versioning;
using System.Security.AccessControl;
using System.Security.Cryptography.X509Certificates;
using System.Security.Principal;

namespace ZeeKayDa.Auth.FileSystem.Tests.Fixtures;

/// <summary>
/// Manages a per-test temporary directory holding real PEM/PFX signing-key files, secured to the
/// current process identity by default (mirroring what a correctly-configured operator deployment
/// looks like), with a way to deliberately widen a file's permissions for the "too permissive"
/// negative tests.
/// </summary>
/// <remarks>
/// This provider's entire job is real filesystem interaction (permission enforcement, symlink
/// detection) — faking <c>FileSigningKeyReader</c>'s dependencies would test nothing meaningful, so
/// every test that exercises it does so against real files created here, not a fake reader.
/// </remarks>
internal sealed class TempSigningKeyDirectory : IDisposable
{
    /// <summary>
    /// The directory's fully-resolved (no-symlinked-ancestor) real path.
    /// </summary>
    /// <remarks>
    /// <para>
    /// <strong>Not just <c>Directory.CreateTempSubdirectory().FullName</c> as-is.</strong> On
    /// macOS, <c>/tmp</c>, <c>/var</c>, and <c>/etc</c> are themselves symlinks to
    /// <c>/private/tmp</c>/<c>/private/var</c>/<c>/private/etc</c> — a long-standing, universal
    /// platform characteristic, not a local machine quirk — and <c>Path.GetTempPath()</c> (and
    /// therefore <c>Directory.CreateTempSubdirectory()</c>) returns a path under <c>/var/folders/...</c>.
    /// <see cref="FileSigningKeyReader"/>'s ancestor-symlink walk (by design — it is what rejects a
    /// deliberately-planted symlinked ancestor as a redirect attack) then rejects <em>every</em> file
    /// under the OS-standard temp directory with <c>signing.file_signing.symlink_detected</c>, which
    /// is an incidental false positive for a test fixture, not the deliberate-attack scenario that
    /// check exists to catch. Resolving to the real path here keeps this fixture's other tests
    /// (rotation, permissions, parsing) measuring the behavior they are meant to, while
    /// <see cref="ZeeKayDa.Auth.FileSystem.Tests.PemFileSigningJwtSigningServiceTests.GetSigningKeysAsync_throws_when_the_registered_path_is_a_symlink"/>
    /// separately and deliberately plants its own symlink to prove that real check still fires.
    /// </para>
    /// <para>
    /// <strong>This was also a live product concern, not just a test-fixture inconvenience</strong> —
    /// since fixed in <see cref="FileSigningKeyReader"/>: because this provider is the sole
    /// recommended signing provider for macOS (ADR 0011 Amendment 7; issue #291), an operator who
    /// pointed <c>AddPemFileSigning</c>/<c>AddPfxFileSigning</c> at a path under <c>/tmp</c>,
    /// <c>/var</c>, or <c>/etc</c> on macOS — all common locations — would have hit this same
    /// false-positive rejection in production.
    /// <c>FileSigningKeyReader.ValidateNoUntrustedSymlinkedAncestorUnix</c> now stops its
    /// ancestor-symlink walk at the first root-owned directory (the same trust anchor
    /// <c>LocalSigningKeyFileSystem.ValidateDirectoryChainOwnershipUnix</c> already uses), so an
    /// OS-managed symlink no longer false-positives while a genuinely attacker-plantable symlinked
    /// ancestor still does — see
    /// <see cref="ZeeKayDa.Auth.FileSystem.Tests.FileSigningKeyReaderTests.ReadPemTextAsync_succeeds_for_a_file_under_the_OS_temp_directory_on_Unix"/>
    /// and its sibling
    /// <see cref="ZeeKayDa.Auth.FileSystem.Tests.FileSigningKeyReaderTests.ReadPemTextAsync_still_throws_for_a_file_under_a_non_root_owned_symlinked_ancestor_on_Unix"/>.
    /// This fixture still resolves the real path up front regardless, so its other tests (rotation,
    /// permissions, parsing) measure only the behavior they are meant to.
    /// </para>
    /// </remarks>
    public string DirectoryPath { get; } = ResolveRealPath(Directory.CreateTempSubdirectory("zkda-filesystem-tests-").FullName);

    public string GetPath(string fileName) => Path.Combine(DirectoryPath, fileName);

    /// <summary>
    /// Resolves every symlinked ancestor directory in <paramref name="path"/> to its real target,
    /// using the same <see cref="FileSystemInfo.LinkTarget"/> API
    /// <c>FileSigningKeyReader.ValidateNoSymlink</c> itself inspects.
    /// </summary>
    private static string ResolveRealPath(string path)
    {
        var fullPath = Path.GetFullPath(path);

        // Bounded loop: a resolved target can itself turn out to be (or contain) another symlink;
        // in practice this converges in one pass (e.g. macOS's /var -> /private/var, where
        // /private is not itself a symlink), but re-running until stable is defensive rather than
        // assuming exactly one level of indirection.
        for (var iteration = 0; iteration < 5; iteration++)
        {
            var resolved = ResolveOnePass(fullPath);
            if (string.Equals(resolved, fullPath, StringComparison.Ordinal))
                return resolved;

            fullPath = resolved;
        }

        return fullPath;
    }

    private static string ResolveOnePass(string fullPath)
    {
        var root = Path.GetPathRoot(fullPath) ?? string.Empty;
        var segments = fullPath[root.Length..].Split(Path.DirectorySeparatorChar, StringSplitOptions.RemoveEmptyEntries);

        // Path.Combine (not string concatenation) correctly handles a bare root like "/" on Unix,
        // where naive concatenation would otherwise silently drop the leading separator.
        var resolved = root;
        foreach (var segment in segments)
        {
            resolved = Path.Combine(resolved, segment);

            if (!Directory.Exists(resolved))
                continue;

            var linkTarget = new DirectoryInfo(resolved).LinkTarget;
            if (linkTarget is null)
                continue;

            resolved = Path.IsPathRooted(linkTarget)
                ? linkTarget
                : Path.GetFullPath(Path.Combine(Path.GetDirectoryName(resolved) ?? root, linkTarget));
        }

        return resolved;
    }

    /// <summary>Writes a combined cert+key PEM file (this provider's required single-file shape), secured to the current identity only.</summary>
    public string WritePemFile(string fileName, X509Certificate2 certificate)
    {
        var path = GetPath(fileName);
        File.WriteAllText(path, BuildCombinedPem(certificate));
        SecureToCurrentIdentity(path);
        return path;
    }

    /// <summary>Writes arbitrary (e.g. deliberately invalid) text content as a would-be PEM file, still secured.</summary>
    public string WriteTextFile(string fileName, string content)
    {
        var path = GetPath(fileName);
        File.WriteAllText(path, content);
        SecureToCurrentIdentity(path);
        return path;
    }

    /// <summary>Writes a PFX/PKCS#12 bundle, secured to the current process identity only.</summary>
    public string WritePfxFile(string fileName, X509Certificate2 certificate, string password)
    {
        var path = GetPath(fileName);
        File.WriteAllBytes(path, certificate.Export(X509ContentType.Pfx, password));
        SecureToCurrentIdentity(path);
        return path;
    }

    /// <summary>Builds the combined cert+key PEM text <c>AddPemFileSigning</c> expects in a single file.</summary>
    public static string BuildCombinedPem(X509Certificate2 certificate)
    {
        var certPem = certificate.ExportCertificatePem();
        var keyPem = certificate.GetRSAPrivateKey() is { } rsa
            ? rsa.ExportPkcs8PrivateKeyPem()
            : certificate.GetECDsaPrivateKey()!.ExportPkcs8PrivateKeyPem();
        return certPem + Environment.NewLine + keyPem + Environment.NewLine;
    }

    /// <summary>
    /// Widens an already-written file's permissions beyond what <c>FileSigningKeyReader</c> allows
    /// (issue #291 AC #2/#6: broader-than-0600 Unix mode, or a broad-principal Windows ACL entry).
    /// </summary>
    public void MakeTooPermissive(string path)
    {
        if (OperatingSystem.IsWindows())
            GrantEveryoneReadWindows(path);
        else
            File.SetUnixFileMode(path, UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.OtherRead);
    }

    /// <summary>
    /// Widens this fixture's own directory to be world-writable, to exercise
    /// <c>FileSigningKeyReader</c>'s best-effort (log-only, non-fatal) world-writable-parent-directory
    /// warning. Unix only — the Windows ACL equivalent is a separate, dedicated code path; a no-op
    /// on Windows, since the caller is expected to skip the Unix-specific test that uses this.
    /// </summary>
    public void MakeParentDirectoryWorldWritable()
    {
        if (OperatingSystem.IsWindows())
            return;

        File.SetUnixFileMode(DirectoryPath, UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute
            | UnixFileMode.OtherRead | UnixFileMode.OtherWrite | UnixFileMode.OtherExecute);
    }

    private static void SecureToCurrentIdentity(string path)
    {
        if (OperatingSystem.IsWindows())
            RestrictToCurrentUserWindows(path);
        else
            File.SetUnixFileMode(path, UnixFileMode.UserRead | UnixFileMode.UserWrite);
    }

    [SupportedOSPlatform("windows")]
    private static void RestrictToCurrentUserWindows(string path)
    {
        var fileInfo = new FileInfo(path);
        var security = fileInfo.GetAccessControl();
        // Break inheritance and drop every existing (inherited or explicit) rule first, so the
        // outcome does not depend on the CI runner's %TEMP% ACL — deterministic across machines.
        security.SetAccessRuleProtection(isProtected: true, preserveInheritance: false);
        foreach (FileSystemAccessRule rule in security.GetAccessRules(true, true, typeof(SecurityIdentifier)))
            security.RemoveAccessRule(rule);

        var currentUser = WindowsIdentity.GetCurrent().User!;
        security.AddAccessRule(new FileSystemAccessRule(currentUser, FileSystemRights.FullControl, AccessControlType.Allow));
        fileInfo.SetAccessControl(security);
    }

    [SupportedOSPlatform("windows")]
    private static void GrantEveryoneReadWindows(string path)
    {
        var fileInfo = new FileInfo(path);
        var security = fileInfo.GetAccessControl();
        security.AddAccessRule(new FileSystemAccessRule(
            new SecurityIdentifier(WellKnownSidType.WorldSid, domainSid: null),
            FileSystemRights.Read,
            AccessControlType.Allow));
        fileInfo.SetAccessControl(security);
    }

    public void Dispose()
    {
        try
        {
            if (!OperatingSystem.IsWindows())
            {
                // A test may have narrowed a file to 0400 or widened it to something Directory.Delete
                // cannot clean up as a non-owner-writable entry; restore write access before deleting.
                foreach (var file in Directory.EnumerateFiles(DirectoryPath))
                    File.SetUnixFileMode(file, UnixFileMode.UserRead | UnixFileMode.UserWrite);
            }

            Directory.Delete(DirectoryPath, recursive: true);
        }
        catch
        {
            // Best-effort cleanup only — a leftover temp directory must never fail a test.
        }
    }
}
