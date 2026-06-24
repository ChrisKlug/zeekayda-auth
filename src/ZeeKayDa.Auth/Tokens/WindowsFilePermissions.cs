using System.Runtime.InteropServices;
using System.Runtime.Versioning;
using System.Security.AccessControl;
using System.Security.Principal;

namespace ZeeKayDa.Auth.Tokens;

/// <summary>
/// Applies restrictive Windows ACLs to signing key files and directories.
/// Only compiled and invoked on Windows.
/// </summary>
[SupportedOSPlatform("windows")]
internal static class WindowsFilePermissions
{
    /// <summary>
    /// Replaces the ACL on a signing key file so that only the current user (and SYSTEM /
    /// Administrators) have access. Inheritance is disabled.
    /// </summary>
    /// <param name="filePath">The path to the key file.</param>
    internal static void SetRestrictiveAcl(string filePath)
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

    /// <summary>
    /// Applies a restrictive ACL to the signing key directory so that only the current user
    /// (and SYSTEM / Administrators) have access. Inheritance is disabled.
    /// </summary>
    /// <param name="directoryPath">The path to the key directory.</param>
    internal static void SetRestrictiveDirectoryAcl(string directoryPath)
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
