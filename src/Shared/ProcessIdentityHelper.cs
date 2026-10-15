using System.Runtime.InteropServices;
using System.Runtime.Versioning;
using System.Security.Principal;

namespace ZeeKayDa.Auth;

/// <summary>Names the process identity in an access-denied message, best-effort. Linked into each provider that needs it.</summary>
internal static class ProcessIdentityHelper
{
    /// <summary>Formats the identity as a message suffix; empty when it could not be resolved.</summary>
    public static string FormatIdentitySuffix(string? identity) =>
        string.IsNullOrEmpty(identity) ? string.Empty : $" (running as '{identity}')";

    /// <summary>The process identity, or <see langword="null"/>; never throws, since it runs while reporting another failure.</summary>
    public static string? TryResolveProcessIdentity()
    {
        try
        {
            return RuntimeInformation.IsOSPlatform(OSPlatform.Windows)
                ? TryResolveWindowsIdentity()
                : Environment.UserName;
        }
        catch (Exception)
        {
            return null;
        }
    }

    [SupportedOSPlatform("windows")]
    private static string? TryResolveWindowsIdentity() => WindowsIdentity.GetCurrent().Name;
}
