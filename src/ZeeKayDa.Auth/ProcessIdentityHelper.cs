using System.Runtime.InteropServices;
using System.Runtime.Versioning;
using System.Security.Principal;

namespace ZeeKayDa.Auth;

/// <summary>
/// Internal helpers for resolving the current process identity for inclusion in access-denied
/// diagnostic messages, best-effort.
/// </summary>
/// <remarks>
/// Lives in the core <c>ZeeKayDa.Auth</c> assembly so that both the file-based signing provider
/// (<c>ZeeKayDa.Auth.FileSystem</c>) and the Windows Certificate Store signing provider
/// (<c>ZeeKayDa.Auth.Windows</c>) share a single implementation of "resolve the process identity,
/// but never let resolution itself become the failure it was meant to explain". Exposed to both
/// via the <c>InternalsVisibleTo</c> declarations in <c>ZeeKayDaAuth.cs</c>.
/// </remarks>
internal static class ProcessIdentityHelper
{
    /// <summary>
    /// Formats the resolved process identity, if any, as a parenthetical suffix for an access-denied
    /// diagnostic message. A <see langword="null"/> or empty <paramref name="identity"/> — the
    /// best-effort degradation outcome when resolution fails or returns nothing usable — yields an
    /// empty suffix rather than a misleading or malformed message.
    /// </summary>
    public static string FormatIdentitySuffix(string? identity) =>
        string.IsNullOrEmpty(identity) ? string.Empty : $" (running as '{identity}')";

    /// <summary>
    /// Resolves the current process identity for inclusion in an access-denied diagnostic message,
    /// best-effort. Identity resolution must never throw or mask the real root cause of the failure
    /// it is meant to enrich — this call typically runs inside a throw expression that wraps a real
    /// <see cref="UnauthorizedAccessException"/>, so an uncaught exception here would silently
    /// replace that root cause with an unrelated one. Every exception from the platform-specific
    /// identity lookup — including <see cref="System.IO.IOException"/> from
    /// <see cref="Environment.UserName"/> on Unix, and <see cref="IdentityNotMappedException"/> or
    /// other <see cref="SystemException"/>s from <see cref="WindowsIdentity.GetCurrent()"/> on
    /// Windows — is therefore caught and degrades to <see langword="null"/>, which
    /// <see cref="FormatIdentitySuffix"/> then omits from the message.
    /// </summary>
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
