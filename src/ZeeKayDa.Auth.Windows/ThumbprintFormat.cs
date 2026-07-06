namespace ZeeKayDa.Auth.Windows;

/// <summary>
/// Normalizes certificate thumbprints copied from tooling such as <c>certmgr</c>, PowerShell, or
/// the Certificates MMC snap-in, which frequently carry embedded whitespace or an invisible
/// leading U+200E LEFT-TO-RIGHT MARK.
/// </summary>
internal static class ThumbprintFormat
{
    /// <summary>
    /// Strips every character that is not a hex digit and uppercases the remainder, so thumbprints
    /// entered with different casing or copy-paste artifacts still compare and look up correctly.
    /// </summary>
    public static string Normalize(string thumbprint) =>
        new string([.. thumbprint.Where(Uri.IsHexDigit)]).ToUpperInvariant();
}
