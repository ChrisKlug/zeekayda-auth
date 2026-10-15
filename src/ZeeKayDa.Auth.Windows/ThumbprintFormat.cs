namespace ZeeKayDa.Auth.Windows;

/// <summary>Normalizes thumbprints copied from tooling, which often carry spaces or an invisible U+200E mark.</summary>
internal static class ThumbprintFormat
{
    /// <summary>Strips every character that is not a hex digit and uppercases the remainder.</summary>
    public static string Normalize(string thumbprint) =>
        new string([.. thumbprint.Where(Uri.IsHexDigit)]).ToUpperInvariant();
}
