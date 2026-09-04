namespace ZeeKayDa.Auth.AspNetCore.Providers;

/// <summary>
/// The grammar a provider name must satisfy before any route is built from it: one to
/// <see cref="MaxLength"/> ASCII letters, digits, <c>-</c>, <c>_</c> or <c>.</c>, and never a
/// dot-segment.
/// </summary>
/// <remarks>
/// The name becomes a path segment of the provider's callback route, so anything a URL parser
/// would treat specially is refused rather than escaped.
/// </remarks>
internal static class ProviderName
{
    public const int MaxLength = 64;

    /// <summary>The grammar in prose, for the message a rejected name gets.</summary>
    public const string Grammar =
        "1 to 64 ASCII letters, digits, '-', '_' or '.', and neither '.' nor '..'";

    public static bool IsValid(string name)
    {
        ArgumentNullException.ThrowIfNull(name);

        if (name.Length is < 1 or > MaxLength)
            return false;

        if (name is "." or "..")
            return false;

        return name.All(IsAllowed);
    }

    private static bool IsAllowed(char c) => char.IsAsciiLetterOrDigit(c) || c is '-' or '_' or '.';
}
