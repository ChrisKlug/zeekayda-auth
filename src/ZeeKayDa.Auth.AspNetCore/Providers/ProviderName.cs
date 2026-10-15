namespace ZeeKayDa.Auth.AspNetCore.Providers;

/// <summary>
/// The grammar a provider name must satisfy: one to <see cref="MaxLength"/> ASCII letters, digits,
/// <c>-</c>, <c>_</c> or <c>.</c>, never a dot-segment, since it becomes a callback path segment.
/// </summary>
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
