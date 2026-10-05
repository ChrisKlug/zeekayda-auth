using System.Diagnostics.CodeAnalysis;

namespace ZeeKayDa.Auth.Tokens;

/// <summary>
/// Yes/no checks on token endpoint authentication method names, shared by the server's
/// <c>TokenEndpoint.AdvertisedAuthMethods</c> and a client's <c>AllowedTokenEndpointAuthMethods</c>.
/// </summary>
internal static class TokenEndpointAuthMethodRules
{
    /// <summary>Null, empty, or whitespace only.</summary>
    internal static bool IsBlank([NotNullWhen(false)] string? method) => string.IsNullOrWhiteSpace(method);

    internal static bool HasSurroundingWhitespace(string method) => method != method.Trim();

    internal static bool HasControlCharacters(string method) => method.Any(char.IsControl);

    /// <summary>Not blank, no leading or trailing whitespace, and no control characters.</summary>
    internal static bool IsWellFormed([NotNullWhen(true)] string? method) =>
        !IsBlank(method)
        && !HasSurroundingWhitespace(method)
        && !HasControlCharacters(method);

    /// <summary>
    /// Whether the methods include <c>none</c>. Compares ordinally rather than trusting the set's
    /// own comparer, which a custom registration may have made case-insensitive.
    /// </summary>
    internal static bool AllowsNone(IEnumerable<string> methods) => methods.Any(IsNone);

    /// <summary>Whether there is at least one method and every one is <c>none</c>: no methods allows nothing.</summary>
    internal static bool AllowsOnlyNone(IEnumerable<string> methods)
    {
        var any = false;
        foreach (var method in methods)
        {
            if (!IsNone(method))
                return false;

            any = true;
        }

        return any;
    }

    private static bool IsNone(string? method)
        => string.Equals(method, TokenEndpointAuthMethods.None, StringComparison.Ordinal);
}
