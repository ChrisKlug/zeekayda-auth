using System.Diagnostics.CodeAnalysis;

namespace ZeeKayDa.Auth.Tokens;

/// <summary>
/// Yes/no checks on token endpoint authentication method names, shared by the server's
/// <c>TokenEndpoint.AuthMethodsSupported</c> and a client's <c>AllowedTokenEndpointAuthMethods</c>.
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

    /// <summary>Whether every method is <c>none</c>; vacuously true when there are no methods.</summary>
    internal static bool AllowsOnlyNone(IEnumerable<string> methods) => methods.All(IsNone);

    /// <summary>
    /// Whether the methods are exactly one entry and it is <c>none</c>. Enumerates rather than
    /// trusting the set's <c>Count</c>, which a custom registration may misreport.
    /// </summary>
    internal static bool IsExactlyNone(IEnumerable<string> methods)
    {
        using var enumerator = methods.GetEnumerator();
        return enumerator.MoveNext() && IsNone(enumerator.Current) && !enumerator.MoveNext();
    }

    private static bool IsNone(string? method)
        => string.Equals(method, TokenEndpointAuthMethods.None, StringComparison.Ordinal);
}
