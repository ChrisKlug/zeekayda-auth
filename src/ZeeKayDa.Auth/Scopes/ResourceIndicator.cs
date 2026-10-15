namespace ZeeKayDa.Auth.Scopes;

/// <summary>
/// Whether a string is an RFC 8707 §2 resource indicator: an absolute URI, scheme written, no fragment,
/// in RFC 3986's grammar as written.
/// </summary>
/// <remarks>
/// Checked character by character because <see cref="Uri"/> silently canonicalizes what RFC 3986 forbids,
/// and the raw string is what becomes <c>aud</c>; a round-trip through <see cref="Uri.AbsoluteUri"/> would
/// refuse an authority-only URI for its added slash.
/// </remarks>
internal static class ResourceIndicator
{
    /// <summary>Whether <paramref name="audience"/> is a resource indicator; the scheme must be written, as <see cref="Uri"/> reads a bare path as a file.</summary>
    public static bool IsValid(string audience)
    {
        ArgumentNullException.ThrowIfNull(audience);

        return Uri.TryCreate(audience, UriKind.Absolute, out var uri)
            && !audience.Contains('#')
            && audience.StartsWith(uri.Scheme + ":", StringComparison.OrdinalIgnoreCase)
            && IsWellFormed(audience);
    }

    /// <summary>Every character permitted where it stands (RFC 3986 §2), and every <c>%</c> a valid escape.</summary>
    private static bool IsWellFormed(string value)
    {
        var authority = AuthoritySpan(value);

        for (var i = 0; i < value.Length; i++)
        {
            if (value[i] == '%')
            {
                if (!BeginsPercentEscape(value, i))
                    return false;

                i += 2;
                continue;
            }

            if (!IsAllowedAt(value[i], i, authority))
                return false;
        }

        return true;
    }

    /// <summary>
    /// Whether <paramref name="c"/> is permitted at <paramref name="index"/>: brackets only inside the
    /// authority, as an IP-literal host (§3.2.2), such as <c>https://[::1]/api</c>.
    /// </summary>
    private static bool IsAllowedAt(char c, int index, (int Start, int End) authority) =>
        c is '[' or ']'
            ? index >= authority.Start && index < authority.End
            : IsAllowedUriCharacter(c);

    /// <summary>Whether the <c>%</c> at <paramref name="index"/> starts exactly two hex digits (RFC 3986 §2.1).</summary>
    private static bool BeginsPercentEscape(string value, int index)
    {
        if (index + 2 >= value.Length)
            return false;

        if (!Uri.IsHexDigit(value[index + 1]))
            return false;

        return Uri.IsHexDigit(value[index + 2]);
    }

    /// <summary>RFC 3986 §2 unreserved, gen-delims and sub-delims; <c>%</c> and brackets are judged by the callers.</summary>
    private static bool IsAllowedUriCharacter(char c) =>
        c is >= 'A' and <= 'Z' or >= 'a' and <= 'z' or >= '0' and <= '9'
        || c is '-' or '.' or '_' or '~'
        || c is ':' or '/' or '?' or '#' or '@'
        || c is '!' or '$' or '&' or '\'' or '(' or ')' or '*' or '+' or ',' or ';' or '=';

    /// <summary>The half-open range after <c>://</c> up to the next <c>/</c>, <c>?</c> or <c>#</c>; empty for a URN.</summary>
    private static (int Start, int End) AuthoritySpan(string value)
    {
        var marker = value.IndexOf("://", StringComparison.Ordinal);
        if (marker < 0)
            return (0, 0);

        var start = marker + 3;
        var end = value.IndexOfAny(['/', '?', '#'], start);

        return (start, end < 0 ? value.Length : end);
    }
}
