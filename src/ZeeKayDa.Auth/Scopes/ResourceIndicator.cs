namespace ZeeKayDa.Auth.Scopes;

/// <summary>
/// Whether a string is a resource indicator as RFC 8707 §2 defines one: an absolute URI with no
/// fragment, written with its scheme, and conforming to RFC 3986's grammar as written.
/// </summary>
/// <remarks>
/// <para>
/// <strong>Its own type because parsing is not validation here.</strong>
/// <see cref="Uri.TryCreate(string, UriKind, out Uri)"/> accepts and silently canonicalizes input
/// RFC 3986 does not allow — a raw space, a non-ASCII letter, a stray <c>%</c> — turning
/// <c>https://api.example.com/orders v2</c> into <c>…/orders%20v2</c>. It is the original string,
/// not the canonical form, that this framework carries into an access token's <c>aud</c> claim, so
/// accepting on the parse would let a value no conforming resource server can match reach the
/// token: relying parties that compare raw and relying parties that normalize first would disagree
/// about who was named.
/// </para>
/// <para>
/// Round-tripping against <see cref="Uri.AbsoluteUri"/> would not do instead: it appends a path to
/// an authority-only URI, so <c>https://api.example.com</c> — a valid resource indicator — would be
/// refused for differing from <c>https://api.example.com/</c>. The characters are therefore checked
/// directly, and the parser is kept for the structural question it does answer well.
/// </para>
/// </remarks>
internal static class ResourceIndicator
{
    /// <summary>
    /// Whether <paramref name="audience"/> is a resource indicator. The scheme must be written,
    /// since <see cref="Uri"/> reads a bare path as a file URI on some platforms and the raw
    /// string is what a token would carry.
    /// </summary>
    public static bool IsValid(string audience)
    {
        ArgumentNullException.ThrowIfNull(audience);

        return Uri.TryCreate(audience, UriKind.Absolute, out var uri)
            && !audience.Contains('#')
            && audience.StartsWith(uri.Scheme + ":", StringComparison.OrdinalIgnoreCase)
            && IsWellFormed(audience);
    }

    /// <summary>
    /// Whether every character is one RFC 3986 §2 permits, in a place it permits it, and every
    /// <c>%</c> begins a valid percent-encoding. The fragment delimiter is the caller's separate
    /// check.
    /// </summary>
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
    /// Whether <paramref name="c"/> is permitted at <paramref name="index"/>. Only the brackets
    /// depend on where they are.
    /// </summary>
    /// <remarks>
    /// §3.2.2 permits a bracket only in an IP-literal host, so one anywhere else is not a
    /// delimiter the grammar has a place for. <see cref="Uri"/> accepts one in a path, and a
    /// resource server comparing against its percent-encoded form would not match what the token
    /// carries. An IPv6 audience such as <c>https://[::1]/api</c> stays valid.
    /// </remarks>
    private static bool IsAllowedAt(char c, int index, (int Start, int End) authority) =>
        c is '[' or ']'
            ? index >= authority.Start && index < authority.End
            : IsAllowedUriCharacter(c);

    /// <summary>
    /// Whether the <c>%</c> at <paramref name="index"/> introduces exactly two hex digits. A bare
    /// percent is not an escape, and RFC 3986 §2.1 admits no other form.
    /// </summary>
    private static bool BeginsPercentEscape(string value, int index)
    {
        if (index + 2 >= value.Length)
            return false;

        if (!Uri.IsHexDigit(value[index + 1]))
            return false;

        return Uri.IsHexDigit(value[index + 2]);
    }

    /// <summary>
    /// RFC 3986 §2: unreserved, gen-delims and sub-delims. Percent is handled by the caller, which
    /// reads it with the two digits that must follow it, and the brackets by
    /// <see cref="IsAllowedAt"/>, which knows where they are.
    /// </summary>
    private static bool IsAllowedUriCharacter(char c) =>
        c is >= 'A' and <= 'Z' or >= 'a' and <= 'z' or >= '0' and <= '9'
        || c is '-' or '.' or '_' or '~'
        || c is ':' or '/' or '?' or '#' or '@'
        || c is '!' or '$' or '&' or '\'' or '(' or ')' or '*' or '+' or ',' or ';' or '=';

    /// <summary>
    /// The half-open range of the authority component — what follows <c>://</c> up to the next
    /// <c>/</c>, <c>?</c> or <c>#</c> — or an empty range for a URI that has no authority, such as
    /// <c>urn:example:orders</c>.
    /// </summary>
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
