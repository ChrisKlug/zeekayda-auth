namespace ZeeKayDa.Auth.Scopes;

/// <summary>
/// Resolves scope names against the repository's definitions, and derives the one audience a
/// set of granted scopes names.
/// </summary>
internal static class ScopeResolution
{
    /// <summary>
    /// The definition of every name in <paramref name="names"/>, in that order, compared
    /// ordinally. Fails on the first name with no definition, which has no audience to correlate
    /// to and no claims to unlock.
    /// </summary>
    public static bool TryResolve(
        IReadOnlyCollection<ScopeDefinition> definitions,
        IReadOnlyList<string> names,
        out IReadOnlyList<ScopeDefinition> resolved,
        out string? undefined)
    {
        ArgumentNullException.ThrowIfNull(definitions);
        ArgumentNullException.ThrowIfNull(names);

        var byName = new Dictionary<string, ScopeDefinition>(StringComparer.Ordinal);
        foreach (var definition in definitions)
            byName.TryAdd(definition.Name, definition);

        var found = new List<ScopeDefinition>(names.Count);
        foreach (var name in names)
        {
            if (!byName.TryGetValue(name, out var definition))
            {
                resolved = [];
                undefined = name;
                return false;
            }

            found.Add(definition);
        }

        resolved = found;
        undefined = null;
        return true;
    }

    /// <summary>
    /// The resource server the granted scopes are for: the one distinct <see cref="ScopeDefinition.Audience"/>
    /// among them, compared ordinally (RFC 7519 §4.1.3), or <see langword="null"/> when none has one.
    /// Fails when two distinct values are present, since without a <c>resource</c> parameter
    /// there is nothing to choose between them (RFC 9068 §3). Whether the one value is a
    /// resource indicator is the caller's separate question, since the two answers are refused
    /// differently: an ambiguous request is the client's, a malformed audience the operator's.
    /// </summary>
    public static bool TryResolveAudience(IEnumerable<ScopeDefinition> granted, out string? audience)
    {
        ArgumentNullException.ThrowIfNull(granted);

        var audiences = granted
            .Select(scope => scope.Audience)
            .OfType<string>()
            .Distinct(StringComparer.Ordinal)
            .ToList();

        audience = audiences.Count == 1 ? audiences[0] : null;
        return audiences.Count <= 1;
    }

    /// <summary>
    /// RFC 8707 §2: an absolute URI with no fragment, empty or otherwise. The scheme must be
    /// written, since <see cref="Uri"/> reads a bare path as a file URI on some platforms and the
    /// raw string is what a token would carry.
    /// </summary>
    /// <remarks>
    /// <para>
    /// <strong>The characters are checked directly, because parsing is not validation here.</strong>
    /// <see cref="Uri.TryCreate(string, UriKind, out Uri)"/> accepts and silently canonicalizes
    /// input RFC 3986 does not allow — a raw space, a non-ASCII letter, a stray <c>%</c> — turning
    /// <c>https://api.example.com/orders v2</c> into <c>…/orders%20v2</c>. It is the original
    /// string, not the canonical form, that this framework carries into an access token's
    /// <c>aud</c> claim, so accepting on the parse would let a value no conforming resource server
    /// can match reach the token: relying parties that compare raw and relying parties that
    /// normalize first would disagree about who was named.
    /// </para>
    /// <para>
    /// Round-tripping against <see cref="Uri.AbsoluteUri"/> would not do instead: it appends a
    /// path to an authority-only URI, so <c>https://api.example.com</c> — a valid resource
    /// indicator — would be refused for differing from <c>https://api.example.com/</c>.
    /// </para>
    /// </remarks>
    public static bool IsResourceIndicator(string audience)
    {
        ArgumentNullException.ThrowIfNull(audience);

        return Uri.TryCreate(audience, UriKind.Absolute, out var uri)
            && !audience.Contains('#')
            && audience.StartsWith(uri.Scheme + ":", StringComparison.OrdinalIgnoreCase)
            && IsWellFormedRfc3986(audience);
    }

    /// <summary>
    /// Whether every character is one RFC 3986 §2 permits in a URI, and every <c>%</c> begins a
    /// valid percent-encoding. The fragment delimiter is the caller's separate check.
    /// </summary>
    private static bool IsWellFormedRfc3986(string value)
    {
        for (var i = 0; i < value.Length; i++)
        {
            if (value[i] != '%')
            {
                if (!IsAllowedUriCharacter(value[i]))
                    return false;

                continue;
            }

            if (!BeginsPercentEscape(value, i))
                return false;

            i += 2;
        }

        return true;
    }

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
    /// reads it together with the two digits that must follow it.
    /// </summary>
    private static bool IsAllowedUriCharacter(char c) =>
        c is >= 'A' and <= 'Z' or >= 'a' and <= 'z' or >= '0' and <= '9'
        || c is '-' or '.' or '_' or '~'
        || c is ':' or '/' or '?' or '#' or '[' or ']' or '@'
        || c is '!' or '$' or '&' or '\'' or '(' or ')' or '*' or '+' or ',' or ';' or '=';
}
