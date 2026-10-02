using System.Diagnostics.CodeAnalysis;
using System.Globalization;
using System.Text;

namespace ZeeKayDa.Auth.Clients;

/// <summary>
/// Formats and parses hashes in the PHC string format:
/// <c>$&lt;id&gt;[$v=&lt;version&gt;][$&lt;name&gt;=&lt;value&gt;(,&lt;name&gt;=&lt;value&gt;)*]$&lt;salt&gt;$&lt;hash&gt;</c>.
/// </summary>
/// <remarks>
/// <para>
/// See <see href="https://github.com/P-H-C/phc-string-format/blob/master/phc-sf-spec.md">the PHC
/// string format</see>. Salt and hash are standard base64 without <c>=</c> padding. This type
/// requires both, where the format allows either to be absent.
/// </para>
/// <para>
/// Optional for an <see cref="IClientSecretHasher"/> author. A library that already produces PHC
/// strings needs none of it; one that works in bytes builds its <see cref="ClientSecret.Value"/>
/// with <see cref="ToString"/>. The framework itself reads only the algorithm id.
/// </para>
/// </remarks>
public sealed class PhcString
{
    private const int MaxNameLength = 32;
    private const string VersionPrefix = "v=";

    private readonly byte[] _salt;
    private readonly byte[] _hash;

    /// <summary>
    /// Creates a PHC string from its parts.
    /// </summary>
    /// <param name="id">The algorithm id: 1–32 characters from <c>[a-z0-9-]</c>.</param>
    /// <param name="salt">The salt. Must not be empty.</param>
    /// <param name="hash">The hash output. Must not be empty.</param>
    /// <param name="parameters">
    /// The algorithm's parameters, in the order the algorithm defines. Names are 1–32 characters
    /// from <c>[a-z0-9-]</c>, unique, and never <c>v</c>; values are non-empty, from
    /// <c>[a-zA-Z0-9/+.-]</c>.
    /// </param>
    /// <param name="version">The algorithm version, written as <c>$v=&lt;version&gt;</c>.</param>
    /// <exception cref="ArgumentNullException"><paramref name="id"/> is <see langword="null"/>.</exception>
    /// <exception cref="ArgumentOutOfRangeException"><paramref name="version"/> is negative.</exception>
    /// <exception cref="ArgumentException">A part is empty or holds a character the format forbids.</exception>
    public PhcString(
        string id,
        ReadOnlySpan<byte> salt,
        ReadOnlySpan<byte> hash,
        IEnumerable<KeyValuePair<string, string>>? parameters = null,
        int? version = null)
    {
        ArgumentNullException.ThrowIfNull(id);
        if (!IsName(id))
            throw new ArgumentException("The id must be 1–32 characters from [a-z0-9-].", nameof(id));
        if (salt.IsEmpty)
            throw new ArgumentException("The salt must not be empty.", nameof(salt));
        if (hash.IsEmpty)
            throw new ArgumentException("The hash must not be empty.", nameof(hash));
        if (version < 0)
            throw new ArgumentOutOfRangeException(nameof(version), "The version must not be negative.");

        var parameterList = (parameters ?? []).ToList();
        if (DescribeParameterProblem(parameterList) is { } problem)
            throw new ArgumentException(problem, nameof(parameters));

        Id = id;
        Version = version;
        Parameters = parameterList.AsReadOnly();
        _salt = salt.ToArray();
        _hash = hash.ToArray();
    }

    /// <summary>The algorithm id, for example <c>pbkdf2-sha256</c>.</summary>
    public string Id { get; }

    /// <summary>The algorithm version (Argon2's <c>v=19</c>), or <see langword="null"/> when absent.</summary>
    public int? Version { get; }

    /// <summary>The algorithm's parameters, in the order they appear. Values are left as strings.</summary>
    public IReadOnlyList<KeyValuePair<string, string>> Parameters { get; }

    /// <summary>The decoded salt, a copy on every read.</summary>
    /// <remarks>A copy because <c>MemoryMarshal.TryGetArray</c> reaches the array behind it.</remarks>
    public ReadOnlyMemory<byte> Salt => _salt.ToArray();

    /// <summary>The decoded hash output, a copy on every read.</summary>
    /// <remarks>A copy because <c>MemoryMarshal.TryGetArray</c> reaches the array behind it.</remarks>
    public ReadOnlyMemory<byte> Hash => _hash.ToArray();

    /// <summary>Returns the <c>$...$</c> form.</summary>
    public override string ToString()
    {
        var builder = new StringBuilder().Append('$').Append(Id);

        if (Version is { } version)
            builder.Append('$').Append(VersionPrefix).Append(version.ToString(CultureInfo.InvariantCulture));

        if (Parameters.Count > 0)
            builder.Append('$').AppendJoin(',', Parameters.Select(p => $"{p.Key}={p.Value}"));

        return builder
            .Append('$').Append(ToUnpaddedBase64(_salt))
            .Append('$').Append(ToUnpaddedBase64(_hash))
            .ToString();
    }

    /// <summary>
    /// Parses <paramref name="value"/>. Returns <see langword="false"/> for anything that is not a
    /// well-formed PHC string with both a salt and a hash, and never throws.
    /// </summary>
    /// <remarks>
    /// Strict: base64 must be canonical and the version has no leading zero, so a parsed string
    /// formats back to exactly <paramref name="value"/>.
    /// </remarks>
    public static bool TryParse(string? value, [NotNullWhen(true)] out PhcString? result)
    {
        result = FieldsOf(value) is { } fields && FieldRules.All(rule => rule(fields))
            ? new PhcString(
                fields.Id,
                FromUnpaddedBase64(fields.Salt),
                FromUnpaddedBase64(fields.Hash),
                fields.Parameters is null ? null : ParametersOf(fields.Parameters),
                fields.Version is null ? null : int.Parse(fields.Version, CultureInfo.InvariantCulture))
            : null;

        return result is not null;
    }

    /// <summary>The text of each field, split out of a PHC string before any of it is checked.</summary>
    private sealed record Fields(string Id, string? Version, string? Parameters, string Salt, string Hash);

    private static readonly Func<Fields, bool>[] FieldRules =
    [
        fields => IsName(fields.Id),
        fields => fields.Version is null || IsVersion(fields.Version),
        fields => fields.Parameters is null
            || ParametersOf(fields.Parameters) is { } parameters && DescribeParameterProblem(parameters) is null,
        fields => IsUnpaddedBase64(fields.Salt),
        fields => IsUnpaddedBase64(fields.Hash),
    ];

    private static readonly Func<KeyValuePair<string, string>, string?>[] ParameterRules =
    [
        parameter => IsName(parameter.Key) ? null : "A parameter name must be 1–32 characters from [a-z0-9-].",
        parameter => parameter.Key != "v"
            ? null
            : "A parameter must not be named 'v', which the format reserves for the version.",
        parameter => parameter.Value is { Length: > 0 } text && text.All(IsValueChar)
            ? null
            : $"The value of parameter '{parameter.Key}' must be non-empty, from [a-zA-Z0-9/+.-].",
    ];

    private static readonly Func<string, bool>[] VersionRules =
    [
        text => text.Length > 0,
        text => text.All(char.IsAsciiDigit),
        // A leading zero would not survive formatting back.
        text => text == "0" || text[0] != '0',
        text => int.TryParse(text, NumberStyles.None, CultureInfo.InvariantCulture, out _),
    ];

    private static readonly Func<string, bool>[] Base64Rules =
    [
        field => field.Length > 0,
        field => field.Length % 4 != 1,
        field => field.All(c => char.IsAsciiLetterOrDigit(c) || c is '+' or '/'),
        // Base64 has more than one spelling for the last few bits; only the canonical one round-trips.
        field => ToUnpaddedBase64(FromUnpaddedBase64(field)) == field,
    ];

    // $<id>[$v=<version>][$<parameters>]$<salt>$<hash>; the first part is the empty text before the
    // leading '$'. A first optional field starting "v=" is the version, whatever follows it.
    private static Fields? FieldsOf(string? value)
    {
        if (value?.Split('$') is not ["", var id, .. var optional, var salt, var hash] || optional.Length > 2)
            return null;

        var version = optional is [var first, ..] && first.StartsWith(VersionPrefix, StringComparison.Ordinal)
            ? first[VersionPrefix.Length..]
            : null;
        var rest = version is null ? optional : optional[1..];

        return rest.Length <= 1 ? new Fields(id, version, rest.FirstOrDefault(), salt, hash) : null;
    }

    private static bool IsVersion(string text) => VersionRules.All(rule => rule(text));

    // Null when a pair has no '='; names and values are checked by the parameter rules.
    private static IReadOnlyList<KeyValuePair<string, string>>? ParametersOf(string field)
    {
        var pairs = field.Split(',').Select(pair => pair.Split('=', 2)).ToList();
        return pairs.All(pair => pair.Length == 2)
            ? [.. pairs.Select(pair => new KeyValuePair<string, string>(pair[0], pair[1]))]
            : null;
    }

    private static string? DescribeParameterProblem(IReadOnlyList<KeyValuePair<string, string>> parameters) =>
        parameters
            .SelectMany(parameter => ParameterRules.Select(rule => rule(parameter)))
            .FirstOrDefault(problem => problem is not null)
        ?? RepeatedNameProblem(parameters);

    private static string? RepeatedNameProblem(IReadOnlyList<KeyValuePair<string, string>> parameters) =>
        parameters.GroupBy(parameter => parameter.Key, StringComparer.Ordinal).FirstOrDefault(group => group.Count() > 1)
            is { } repeated
            ? $"The parameter '{repeated.Key}' appears more than once."
            : null;

    internal static bool IsName(string? value) =>
        value is { Length: > 0 and <= MaxNameLength }
        && value.All(c => char.IsAsciiLetterLower(c) || char.IsAsciiDigit(c) || c == '-');

    private static bool IsValueChar(char c) =>
        char.IsAsciiLetterOrDigit(c) || c is '/' or '+' or '.' or '-';

    private static string ToUnpaddedBase64(ReadOnlySpan<byte> bytes) =>
        Convert.ToBase64String(bytes).TrimEnd('=');

    private static bool IsUnpaddedBase64(string field) => Base64Rules.All(rule => rule(field));

    // Only for a field the Base64 rules accepted, or for checking that one round-trips.
    private static byte[] FromUnpaddedBase64(string field) =>
        Convert.FromBase64String(field.PadRight(field.Length + ((4 - (field.Length % 4)) % 4), '='));
}
