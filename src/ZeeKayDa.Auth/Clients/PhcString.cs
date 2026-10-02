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
    /// Strict: base64 must be canonical, so a parsed string formats back to exactly
    /// <paramref name="value"/>.
    /// </remarks>
    public static bool TryParse(string? value, [NotNullWhen(true)] out PhcString? result)
    {
        result = null;
        if (value is null || !value.StartsWith('$'))
            return false;

        // [0] is the empty string before the leading '$'; then id, up to two optional fields, salt, hash.
        var fields = value.Split('$');
        if (fields.Length is < 4 or > 6)
            return false;

        var id = fields[1];
        var optional = fields[2..^2];
        int? version = null;
        IReadOnlyList<KeyValuePair<string, string>> parameters = [];

        if (optional.Length > 0 && TryParseVersion(optional[0], out var parsedVersion))
        {
            version = parsedVersion;
            optional = optional[1..];
        }

        if (optional.Length > 1)
            return false;

        if (optional.Length == 1 && !TryParseParameters(optional[0], out parameters))
            return false;

        if (!IsName(id)
            || !TryFromUnpaddedBase64(fields[^2], out var salt)
            || !TryFromUnpaddedBase64(fields[^1], out var hash)
            || DescribeParameterProblem(parameters) is not null)
        {
            return false;
        }

        result = new PhcString(id, salt, hash, parameters, version);
        return true;
    }

    private static bool TryParseVersion(string field, out int version)
    {
        version = 0;
        return field.StartsWith(VersionPrefix, StringComparison.Ordinal)
            && field.Length > VersionPrefix.Length
            && field.AsSpan(VersionPrefix.Length).IndexOfAnyExceptInRange('0', '9') < 0
            && int.TryParse(field.AsSpan(VersionPrefix.Length), NumberStyles.None, CultureInfo.InvariantCulture, out version);
    }

    private static bool TryParseParameters(string field, out IReadOnlyList<KeyValuePair<string, string>> parameters)
    {
        var pairs = new List<KeyValuePair<string, string>>();
        parameters = pairs;

        foreach (var pair in field.Split(','))
        {
            var separator = pair.IndexOf('=', StringComparison.Ordinal);
            if (separator < 0)
                return false;

            pairs.Add(new(pair[..separator], pair[(separator + 1)..]));
        }

        return true;
    }

    private static string? DescribeParameterProblem(IReadOnlyList<KeyValuePair<string, string>> parameters)
    {
        var names = new HashSet<string>(StringComparer.Ordinal);
        foreach (var (name, value) in parameters)
        {
            if (name is null || !IsName(name))
                return "A parameter name must be 1–32 characters from [a-z0-9-].";
            if (name == "v")
                return "A parameter must not be named 'v', which the format reserves for the version.";
            if (!names.Add(name))
                return $"The parameter '{name}' appears more than once.";
            if (string.IsNullOrEmpty(value) || !value.All(IsValueChar))
                return $"The value of parameter '{name}' must be non-empty, from [a-zA-Z0-9/+.-].";
        }

        return null;
    }

    internal static bool IsName(string value) =>
        value.Length is > 0 and <= MaxNameLength
        && value.All(c => char.IsAsciiLetterLower(c) || char.IsAsciiDigit(c) || c == '-');

    private static bool IsValueChar(char c) =>
        char.IsAsciiLetterOrDigit(c) || c is '/' or '+' or '.' or '-';

    private static string ToUnpaddedBase64(ReadOnlySpan<byte> bytes) =>
        Convert.ToBase64String(bytes).TrimEnd('=');

    private static bool TryFromUnpaddedBase64(string field, out byte[] bytes)
    {
        bytes = [];
        if (field.Length == 0 || field.Length % 4 == 1
            || !field.All(c => char.IsAsciiLetterOrDigit(c) || c is '+' or '/'))
        {
            return false;
        }

        var padded = field.PadRight(field.Length + ((4 - (field.Length % 4)) % 4), '=');
        bytes = Convert.FromBase64String(padded);

        // Base64 has more than one spelling for the last few bits; only the canonical one round-trips.
        return ToUnpaddedBase64(bytes) == field;
    }
}
