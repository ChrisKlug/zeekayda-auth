using System.Buffers;
using System.Globalization;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace ZeeKayDa.Auth.Claims;

/// <summary>
/// A claim's value as it will appear on the wire: a JSON string, number, boolean, object or
/// array, built once and held detached from whatever the provider keeps.
/// </summary>
/// <remarks>
/// <para>
/// The implicit conversions cover every type a standard OpenID Connect claim can be, so a
/// provider writes <c>new ClaimRecord("email_verified", true)</c> and the token carries a JSON
/// boolean. None of them throws: a value that has no JSON form, a <see langword="null"/> string,
/// <see cref="double.NaN"/> or an infinity, becomes a value that
/// <see cref="ClaimRecord(string, ClaimValue)"/> refuses by claim name.
/// </para>
/// <para>
/// A custom shape reaches a token only through <see cref="From{T}(T, JsonSerializerOptions?)"/>,
/// which serialises it on the spot with snake_case names by default, OpenID Connect's own
/// convention. There is no conversion from <see cref="object"/>, so a domain entity cannot be
/// handed over by accident. A host that emits its own type often declares an implicit conversion
/// on that type which calls <c>From</c>.
/// </para>
/// <para>
/// The value serialises through <see cref="JsonSerializer"/> as the JSON it holds, so a custom
/// <c>ITokenIssuer</c> that serialises a <c>TokenPayload</c> writes it correctly without knowing
/// this type; one that stores claims some other way reads <see cref="Kind"/> and writes the JSON
/// with <see cref="WriteTo"/>. The default value holds nothing and cannot be written.
/// </para>
/// </remarks>
[JsonConverter(typeof(ClaimValueJsonConverter))]
public readonly record struct ClaimValue
{
    private const string EmptyStringJson = "\"\"";

    private static readonly JsonSerializerOptions SnakeCase = new()
    {
        PropertyNamingPolicy = JsonNamingPolicy.SnakeCaseLower,
    };

    private readonly string? _json;
    private readonly JsonValueKind _kind;

    private ClaimValue(string json, JsonValueKind kind)
    {
        _json = json;
        _kind = kind;
    }

    /// <summary>A JSON string. A <see langword="null"/> converts to a value no record accepts.</summary>
    public static implicit operator ClaimValue(string value) =>
        value is null ? default : new(JsonSerializer.Serialize(value), JsonValueKind.String);

    /// <summary>A JSON boolean.</summary>
    public static implicit operator ClaimValue(bool value) =>
        value ? new("true", JsonValueKind.True) : new("false", JsonValueKind.False);

    /// <summary>A JSON number.</summary>
    public static implicit operator ClaimValue(int value) =>
        new(value.ToString(CultureInfo.InvariantCulture), JsonValueKind.Number);

    /// <summary>A JSON number.</summary>
    public static implicit operator ClaimValue(long value) =>
        new(value.ToString(CultureInfo.InvariantCulture), JsonValueKind.Number);

    /// <summary>
    /// A JSON number. <see cref="double.NaN"/> and the infinities have no JSON form and convert
    /// to a value no record accepts.
    /// </summary>
    public static implicit operator ClaimValue(double value) =>
        double.IsFinite(value) ? new(JsonSerializer.Serialize(value), JsonValueKind.Number) : default;

    /// <summary>
    /// The <c>address</c> object of OpenID Connect Core §5.1.1, with its standard member names
    /// and every <see langword="null"/> member omitted. A <see langword="null"/> address converts
    /// to a value no record accepts.
    /// </summary>
    public static implicit operator ClaimValue(AddressClaim value)
    {
        if (value is null)
            return default;

        var buffer = new ArrayBufferWriter<byte>();
        using (var writer = new Utf8JsonWriter(buffer))
        {
            writer.WriteStartObject();
            WriteIfPresent(writer, "formatted", value.Formatted);
            WriteIfPresent(writer, "street_address", value.StreetAddress);
            WriteIfPresent(writer, "locality", value.Locality);
            WriteIfPresent(writer, "region", value.Region);
            WriteIfPresent(writer, "postal_code", value.PostalCode);
            WriteIfPresent(writer, "country", value.Country);
            writer.WriteEndObject();
        }

        return new(Encoding.UTF8.GetString(buffer.WrittenSpan), JsonValueKind.Object);
    }

    /// <summary>
    /// Serialises <paramref name="value"/> to the JSON a claim will carry: the deliberate route
    /// for a custom object or array.
    /// </summary>
    /// <typeparam name="T">The type to serialise.</typeparam>
    /// <param name="value">The value. Serialised now; later changes to it do not reach a token.</param>
    /// <param name="options">
    /// Serializer options, or <see langword="null"/> for the default: snake_case property names,
    /// the naming convention of every standard claim.
    /// </param>
    /// <returns>The serialised value. One that serialises to JSON <c>null</c> is a value no record accepts.</returns>
    /// <exception cref="NotSupportedException">
    /// Thrown when <typeparamref name="T"/> has no JSON representation under <paramref name="options"/>.
    /// </exception>
    /// <exception cref="JsonException">Thrown when serialisation fails, for a reference cycle for instance.</exception>
    public static ClaimValue From<T>(T value, JsonSerializerOptions? options = null)
        where T : notnull
    {
        var json = JsonSerializer.Serialize(value, options ?? SnakeCase);

        using var document = JsonDocument.Parse(json);
        return new(json, document.RootElement.ValueKind);
    }

    /// <summary>
    /// Writes the JSON this value holds to <paramref name="writer"/>, as one value: the route for
    /// a custom token issuer that assembles its own JSON or stores claims outside a JWT.
    /// </summary>
    /// <param name="writer">The writer, positioned where a value is expected.</param>
    /// <exception cref="ArgumentNullException">Thrown when <paramref name="writer"/> is <see langword="null"/>.</exception>
    /// <exception cref="InvalidOperationException">This is the default <see cref="ClaimValue"/>, which holds no JSON.</exception>
    public void WriteTo(Utf8JsonWriter writer)
    {
        ArgumentNullException.ThrowIfNull(writer);

        if (_json is null)
            throw new InvalidOperationException("This is the default ClaimValue, which holds no JSON and cannot be written.");

        writer.WriteRawValue(_json);
    }

    /// <summary>Names the JSON kind and nothing else, so a printed value carries no personal data.</summary>
    public override string ToString() => $"ClaimValue({_kind})";

    /// <summary>
    /// The JSON kind of the value: string, number, true, false, object or array, or
    /// <see cref="JsonValueKind.Undefined"/> for the default value.
    /// </summary>
    public JsonValueKind Kind => _kind;

    /// <summary>The JSON text, or <see langword="null"/> for the default value.</summary>
    internal string? Json => _json;

    /// <summary>
    /// Whether a token could carry this value: not the default, not JSON <c>null</c>, and not the
    /// empty string, which OpenID Connect Core §5.3.2 says an absent claim must never be written as.
    /// </summary>
    internal bool IsRepresentable =>
        _kind is not (JsonValueKind.Undefined or JsonValueKind.Null) && _json != EmptyStringJson;

    /// <summary>A JSON array of <paramref name="values"/>, in order, each of which must be representable.</summary>
    internal static ClaimValue ArrayOf(IReadOnlyList<ClaimValue> values) =>
        new($"[{string.Join(',', values.Select(value => value._json))}]", JsonValueKind.Array);

    private static void WriteIfPresent(Utf8JsonWriter writer, string name, string? value)
    {
        if (value is not null)
            writer.WriteString(name, value);
    }

    private sealed class ClaimValueJsonConverter : JsonConverter<ClaimValue>
    {
        public override ClaimValue Read(ref Utf8JsonReader reader, Type typeToConvert, JsonSerializerOptions options)
        {
            using var document = JsonDocument.ParseValue(ref reader);
            return new(document.RootElement.GetRawText(), document.RootElement.ValueKind);
        }

        public override void Write(Utf8JsonWriter writer, ClaimValue value, JsonSerializerOptions options)
        {
            if (value._json is null)
                throw new JsonException("A default ClaimValue holds no JSON and cannot be written.");

            value.WriteTo(writer);
        }
    }
}
