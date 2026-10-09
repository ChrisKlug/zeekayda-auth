using System.Buffers;
using System.Buffers.Text;
using System.Diagnostics.CodeAnalysis;
using System.Text;
using System.Text.Json;

namespace ZeeKayDa.Auth.Tokens;

/// <summary>
/// The compact JWS (RFC 7515 §7.1) this server writes and reads back:
/// <c>base64url(header).base64url(payload).base64url(signature)</c>, with a header of exactly
/// <c>alg</c>, <c>typ</c> and <c>kid</c>. The payload is the caller's on both sides.
/// </summary>
internal readonly struct CompactJws
{
    /// <summary>The longest token read at all, in characters. Far above anything this server issues.</summary>
    internal const int MaxLength = 8192;

    private const string AlgorithmMember = "alg";
    private const string TypeMember = "typ";
    private const string KeyIdMember = "kid";

    /// <summary>The header's member names in ordinal order, to compare a read header against.</summary>
    private static readonly string[] HeaderMembers = [AlgorithmMember, KeyIdMember, TypeMember];

    private CompactJws(
        JoseHeader header, ReadOnlyMemory<byte> signingInput, ReadOnlyMemory<byte> payload, ReadOnlyMemory<byte> signature)
    {
        Alg = header.Alg;
        Typ = header.Typ;
        Kid = header.Kid;
        SigningInput = signingInput;
        Payload = payload;
        Signature = signature;
    }

    /// <summary>
    /// The bytes to sign for <paramref name="payload"/>: a header naming <paramref name="key"/>'s
    /// <c>kid</c> and algorithm and <paramref name="typ"/>, then the payload, each base64url-encoded.
    /// </summary>
    public static ReadOnlyMemory<byte> BuildSigningInput(SigningKey key, string typ, ReadOnlySpan<byte> payload) =>
        Encoding.ASCII.GetBytes($"{Base64Url.EncodeToString(Header(key, typ))}.{Base64Url.EncodeToString(payload)}");

    /// <summary>The token: <paramref name="signingInput"/>, a dot, and <paramref name="signature"/> base64url-encoded.</summary>
    public static string Serialize(ReadOnlySpan<byte> signingInput, ReadOnlySpan<byte> signature) =>
        $"{Encoding.ASCII.GetString(signingInput)}.{Base64Url.EncodeToString(signature)}";

    /// <summary>
    /// Reads <paramref name="token"/> when it has the shape <see cref="BuildSigningInput"/> and
    /// <see cref="Serialize"/> write. Nothing is verified: the signature is the ring's to check.
    /// </summary>
    public static bool TryParse([NotNullWhen(true)] string? token, out CompactJws jws)
    {
        jws = default;
        if (!IsReadable(token))
            return false;

        var segments = token.Split('.');
        if (segments.Length != 3)
            return false;

        try
        {
            if (ReadHeader(segments[0]) is not { } header)
                return false;

            jws = new CompactJws(
                header,
                Encoding.ASCII.GetBytes(token, 0, token.LastIndexOf('.')),
                Base64Url.DecodeFromChars(segments[1]),
                Base64Url.DecodeFromChars(segments[2]));
            return true;
        }
        catch (Exception ex) when (ex is FormatException or JsonException)
        {
            // Malformed Base64Url or malformed JSON: either is a token this server did not write.
            _ = ex;
            return false;
        }
    }

    /// <summary>Whether the header names <paramref name="key"/>'s own algorithm, as the issuer writes it.</summary>
    public bool NamesAlgorithmOf(SigningKey key) =>
        string.Equals(Alg, SigningAlgorithms.WireName(key.Algorithm), StringComparison.Ordinal);

    private static ReadOnlySpan<byte> Header(SigningKey key, string typ)
    {
        var buffer = new ArrayBufferWriter<byte>();
        using (var writer = new Utf8JsonWriter(buffer))
        {
            writer.WriteStartObject();
            writer.WriteString(AlgorithmMember, SigningAlgorithms.WireName(key.Algorithm));
            writer.WriteString(TypeMember, typ);
            writer.WriteString(KeyIdMember, key.Kid);
            writer.WriteEndObject();
        }

        return buffer.WrittenSpan;
    }

    private static JoseHeader? ReadHeader(string headerSegment)
    {
        using var document = JsonDocument.Parse(Base64Url.DecodeFromChars(headerSegment));
        var header = document.RootElement;
        if (!HasExactlyTheMembersWritten(header))
            return null;

        return new JoseHeader(
            header.GetProperty(AlgorithmMember).GetString()!,
            header.GetProperty(TypeMember).GetString()!,
            header.GetProperty(KeyIdMember).GetString()!);
    }

    /// <summary>
    /// An object of <c>alg</c>, <c>typ</c> and <c>kid</c>, each once and each a string. Anything
    /// else, a repeated member or a <c>crit</c> included, is a header the issuer did not write.
    /// </summary>
    private static bool HasExactlyTheMembersWritten(JsonElement header) =>
        header.ValueKind == JsonValueKind.Object
        && header.EnumerateObject().Select(member => member.Name).Order(StringComparer.Ordinal).SequenceEqual(HeaderMembers)
        && header.EnumerateObject().All(member => member.Value.ValueKind == JsonValueKind.String);

    /// <summary>
    /// Whether the token is worth reading at all. Only ASCII is accepted because every segment of
    /// a compact JWS is Base64Url, and the signing input is taken as the token's ASCII bytes.
    /// </summary>
    private static bool IsReadable([NotNullWhen(true)] string? token) =>
        !string.IsNullOrEmpty(token) && token.Length <= MaxLength && Ascii.IsValid(token);

    /// <summary>Gets the header's <c>alg</c>, as written.</summary>
    public string Alg { get; }

    /// <summary>Gets the header's <c>typ</c>, as written.</summary>
    public string Typ { get; }

    /// <summary>Gets the header's <c>kid</c>: the key the token says signed it.</summary>
    public string Kid { get; }

    /// <summary>Gets the bytes the signature is over: the token up to its last dot.</summary>
    public ReadOnlyMemory<byte> SigningInput { get; }

    /// <summary>Gets the decoded payload.</summary>
    public ReadOnlyMemory<byte> Payload { get; }

    /// <summary>Gets the decoded signature.</summary>
    public ReadOnlyMemory<byte> Signature { get; }

    private readonly record struct JoseHeader(string Alg, string Typ, string Kid);
}
