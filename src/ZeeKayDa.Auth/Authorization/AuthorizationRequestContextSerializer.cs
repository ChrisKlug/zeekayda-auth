using System.Text;

namespace ZeeKayDa.Auth.Authorization;

/// <summary>
/// Encodes an <see cref="AuthorizationRequestContext"/> to the compact binary form carried in the
/// interaction cookie, and decodes it back.
/// </summary>
/// <remarks>
/// <para>
/// The format is positional — a version byte followed by length-prefixed fields in a fixed order —
/// rather than JSON. Field names would be roughly 200 bytes of pure overhead on a payload of about
/// 400, and the cookie is re-sent on every request to its path. Nothing is lost by dropping
/// self-description from a payload only this framework reads.
/// </para>
/// <para>
/// The payload is never compressed before encryption. Mixing an attacker-controlled <c>state</c>
/// into a compressed, encrypted payload is a needless nod to CRIME-style length oracles.
/// </para>
/// <para>
/// <see cref="TryDecode"/> answers <see langword="false"/> for anything it does not recognise and
/// never throws for malformed input: the bytes reaching it have been decrypted, but a payload
/// written by an older version of this framework is not thereby well-formed.
/// </para>
/// </remarks>
internal static class AuthorizationRequestContextSerializer
{
    /// <summary>
    /// The format version. A payload carrying any other value is refused rather than misread —
    /// positional formats have no way to detect a field that moved.
    /// </summary>
    private const byte Version = 1;

    public static byte[] Encode(AuthorizationRequestContext context)
    {
        ArgumentNullException.ThrowIfNull(context);

        using var buffer = new MemoryStream();
        using var writer = new BinaryWriter(buffer, Encoding.UTF8, leaveOpen: true);

        writer.Write(Version);

        writer.Write(context.Id);
        writer.Write(context.ClientId);
        writer.Write(context.RedirectUri);
        WriteStrings(writer, context.Scopes);
        WriteNullableString(writer, context.State);
        writer.Write(context.Nonce);
        writer.Write(context.CodeChallenge);
        writer.Write((byte)context.CodeChallengeMethod);

        writer.Write((byte)context.Prompts.Count);
        foreach (var prompt in context.Prompts)
            writer.Write((byte)prompt);

        WriteNullableTimeSpan(writer, context.MaxAge);
        writer.Write(context.IssuedAt.ToUnixTimeSeconds());
        writer.Write(context.ExpiresAt.ToUnixTimeSeconds());

        WriteNullableString(writer, context.SsoSessionId);
        WriteNullableString(writer, context.Subject);
        WriteNullableTimestamp(writer, context.AuthTime);
        WriteNullableString(writer, context.ProviderScheme);
        WriteNullableString(writer, context.Acr);
        WriteNullableStrings(writer, context.Amr);
        WriteNullableStrings(writer, context.GrantedScopes);
        WriteNullableTimestamp(writer, context.ConsentedAt);

        writer.Flush();
        return buffer.ToArray();
    }

    public static bool TryDecode(ReadOnlySpan<byte> payload, out AuthorizationRequestContext? context)
    {
        context = null;

        try
        {
            using var buffer = new MemoryStream(payload.ToArray(), writable: false);
            using var reader = new BinaryReader(buffer, Encoding.UTF8, leaveOpen: true);

            if (reader.ReadByte() != Version)
                return false;

            var id = reader.ReadString();
            var clientId = reader.ReadString();
            var redirectUri = reader.ReadString();
            var scopes = ReadStrings(reader);
            var state = ReadNullableString(reader);
            var nonce = reader.ReadString();
            var codeChallenge = reader.ReadString();

            var challengeMethod = (CodeChallengeMethod)reader.ReadByte();
            if (!Enum.IsDefined(challengeMethod))
                return false;

            var promptCount = reader.ReadByte();
            var prompts = new HashSet<PromptValue>();
            for (var i = 0; i < promptCount; i++)
            {
                var prompt = (PromptValue)reader.ReadByte();
                if (!Enum.IsDefined(prompt))
                    return false;

                prompts.Add(prompt);
            }

            var maxAge = ReadNullableTimeSpan(reader);
            var issuedAt = DateTimeOffset.FromUnixTimeSeconds(reader.ReadInt64());
            var expiresAt = DateTimeOffset.FromUnixTimeSeconds(reader.ReadInt64());

            var decoded = new AuthorizationRequestContext
            {
                Id = id,
                ClientId = clientId,
                RedirectUri = redirectUri,
                Scopes = scopes,
                State = state,
                Nonce = nonce,
                CodeChallenge = codeChallenge,
                CodeChallengeMethod = challengeMethod,
                Prompts = prompts,
                MaxAge = maxAge,
                IssuedAt = issuedAt,
                ExpiresAt = expiresAt,
                SsoSessionId = ReadNullableString(reader),
                Subject = ReadNullableString(reader),
                AuthTime = ReadNullableTimestamp(reader),
                ProviderScheme = ReadNullableString(reader),
                Acr = ReadNullableString(reader),
                Amr = ReadNullableStrings(reader),
                GrantedScopes = ReadNullableStrings(reader),
                ConsentedAt = ReadNullableTimestamp(reader),
            };

            // Trailing bytes mean the payload is not what this version writes, whatever else
            // decoded cleanly along the way.
            if (buffer.Position != buffer.Length)
                return false;

            context = decoded;
            return true;
        }
        catch (Exception ex) when (ex is EndOfStreamException or FormatException or IOException or ArgumentException)
        {
            return false;
        }
    }

    private static void WriteStrings(BinaryWriter writer, IReadOnlyList<string> values)
    {
        writer.Write7BitEncodedInt(values.Count);
        foreach (var value in values)
            writer.Write(value);
    }

    private static List<string> ReadStrings(BinaryReader reader)
    {
        var count = reader.Read7BitEncodedInt();
        ArgumentOutOfRangeException.ThrowIfNegative(count);

        var values = new List<string>(Math.Min(count, 16));
        for (var i = 0; i < count; i++)
            values.Add(reader.ReadString());

        return values;
    }

    private static void WriteNullableStrings(BinaryWriter writer, IReadOnlyList<string>? values)
    {
        writer.Write(values is not null);
        if (values is not null)
            WriteStrings(writer, values);
    }

    private static List<string>? ReadNullableStrings(BinaryReader reader) =>
        reader.ReadBoolean() ? ReadStrings(reader) : null;

    private static void WriteNullableString(BinaryWriter writer, string? value)
    {
        writer.Write(value is not null);
        if (value is not null)
            writer.Write(value);
    }

    private static string? ReadNullableString(BinaryReader reader) =>
        reader.ReadBoolean() ? reader.ReadString() : null;

    private static void WriteNullableTimeSpan(BinaryWriter writer, TimeSpan? value)
    {
        writer.Write(value.HasValue);
        if (value.HasValue)
            writer.Write((long)value.Value.TotalSeconds);
    }

    private static TimeSpan? ReadNullableTimeSpan(BinaryReader reader) =>
        reader.ReadBoolean() ? TimeSpan.FromSeconds(reader.ReadInt64()) : null;

    private static void WriteNullableTimestamp(BinaryWriter writer, DateTimeOffset? value)
    {
        writer.Write(value.HasValue);
        if (value.HasValue)
            writer.Write(value.Value.ToUnixTimeSeconds());
    }

    private static DateTimeOffset? ReadNullableTimestamp(BinaryReader reader) =>
        reader.ReadBoolean() ? DateTimeOffset.FromUnixTimeSeconds(reader.ReadInt64()) : null;
}
