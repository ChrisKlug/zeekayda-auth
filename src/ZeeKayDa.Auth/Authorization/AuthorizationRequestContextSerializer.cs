using System.Text;

namespace ZeeKayDa.Auth.Authorization;

/// <summary>
/// Encodes an <see cref="AuthorizationRequestContext"/> to the compact binary form held in the
/// interaction store, and decodes it back.
/// </summary>
/// <remarks>
/// Positional rather than JSON, since field names would double the payload. Never compressed before
/// encryption: an attacker-controlled <c>state</c> would open a CRIME-style length oracle.
/// </remarks>
internal static class AuthorizationRequestContextSerializer
{
    /// <summary>The format version; any other is refused, as a positional format cannot detect a moved field.</summary>
    private const byte Version = 6;

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
        WriteNullableString(writer, context.Nonce);
        WritePkce(writer, context.Pkce);

        writer.Write7BitEncodedInt(context.Prompts.Count);
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
        WriteProviderAttempt(writer, context.ProviderAttempt);
        WriteNullableString(writer, context.LoginHint);
        WriteNullableString(writer, context.RequiredSubject);

        writer.Flush();
        return buffer.ToArray();
    }

    /// <summary>Decodes a payload; <see langword="false"/>, never a throw, for one this version did not write.</summary>
    public static bool TryDecode(ReadOnlySpan<byte> payload, out AuthorizationRequestContext? context)
    {
        context = null;

        try
        {
            using var buffer = new MemoryStream(payload.ToArray(), writable: false);
            using var reader = new BinaryReader(buffer, Encoding.UTF8, leaveOpen: true);

            if (reader.ReadByte() != Version)
                return false;

            var decoded = ReadContext(reader);
            if (decoded is null)
                return false;

            bool hasTrailingBytes = buffer.Position != buffer.Length;
            if (hasTrailingBytes || !IsComplete(decoded))
                return false;

            context = decoded;
            return true;
        }
        catch (Exception ex) when (ex is EndOfStreamException or FormatException or IOException or ArgumentException)
        {
            return false;
        }
    }

    /// <summary>
    /// Reads the fields in order, or <see langword="null"/> for an unrecognised value; structural
    /// failures throw for <see cref="TryDecode"/> to absorb.
    /// </summary>
    private static AuthorizationRequestContext? ReadContext(BinaryReader reader)
    {
        var id = reader.ReadString();
        var clientId = reader.ReadString();
        var redirectUri = reader.ReadString();
        var scopes = ReadStrings(reader);
        var state = ReadNullableString(reader);
        var nonce = ReadNullableString(reader);
        if (!TryReadPkce(reader, out var pkce))
            return null;

        var prompts = ReadPrompts(reader);
        if (prompts is null)
            return null;

        var context = new AuthorizationRequestContext
        {
            Id = id,
            ClientId = clientId,
            RedirectUri = redirectUri,
            Scopes = scopes,
            State = state,
            Nonce = nonce,
            Pkce = pkce,
            Prompts = prompts,
            MaxAge = ReadNullableTimeSpan(reader),
            IssuedAt = DateTimeOffset.FromUnixTimeSeconds(reader.ReadInt64()),
            ExpiresAt = DateTimeOffset.FromUnixTimeSeconds(reader.ReadInt64()),
            SsoSessionId = ReadNullableString(reader),
            Subject = ReadNullableString(reader),
            AuthTime = ReadNullableTimestamp(reader),
            ProviderScheme = ReadNullableString(reader),
            Acr = ReadNullableString(reader),
            Amr = ReadNullableStrings(reader),
            GrantedScopes = ReadNullableStrings(reader),
            ConsentedAt = ReadNullableTimestamp(reader),
        };

        if (!TryReadProviderAttempt(reader, out var attempt))
            return null;

        return context with
        {
            ProviderAttempt = attempt,
            LoginHint = ReadNullableString(reader),
            RequiredSubject = ReadNullableString(reader),
        };
    }

    /// <summary>The prompt set, or <see langword="null"/> for a negative count or a value outside the enum.</summary>
    private static HashSet<PromptValue>? ReadPrompts(BinaryReader reader)
    {
        var count = reader.Read7BitEncodedInt();
        if (count < 0)
            return null;

        var prompts = new HashSet<PromptValue>();
        for (var i = 0; i < count; i++)
        {
            var prompt = (PromptValue)reader.ReadByte();
            if (!Enum.IsDefined(prompt))
                return null;

            prompts.Add(prompt);
        }

        return prompts;
    }

    /// <summary>
    /// Whether every value the validator guarantees is present: an empty <c>RedirectUri</c> would
    /// redirect back to the server itself. An empty <c>nonce</c> is one the validator never produces.
    /// </summary>
    private static bool IsComplete(AuthorizationRequestContext context) =>
        !string.IsNullOrEmpty(context.Id) &&
        !string.IsNullOrEmpty(context.ClientId) &&
        !string.IsNullOrEmpty(context.RedirectUri) &&
        context.Nonce is not { Length: 0 } &&
        context.Scopes.Count > 0;

    private static void WritePkce(BinaryWriter writer, PkceChallenge? pkce)
    {
        writer.Write(pkce is not null);
        if (pkce is null)
            return;

        writer.Write(pkce.Challenge);
        writer.Write((byte)pkce.Method);
    }

    /// <summary>False for a method this version does not define or an empty challenge: a payload this version did not write.</summary>
    private static bool TryReadPkce(BinaryReader reader, out PkceChallenge? pkce)
    {
        pkce = null;
        if (!reader.ReadBoolean())
            return true;

        var challenge = reader.ReadString();
        var method = (CodeChallengeMethod)reader.ReadByte();
        if (challenge.Length == 0 || !Enum.IsDefined(method))
            return false;

        pkce = new PkceChallenge(challenge, method);
        return true;
    }

    private static void WriteProviderAttempt(BinaryWriter writer, ProviderAttempt? attempt)
    {
        writer.Write(attempt is not null);
        if (attempt is null)
            return;

        writer.Write(attempt.Provider);
        writer.Write(attempt.Declined);
    }

    /// <summary>False for an empty provider name: a payload this version did not write.</summary>
    private static bool TryReadProviderAttempt(BinaryReader reader, out ProviderAttempt? attempt)
    {
        attempt = null;
        if (!reader.ReadBoolean())
            return true;

        var provider = reader.ReadString();
        var declined = reader.ReadBoolean();
        if (provider.Length == 0)
            return false;

        attempt = new ProviderAttempt(provider, declined);
        return true;
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
