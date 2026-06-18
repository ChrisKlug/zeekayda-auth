using System.Collections;
using System.Text;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

namespace ZeeKayDa.Auth.Logging;

/// <summary>
/// Wraps an <see cref="ILogger{T}"/> and replaces known-sensitive structured-log values
/// with <c>[REDACTED]</c> before they reach the underlying logger.
/// </summary>
/// <remarks>
/// Sensitive keys (case-insensitive):
/// <c>client_secret</c>
/// <c>code_verifier</c>
/// <c>Authorization</c>
/// <c>access_token</c>
/// <c>refresh_token</c>
/// <c>id_token</c>
/// <c>client_assertion</c>
/// <c>assertion</c>
/// <c>device_code</c>
/// <c>subject_token</c>
/// <c>actor_token</c>
/// <c>password</c>
/// <c>code</c>
/// <c>DPoP</c>. Only states that implement
/// <see cref="IEnumerable{T}">IEnumerable&lt;KeyValuePair&lt;string, object?&gt;&gt;</see>
/// are inspected; all other state types pass through unchanged.
/// <para>
/// Exception messages are wrapped in a <see cref="RedactedExceptionWrapper"/> by default so that
/// credential material embedded in exception messages cannot reach log sinks. Call
/// <c>DisableExceptionSanitizing()</c> on the builder to opt out.
/// </para>
/// <para>
/// This is a defence-in-depth backstop for ADR 0007 §7. The Roslyn analyzer
/// (<c>ZEEKAYDA0001</c>) is the primary preventive control: it enforces at compile time that
/// every ZeeKayDa service injects <see cref="ISanitizingLogger{T}"/> rather than
/// <see cref="ILogger{T}"/> directly. The CI log-hygiene grep
/// (<c>.github/scripts/check_log_hygiene.sh</c>) and this runtime wrapper are defence-in-depth
/// layers that remain in place regardless.
/// </para>
/// </remarks>
internal sealed class SecretSanitizingLogger<T>(
    ILogger<T> inner,
    IOptions<SecretSanitizingLoggerOptions> options) : ISanitizingLogger<T>
{
    internal static readonly IReadOnlySet<string> SensitiveKeys =
        new HashSet<string>(StringComparer.OrdinalIgnoreCase)
        {
            "client_secret",
            "code_verifier",
            "Authorization",
            "access_token",
            "refresh_token",
            "id_token",
            "client_assertion",
            "assertion",
            "device_code",
            "subject_token",
            "actor_token",
            "password",
            "code",
            "DPoP"
        };

    public IDisposable? BeginScope<TState>(TState state) where TState : notnull
    {
        if (state is IEnumerable<KeyValuePair<string, object?>> pairs)
        {
            var list = pairs.ToList();
            if (list.Any(kv => SensitiveKeys.Contains(kv.Key)))
            {
                var redacted = list
                    .Select(kv => SensitiveKeys.Contains(kv.Key)
                        ? new KeyValuePair<string, object?>(kv.Key, "[REDACTED]")
                        : kv)
                    .ToList();
                return inner.BeginScope(redacted);
            }
        }

        return inner.BeginScope(state);
    }

    public bool IsEnabled(LogLevel logLevel)
        => inner.IsEnabled(logLevel);

    public void Log<TState>(
        LogLevel logLevel,
        EventId eventId,
        TState state,
        Exception? exception,
        Func<TState, Exception?, string> formatter)
    {
        var wrappedException = WrapException(exception);

        if (state is IEnumerable<KeyValuePair<string, object?>> pairs)
        {
            var list = pairs.ToList();
            if (list.Any(kv => kv.Key != "{OriginalFormat}" && SensitiveKeys.Contains(kv.Key)))
            {
                var redacted = list
                    .Select(kv => kv.Key != "{OriginalFormat}" && SensitiveKeys.Contains(kv.Key)
                        ? new KeyValuePair<string, object?>(kv.Key, "[REDACTED]")
                        : kv)
                    .ToList();
                inner.Log(logLevel, eventId, new RedactedLogValues(redacted), wrappedException, (s, ex) => s.ToString());
                return;
            }
        }
        else if (state is not string)
        {
            // Non-string, non-IEnumerable<KVP> state cannot be inspected for sensitive key-value
            // pairs. LoggerMessage.Define<T> and [LoggerMessage] source-generated states both
            // implement IReadOnlyList<KVP> and are handled by the branch above; this guard exists
            // for truly opaque custom state types passed directly to Log<TState>. Substitute a
            // safe placeholder rather than risk leaking structured parameter values to sinks.
            const string blocked = "[ZeeKayDa: unscrubbable log state blocked]";
            inner.Log(logLevel, eventId, blocked, wrappedException, static (s, _) => s);
            return;
        }

        inner.Log(logLevel, eventId, state, wrappedException, formatter);
    }

    private Exception? WrapException(Exception? exception)
    {
        if (exception is null || options.Value.ExceptionSanitizingDisabled)
            return exception;

        return new RedactedExceptionWrapper(exception);
    }

    private sealed class RedactedLogValues(List<KeyValuePair<string, object?>> pairs)
        : IEnumerable<KeyValuePair<string, object?>>
    {
        public IEnumerator<KeyValuePair<string, object?>> GetEnumerator() => pairs.GetEnumerator();
        IEnumerator IEnumerable.GetEnumerator() => pairs.GetEnumerator();

        public override string ToString()
        {
            var formatEntry = pairs.FirstOrDefault(kv => kv.Key == "{OriginalFormat}");
            if (formatEntry.Value is not string template)
                return string.Join(", ", pairs.Select(kv => $"{kv.Key}: {kv.Value}"));

            return FormatTemplate(
                template,
                pairs
                    .Where(kv => kv.Key != "{OriginalFormat}")
                    .ToDictionary(kv => kv.Key, kv => kv.Value, StringComparer.Ordinal));
        }

        // Converts a structured-logging named template (e.g. "Count={Count:N0}") to an indexed
        // string.Format template ("Count={0:N0}") and delegates to string.Format so that alignment
        // specifiers, format specifiers, escaped braces ({{/}}), and duplicate placeholders are all
        // handled correctly by the framework rather than re-implemented here.
        // FormattedLogValues (which does this authoritatively) is internal, so this is the best
        // available approach without reflection.
        private static string FormatTemplate(string template, Dictionary<string, object?> values)
        {
            var args = new List<object?>();
            var keyToIndex = new Dictionary<string, int>(StringComparer.Ordinal);
            var sb = new StringBuilder(template.Length);
            var i = 0;

            while (i < template.Length)
            {
                var c = template[i];
                if (c == '{')
                {
                    if (i + 1 < template.Length && template[i + 1] == '{')
                    {
                        sb.Append("{{");
                        i += 2;
                        continue;
                    }

                    var end = template.IndexOf('}', i + 1);
                    if (end < 0) { sb.Append(c); i++; continue; }

                    var content = template[(i + 1)..end];
                    var specifierStart = content.IndexOfAny([',', ':']);
                    var key = specifierStart < 0 ? content : content[..specifierStart];
                    var specifier = specifierStart < 0 ? "" : content[specifierStart..];

                    if (!keyToIndex.TryGetValue(key, out var idx))
                    {
                        idx = args.Count;
                        keyToIndex[key] = idx;
                        args.Add(values.TryGetValue(key, out var v) ? v : null);
                    }

                    sb.Append('{').Append(idx).Append(specifier).Append('}');
                    i = end + 1;
                }
                else if (c == '}' && i + 1 < template.Length && template[i + 1] == '}')
                {
                    sb.Append("}}");
                    i += 2;
                }
                else
                {
                    sb.Append(c);
                    i++;
                }
            }

            try { return string.Format(sb.ToString(), args.ToArray()); }
            catch { return template; }
        }
    }
}
