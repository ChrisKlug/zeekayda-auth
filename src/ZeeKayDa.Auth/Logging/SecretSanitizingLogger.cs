using System.Collections;
using Microsoft.Extensions.Logging;

namespace ZeeKayDa.Auth.Logging;

/// <summary>
/// Wraps an <see cref="ILogger{T}"/> and replaces known-sensitive structured-log values
/// with <c>[REDACTED]</c> before they reach the underlying logger.
/// </summary>
/// <remarks>
/// Sensitive keys (case-insensitive): <c>client_secret</c>, <c>code_verifier</c>,
/// <c>Authorization</c>. Only states that implement
/// <see cref="IEnumerable{T}">IEnumerable&lt;KeyValuePair&lt;string, object?&gt;&gt;</see>
/// are inspected; all other state types pass through unchanged.
/// <para>
/// This is a defence-in-depth backstop for ADR 0007 §7. The Roslyn analyzer
/// (<c>ZEEKAYDA0001</c>) is the primary preventive control: it enforces at compile time that
/// every ZeeKayDa service injects <see cref="ISanitizingLogger{T}"/> rather than
/// <see cref="ILogger{T}"/> directly. The CI log-hygiene grep
/// (<c>.github/scripts/check_log_hygiene.sh</c>) and this runtime wrapper are defence-in-depth
/// layers that remain in place regardless.
/// </para>
/// </remarks>
internal sealed class SecretSanitizingLogger<T>(ILogger<T> inner) : ISanitizingLogger<T>
{
    internal static readonly IReadOnlySet<string> SensitiveKeys =
        new HashSet<string>(StringComparer.OrdinalIgnoreCase)
        {
            "client_secret",
            "code_verifier",
            "Authorization",
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
                inner.Log(logLevel, eventId, new RedactedLogValues(redacted), exception, (s, ex) => s.ToString());
                return;
            }
        }
        else if (state is not string)
        {
            // Non-string, non-IEnumerable<KVP> state (e.g. from LoggerMessage.Define<T>) cannot
            // be inspected for sensitive key-value pairs. Substitute a safe placeholder rather
            // than risk leaking structured parameter values to the inner logger's sinks.
            const string blocked = "[ZeeKayDa: unscrubbable log state blocked]";
            inner.Log(logLevel, eventId, blocked, exception, static (s, _) => s);
            return;
        }

        inner.Log(logLevel, eventId, state, exception, formatter);
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

            var result = template;
            foreach (var kv in pairs.Where(kv => kv.Key != "{OriginalFormat}"))
            {
                // Ordinal is safe: structured logging convention guarantees the KV pair key and
                // the template placeholder are identical strings (same casing), so a case-sensitive
                // replace always finds the right substring.
                result = result.Replace($"{{{kv.Key}}}", kv.Value?.ToString() ?? "(null)", StringComparison.Ordinal);
            }
            return result;
        }
    }
}
