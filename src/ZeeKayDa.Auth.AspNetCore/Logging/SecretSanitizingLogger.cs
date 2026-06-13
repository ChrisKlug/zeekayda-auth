using System.Collections;
using Microsoft.Extensions.Logging;

namespace ZeeKayDa.Auth.AspNetCore.Logging;

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
/// This is a defence-in-depth backstop for ADR 0007 §7. The CI log-hygiene grep
/// (<c>.github/scripts/check_log_hygiene.sh</c>) is the primary preventive control.
/// </para>
/// </remarks>
internal sealed class SecretSanitizingLogger<T>(ILogger<T> inner) : ILogger<T>
{
    internal static readonly IReadOnlySet<string> SensitiveKeys =
        new HashSet<string>(StringComparer.OrdinalIgnoreCase)
        {
            "client_secret",
            "code_verifier",
            "Authorization",
        };

    public IDisposable? BeginScope<TState>(TState state) where TState : notnull
        => inner.BeginScope(state);

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
            foreach (var kv in pairs)
            {
                if (kv.Key == "{OriginalFormat}") continue;
                result = result.Replace($"{{{kv.Key}}}", kv.Value?.ToString() ?? "(null)", StringComparison.Ordinal);
            }
            return result;
        }
    }
}
