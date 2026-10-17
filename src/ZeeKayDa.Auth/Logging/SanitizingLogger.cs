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
/// <para>
/// Covers only ZeeKayDa.Auth's own log calls. Host surfaces such as <c>UseHttpLogging()</c>, Kestrel,
/// W3CLogger and Application Insights need their own configuration; see the
/// <see href="https://chrisklug.github.io/zeekayda-auth/how-to/configure-host-log-hygiene/">
/// host log hygiene</see> guide. Only key-value states are inspected, against <c>SensitiveKeys</c>.
/// </para>
/// <para>
/// Exceptions are wrapped in a <see cref="RedactedExceptionWrapper"/> unless
/// <see cref="Configuration.DevelopmentOptions.DisableExceptionSanitizing"/> is set.
/// </para>
/// <para>
/// The <c>ZEEKAYDA0001</c> analyzer requires it over a direct <see cref="ILogger{T}"/>. Its only
/// constructor is internal, so no registration can substitute a logger that skips redaction.
/// </para>
/// </remarks>
/// <typeparam name="T">The type whose name is used for the logger category.</typeparam>
public class SanitizingLogger<T> : ILogger<T>
{
    private readonly ILogger<T> _inner;
    private readonly IOptions<AuthorizationServerOptions> _options;

    internal SanitizingLogger(ILogger<T> inner, IOptions<AuthorizationServerOptions> options)
    {
        _inner = inner;
        _options = options;
    }

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
            "DPoP",

            // An ID token presented back as a hint: a signed JWT carrying the user's sub and claims.
            "id_token_hint",
            "IdTokenHint",

            // Personal data rather than a credential: an email address or phone number.
            "login_hint",
            "LoginHint",
        };

    /// <inheritdoc/>
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
                return _inner.BeginScope(redacted);
            }
        }

        return _inner.BeginScope(state);
    }

    /// <inheritdoc/>
    public bool IsEnabled(LogLevel logLevel)
        => _inner.IsEnabled(logLevel);

    /// <inheritdoc/>
    public void Log<TState>(
        LogLevel logLevel,
        EventId eventId,
        TState state,
        Exception? exception,
        Func<TState, Exception?, string> formatter)
    {
        if (!_inner.IsEnabled(logLevel))
            return;

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
                _inner.Log(logLevel, eventId, new RedactedLogValues(redacted), wrappedException, (s, ex) => s.ToString());
                return;
            }
        }
        else if (state is not string)
        {
            // Opaque state cannot be inspected, so it is replaced rather than risk leaking it.
            const string blocked = "[ZeeKayDa: unscrubbable log state blocked]";
            _inner.Log(logLevel, eventId, blocked, wrappedException, static (s, _) => s);
            return;
        }

        _inner.Log(logLevel, eventId, state, wrappedException, formatter);
    }

    private Exception? WrapException(Exception? exception)
    {
        if (exception is null || _options.Value.Development.DisableExceptionSanitizing)
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

        // Rewrites a named template as an indexed one, so string.Format handles specifiers and escapes.
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

/// <summary>
/// The <see cref="SanitizingLogger{T}"/> the framework registers, since DI needs a public constructor it must not have.
/// </summary>
internal sealed class RegisteredSanitizingLogger<T>(ILogger<T> inner, IOptions<AuthorizationServerOptions> options)
    : SanitizingLogger<T>(inner, options);
