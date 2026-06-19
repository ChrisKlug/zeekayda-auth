using System.Text;

namespace ZeeKayDa.Auth.Logging;

/// <summary>
/// Wraps an exception so that its message — which may contain credential material — never reaches
/// log sinks in plain text. The original exception object is never stored or exposed; only the
/// type name, the placeholder message, and the stack trace are forwarded to sinks.
/// </summary>
/// <remarks>
/// The <see cref="Exception.InnerException"/> chain is preserved as a recursively-wrapped
/// <see cref="RedactedExceptionWrapper"/> tree rather than the original exception objects, so no
/// un-redacted message text can leak through <c>InnerException.ToString()</c> or
/// <c>InnerException.Message</c>.
/// </remarks>
internal sealed class RedactedExceptionWrapper : Exception
{
    internal const string RedactedMessage =
        "[exception message redacted by SecretSanitizingLogger]";

    private const int MaxDepth = 50;

    private readonly Exception _original;

    /// <summary>
    /// Initialises a new <see cref="RedactedExceptionWrapper"/> from <paramref name="original"/>.
    /// </summary>
    /// <param name="original">The exception whose message must be redacted.</param>
    /// <exception cref="ArgumentNullException">
    /// Thrown when <paramref name="original"/> is <see langword="null"/>.
    /// </exception>
    public RedactedExceptionWrapper(Exception original)
        : this(original, depth: 0)
    {
    }

    private RedactedExceptionWrapper(Exception original, int depth)
        : base(RedactedMessage, BuildInner(original, depth))
    {
        // ArgumentNullException.ThrowIfNull is intentionally absent here: BuildInner —
        // evaluated in the base-constructor initializer above — already throws with the
        // correct "original" parameter name before this body is reached.
        _original = original;
        OriginalExceptionType = original.GetType().FullName ?? original.GetType().Name;
    }

    private static RedactedExceptionWrapper? BuildInner(Exception original, int depth)
    {
        ArgumentNullException.ThrowIfNull(original);

        if (original.InnerException is null || depth >= MaxDepth)
            return null;

        return new RedactedExceptionWrapper(original.InnerException, depth + 1);
    }

    /// <summary>Gets the fully-qualified type name of the wrapped exception.</summary>
    public string OriginalExceptionType { get; }

    /// <inheritdoc/>
    /// <remarks>
    /// Returns the stack trace from the original exception so that operators retain
    /// full diagnostic information even though the original is not stored as
    /// <see cref="Exception.InnerException"/>. A stack trace contains only frame metadata
    /// (method names, file names, and line numbers) — it never includes the exception
    /// message text — so forwarding it does not create a message-leak vector.
    /// </remarks>
    public override string? StackTrace => _original.StackTrace;

    /// <inheritdoc/>
    public override string ToString()
    {
        var sb = new StringBuilder();
        sb.Append(nameof(RedactedExceptionWrapper));
        sb.Append(" (");
        sb.Append(OriginalExceptionType);
        sb.Append("): ");
        sb.Append(Message);

        if (StackTrace is not null)
        {
            sb.AppendLine();
            sb.Append(StackTrace);
        }

        if (InnerException is not null)
        {
            sb.AppendLine();
            sb.Append(" ---> ");
            // InnerException is always a RedactedExceptionWrapper — calling ToString() on it
            // is safe and will never surface the original message text.
            sb.Append(InnerException);
        }

        return sb.ToString();
    }
}
