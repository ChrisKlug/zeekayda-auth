using System.Text;

namespace ZeeKayDa.Auth.Logging;

/// <summary>
/// An exception carrying only another's type name and stack trace, its inner chain wrapped the same
/// way, so no message that may hold credentials reaches a log sink.
/// </summary>
internal sealed class RedactedExceptionWrapper : Exception
{
    internal const string RedactedMessage =
        "[exception message redacted by SanitizingLogger]";

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
        // BuildInner has already thrown for a null original, in the base initializer.
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
    /// <remarks>The original's; a stack trace holds frame metadata only, never message text.</remarks>
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
            sb.Append(InnerException);
        }

        return sb.ToString();
    }
}
