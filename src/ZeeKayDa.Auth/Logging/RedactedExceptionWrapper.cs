namespace ZeeKayDa.Auth.Logging;

/// <summary>
/// Wraps an exception so that its message — which may contain credential material — never reaches
/// log sinks in plain text. The original exception is preserved as <see cref="Exception.InnerException"/>
/// so stack traces and the full exception chain remain inspectable by operators.
/// </summary>
internal sealed class RedactedExceptionWrapper : Exception
{
    internal const string RedactedMessage =
        "[exception message redacted by SecretSanitizingLogger]";

    public RedactedExceptionWrapper(Exception original)
        : base(RedactedMessage, original)
    {
        ArgumentNullException.ThrowIfNull(original);
        OriginalExceptionType = original.GetType().FullName ?? original.GetType().Name;
    }

    /// <summary>Gets the fully-qualified type name of the wrapped exception.</summary>
    public string OriginalExceptionType { get; }

    /// <inheritdoc/>
    public override string ToString()
        => $"{nameof(RedactedExceptionWrapper)} ({OriginalExceptionType}): {RedactedMessage}{Environment.NewLine}{InnerException}";
}
