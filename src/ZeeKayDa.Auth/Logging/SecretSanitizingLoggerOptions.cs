namespace ZeeKayDa.Auth.Logging;

/// <summary>
/// Options that control runtime behaviour of <see cref="SecretSanitizingLogger{T}"/>.
/// </summary>
internal sealed class SecretSanitizingLoggerOptions
{
    /// <summary>
    /// Gets or sets a value indicating whether exception message sanitization is disabled.
    /// </summary>
    /// <remarks>
    /// When <see langword="true"/>, exception objects are forwarded to log sinks without wrapping.
    /// Exception messages may therefore contain credential material. Only disable this when a
    /// downstream sink is itself responsible for exception message redaction.
    /// </remarks>
    public bool ExceptionSanitizingDisabled { get; set; }
}
