namespace ZeeKayDa.Auth;

/// <summary>
/// Thrown when the ZeeKayDa.Auth interaction API is called incorrectly — for example, calling
/// a continuation method without a valid pending interaction context, or providing a result
/// that is inconsistent with the expected interaction step.
/// </summary>
/// <remarks>
/// <para>
/// This exception indicates a programming error in the host application: the interaction API
/// was called in the wrong state or in the wrong order. It is not a recoverable runtime
/// condition; the correct response is to fix the host application code.
/// </para>
/// <para>
/// This exception is deliberately distinct from <see cref="ZeeKayDaConfigurationException"/>.
/// Configuration errors exist at startup/setup time; interaction errors exist at request time.
/// The distinction matters for logging, alerting, and catch-clause granularity.
/// </para>
/// </remarks>
public class ZeeKayDaInteractionException : ZeeKayDaException
{
    /// <summary>Initialises a new instance with the specified <paramref name="message"/>.</summary>
    public ZeeKayDaInteractionException(string message) : base(message) { }

    /// <summary>
    /// Initialises a new instance with the specified <paramref name="message"/> and
    /// <paramref name="innerException"/>.
    /// </summary>
    public ZeeKayDaInteractionException(string message, Exception innerException)
        : base(message, innerException) { }
}
