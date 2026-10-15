namespace ZeeKayDa.Auth;

/// <summary>
/// Thrown at request time when the host calls the interaction API in the wrong state or order: a
/// programming error to fix in the host, not a recoverable condition.
/// </summary>
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
