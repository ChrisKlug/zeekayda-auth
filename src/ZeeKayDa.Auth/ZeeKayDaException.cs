namespace ZeeKayDa.Auth;

/// <summary>
/// The base class for every exception ZeeKayDa.Auth throws; catch it for any framework error, or a subtype for one category.
/// </summary>
public abstract class ZeeKayDaException : Exception
{
    /// <summary>Initialises a new instance with the specified <paramref name="message"/>.</summary>
    protected ZeeKayDaException(string message) : base(message) { }

    /// <summary>
    /// Initialises a new instance with the specified <paramref name="message"/> and
    /// <paramref name="innerException"/>.
    /// </summary>
    protected ZeeKayDaException(string message, Exception innerException)
        : base(message, innerException) { }
}
