namespace ZeeKayDa.Auth;

/// <summary>
/// The base class for all exceptions thrown by ZeeKayDa.Auth framework code.
/// </summary>
/// <remarks>
/// This class is never thrown directly. Catch <see cref="ZeeKayDaException"/> as a blanket
/// handler for any ZeeKayDa.Auth framework error, or catch a specific subtype to handle a
/// known failure category.
/// </remarks>
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
