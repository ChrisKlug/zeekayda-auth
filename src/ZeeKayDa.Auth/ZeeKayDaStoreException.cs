namespace ZeeKayDa.Auth;

/// <summary>
/// Thrown by the authorization code and refresh token stores when the underlying storage fails at
/// request time. Outcomes such as "not found" or "already consumed" are returned, not thrown.
/// </summary>
public class ZeeKayDaStoreException : ZeeKayDaException
{
    /// <summary>Initialises a new instance with the specified <paramref name="message"/>.</summary>
    public ZeeKayDaStoreException(string message) : base(message) { }

    /// <summary>
    /// Initialises a new instance with the specified <paramref name="message"/> and
    /// <paramref name="innerException"/>.
    /// </summary>
    public ZeeKayDaStoreException(string message, Exception innerException)
        : base(message, innerException) { }
}
