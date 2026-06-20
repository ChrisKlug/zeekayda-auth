namespace ZeeKayDa.Auth;

/// <summary>
/// Thrown by <c>IAuthorizationCodeStore</c> and <c>IRefreshTokenStore</c> implementations when
/// an underlying transport (cache, database, network) fails. Distinct from semantic outcomes such
/// as NotFound or AlreadyConsumed, which are returned, not thrown.
/// <!-- TODO: upgrade to <see cref="IAuthorizationCodeStore"/> and <see cref="IRefreshTokenStore"/> once those interfaces are defined -->
/// </summary>
/// <remarks>
/// <para>
/// This exception indicates an infrastructure failure — the store could not complete the
/// requested operation due to a problem with the underlying storage technology (e.g. Redis
/// connection failure, database timeout, network error). It is distinct from semantic outcomes
/// such as NotFound or AlreadyConsumed, which are modelled as return values rather than
/// exceptions.
/// </para>
/// <para>
/// This exception is deliberately distinct from <see cref="ZeeKayDaConfigurationException"/>.
/// Configuration errors exist at startup/setup time; store transport errors exist at request
/// time. The distinction matters for logging, alerting, and catch-clause granularity.
/// </para>
/// </remarks>
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
