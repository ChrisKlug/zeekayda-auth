namespace ZeeKayDa.Auth;

/// <summary>
/// Thrown when the ZeeKayDa.Auth framework is misconfigured or when a required configuration
/// value is absent or invalid at the point where it is first needed.
/// </summary>
/// <remarks>
/// <para>
/// This exception indicates a setup-time error in the host application — missing service
/// registrations, invalid options values, or configuration state that is required for the
/// framework to operate but was not provided. It is not recoverable at runtime; the correct
/// response is to fix the configuration and restart.
/// </para>
/// <para>
/// Most configuration errors are caught earlier by the startup validator
/// (<c>ValidateOnStart()</c> / <see cref="Microsoft.Extensions.Options.IValidateOptions{TOptions}"/>).
/// This exception covers the residual cases where invalid state is only detectable at the moment
/// the framework needs to use a value — for example, when <c>MapZeeKayDaAuth()</c> is called
/// before <c>AddZeeKayDaAuth()</c>.
/// </para>
/// </remarks>
public class ZeeKayDaConfigurationException : ZeeKayDaException
{
    /// <summary>Initialises a new instance with the specified <paramref name="message"/>.</summary>
    public ZeeKayDaConfigurationException(string message) : base(message) { }

    /// <summary>
    /// Initialises a new instance with the specified <paramref name="message"/> and
    /// <paramref name="innerException"/>.
    /// </summary>
    public ZeeKayDaConfigurationException(string message, Exception innerException)
        : base(message, innerException) { }
}
