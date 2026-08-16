namespace ZeeKayDa.Auth.AzureKeyVault;

/// <summary>
/// Thrown when a transient fault occurs while asking Azure Key Vault to perform a sign operation
/// at request time — for example, throttling (HTTP 429) or a transport-level failure.
/// </summary>
/// <remarks>
/// Deliberately distinct from <see cref="ZeeKayDaConfigurationException"/>, which covers
/// setup-time faults (missing key, denied access) that are not recoverable without an operator
/// fixing the configuration; a fault covered by this exception may be transient. The original
/// Azure SDK exception is chained as <see cref="Exception.InnerException"/> so its <c>Status</c>
/// and <c>ErrorCode</c> remain inspectable.
/// </remarks>
public class AzureKeyVaultSigningException : ZeeKayDaException
{
    /// <summary>Initialises a new instance with the specified <paramref name="message"/>.</summary>
    public AzureKeyVaultSigningException(string message) : base(message) { }

    /// <summary>
    /// Initialises a new instance with the specified <paramref name="message"/> and
    /// <paramref name="innerException"/>.
    /// </summary>
    public AzureKeyVaultSigningException(string message, Exception innerException)
        : base(message, innerException) { }
}
