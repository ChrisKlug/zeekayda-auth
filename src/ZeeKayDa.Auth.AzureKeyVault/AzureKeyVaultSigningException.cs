namespace ZeeKayDa.Auth.AzureKeyVault;

/// <summary>
/// Thrown when a transient fault occurs while asking Azure Key Vault to perform a sign operation
/// at request time — for example, throttling (HTTP 429) or a transport-level failure.
/// </summary>
/// <remarks>
/// <para>
/// This is deliberately distinct from <see cref="ZeeKayDaConfigurationException"/>, which covers
/// setup-time faults detected while discovering key versions (missing key, denied access). Those
/// are not recoverable without an operator fixing the configuration; a fault covered by this
/// exception may be transient (e.g. a throttled request can succeed on retry).
/// </para>
/// <para>
/// The original Azure SDK exception (typically <see cref="Azure.RequestFailedException"/>) is
/// always chained as <see cref="Exception.InnerException"/> so its <c>Status</c> and
/// <c>ErrorCode</c> remain inspectable by callers that want to distinguish failure modes.
/// </para>
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
