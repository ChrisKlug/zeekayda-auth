namespace ZeeKayDa.Auth.Clients;

/// <summary>
/// Validates a client registration against the framework's configuration rules.
/// </summary>
/// <remarks>
/// <para>
/// The default implementation (<c>ClientRegistrationValidator</c>) enforces all redirect URI
/// rules, the <c>IsPublic</c> trinity, <c>ClientId</c> format, the empty-secret probe, the
/// two-credential cap, and the <c>AllowedTokenEndpointAuthMethods</c> subset check.
/// </para>
/// <para>
/// Custom <c>IClientRepository</c> implementations MUST resolve this service from DI and
/// invoke it before persisting a new or updated client.
/// </para>
/// </remarks>
public interface IClientRegistrationValidator
{
    /// <summary>
    /// Validates <paramref name="client"/> against all framework configuration rules.
    /// </summary>
    /// <param name="client">The registration to validate.</param>
    /// <exception cref="ZeeKayDaConfigurationException">
    /// Thrown when one or more rule violations are detected. All violations are aggregated into
    /// a single exception so operators see every problem in one pass — see
    /// <see cref="ZeeKayDaConfigurationException.AggregatedFailures"/>.
    /// </exception>
    void Validate(IClientRegistration client);
}
