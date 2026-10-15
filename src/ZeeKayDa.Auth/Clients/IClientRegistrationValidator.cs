namespace ZeeKayDa.Auth.Clients;

/// <summary>
/// Validates a client registration against the framework's configuration rules.
/// </summary>
/// <remarks>
/// The framework runs it on every registration a repository returns. A custom repository may also call it
/// before persisting, so a bad registration is refused where it is written.
/// </remarks>
public interface IClientRegistrationValidator
{
    /// <summary>
    /// Validates <paramref name="client"/> against all framework configuration rules.
    /// </summary>
    /// <param name="client">The registration to validate.</param>
    /// <returns>
    /// Every rule violation found, so operators see every problem in one pass; empty when the
    /// registration is valid. An invalid registration is an expected outcome, never an exception.
    /// </returns>
    IReadOnlyList<ZeeKayDaConfigurationFailure> Validate(IClientWithCredentials client);
}
