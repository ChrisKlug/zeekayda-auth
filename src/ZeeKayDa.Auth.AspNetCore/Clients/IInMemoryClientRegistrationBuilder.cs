using ZeeKayDa.Auth.Clients;

namespace ZeeKayDa.Auth.AspNetCore.Clients;

/// <summary>
/// A builder for registering clients with the in-memory client repository.
/// </summary>
/// <remarks>
/// Obtained via <c>builder.AddInMemoryClients(clients => { ... })</c>. Multiple
/// <c>AddInMemoryClients</c> calls are additive — registrations accumulate rather than replace.
/// </remarks>
public interface IInMemoryClientRegistrationBuilder
{
    /// <summary>
    /// Registers a public client (no credentials, token endpoint auth method <c>none</c>).
    /// </summary>
    /// <remarks>
    /// <paramref name="configure"/>, when given, sets the client's other settings — for example
    /// <see cref="ClientOptions.RequireConsent"/> or <see cref="ClientOptions.DisplayName"/>. It is
    /// called once, before this method returns.
    /// </remarks>
    IInMemoryClientRegistrationBuilder AddPublic(
        string clientId,
        IEnumerable<string> redirectUris,
        IEnumerable<string> postLogoutRedirectUris,
        IEnumerable<string> allowedScopes,
        Action<PublicClientOptions>? configure = null);

    /// <summary>
    /// Registers a confidential client with a plaintext secret.
    /// </summary>
    /// <remarks>
    /// <para>
    /// <paramref name="configure"/>, when given, sets the client's other settings — for example
    /// <see cref="ClientOptions.RequireConsent"/> or
    /// <see cref="ConfidentialClientOptions.AllowedTokenEndpointAuthMethods"/>. It is called once,
    /// before this method returns.
    /// </para>
    /// <para>
    /// <strong>Warning:</strong> The plaintext secret is held transiently in the options object
    /// until the repository is constructed at host startup, at which point it is hashed by the
    /// configured <c>CompositeClientSecretHasher</c> and the options list is cleared so the
    /// plaintext becomes GC-eligible. Never store or log plaintext secrets in production.
    /// The <paramref name="clientSecret"/> parameter is for bootstrap registration only;
    /// for production usage load secrets from a secure store.
    /// </para>
    /// </remarks>
    IInMemoryClientRegistrationBuilder AddConfidential(
        string clientId,
        string clientSecret,
        IEnumerable<string> redirectUris,
        IEnumerable<string> postLogoutRedirectUris,
        IEnumerable<string> allowedScopes,
        Action<ConfidentialClientOptions>? configure = null);

    /// <summary>
    /// Registers a pre-built or pre-hashed <see cref="IClientRegistration"/> directly.
    /// </summary>
    IInMemoryClientRegistrationBuilder Add(IClientRegistration registration);
}
