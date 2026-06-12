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
    IInMemoryClientRegistrationBuilder AddPublic(
        string clientId,
        IEnumerable<string> redirectUris,
        IEnumerable<string> postLogoutRedirectUris,
        IEnumerable<string> allowedScopes);

    /// <summary>
    /// Registers a confidential client with a plaintext secret.
    /// </summary>
    /// <remarks>
    /// <strong>Warning:</strong> The plaintext secret is stored temporarily during service
    /// registration and hashed at repository construction using the configured
    /// <c>CompositeClientSecretHasher</c>. Never store or log plaintext secrets in production.
    /// The <paramref name="clientSecret"/> parameter is for bootstrap registration only;
    /// for production usage load secrets from a secure store.
    /// </remarks>
    IInMemoryClientRegistrationBuilder AddConfidential(
        string clientId,
        string clientSecret,
        IEnumerable<string> redirectUris,
        IEnumerable<string> postLogoutRedirectUris,
        IEnumerable<string> allowedScopes);

    /// <summary>
    /// Registers a pre-built or pre-hashed <see cref="IClientRegistration"/> directly.
    /// </summary>
    IInMemoryClientRegistrationBuilder Add(IClientRegistration registration);
}
