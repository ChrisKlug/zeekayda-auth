using ZeeKayDa.Auth.Clients;
using ZeeKayDa.Auth.Tokens;

namespace ZeeKayDa.Auth.Clients;

/// <summary>
/// The settings a confidential client registered with
/// <see cref="InMemoryClientRegistrationBuilder.AddConfidential"/> can configure.
/// </summary>
/// <remarks>
/// Exactly one of <see cref="Secret"/> and <see cref="SecretHash"/> must be set; startup fails
/// otherwise.
/// </remarks>
public sealed class ConfidentialClientOptions : ClientOptions
{
    internal ConfidentialClientOptions()
    {
    }

    internal override Client ToClient(string clientId) => ToClient(clientId, isPublic: false) with
    {
        RequirePkce = RequirePkce,
        AllowedTokenEndpointAuthMethods = OrDefault(
            AllowedTokenEndpointAuthMethods,
            ClientDefaults.AllowedTokenEndpointAuthMethods(isPublic: false),
            StringComparer.Ordinal),
    };

    /// <summary>
    /// The client's secret in plaintext, hashed by the host's default <see cref="IClientSecretHasher"/>
    /// when the host starts.
    /// </summary>
    /// <remarks>
    /// A convenience for development and bootstrapping. The plaintext is held until startup and then
    /// released, but any configuration source it came from keeps its own copy for the life of the
    /// process. Prefer <see cref="SecretHash"/>, so the plaintext is never in the host at all.
    /// </remarks>
    public string? Secret { get; set; }

    /// <summary>
    /// The client's secret, already hashed, as a <see cref="ClientSecret"/> string such as
    /// <c>$pbkdf2-sha256$i=600000$&lt;salt&gt;$&lt;hash&gt;</c>.
    /// </summary>
    /// <remarks>
    /// Stored as given. A registered <see cref="IClientSecretHasher"/> must declare its algorithm id;
    /// startup fails otherwise.
    /// </remarks>
    public string? SecretHash { get; set; }

    /// <inheritdoc cref="IClient.RequirePkce"/>
    public bool RequirePkce { get; set; } = ClientDefaults.RequirePkce;

    /// <summary>
    /// Token endpoint authentication methods this client is permitted to use. Starts empty; left
    /// empty, the client gets <see cref="TokenEndpointAuthMethods.ClientSecretBasic"/>.
    /// </summary>
    /// <remarks>
    /// Every entry must also be listed in the server's <c>TokenEndpointOptions.AuthMethodsSupported</c>,
    /// and <see cref="TokenEndpointAuthMethods.None"/> is refused; startup fails otherwise.
    /// </remarks>
    public ISet<string> AllowedTokenEndpointAuthMethods { get; } = new HashSet<string>(StringComparer.Ordinal);
}
