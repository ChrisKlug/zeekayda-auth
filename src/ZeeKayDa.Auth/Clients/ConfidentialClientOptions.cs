using ZeeKayDa.Auth.Clients;
using ZeeKayDa.Auth.Tokens;

namespace ZeeKayDa.Auth.Clients;

/// <summary>
/// The settings a confidential client registered with
/// <see cref="IInMemoryClientRegistrationBuilder.AddConfidential"/> can configure.
/// </summary>
public sealed class ConfidentialClientOptions : ClientOptions
{
    internal ConfidentialClientOptions()
    {
        RequirePkce = ClientDefaults.RequirePkce;
        AllowedTokenEndpointAuthMethods = new HashSet<string>(StringComparer.Ordinal);
    }

    internal override Client ApplyTo(Client registration) => base.ApplyTo(registration) with
    {
        RequirePkce = RequirePkce,
        AllowedTokenEndpointAuthMethods = OrDefault(
            AllowedTokenEndpointAuthMethods, registration.AllowedTokenEndpointAuthMethods, StringComparer.Ordinal),
    };

    /// <inheritdoc cref="IClient.RequirePkce"/>
    public bool RequirePkce { get; set; }

    /// <summary>
    /// Token endpoint authentication methods this client is permitted to use. Starts empty; left
    /// empty, the client gets <see cref="TokenEndpointAuthMethods.ClientSecretBasic"/>.
    /// </summary>
    /// <remarks>
    /// Every entry must also be listed in the server's <c>TokenEndpointOptions.AuthMethodsSupported</c>,
    /// and <see cref="TokenEndpointAuthMethods.None"/> is refused; startup fails otherwise.
    /// </remarks>
    public ISet<string> AllowedTokenEndpointAuthMethods { get; }
}
