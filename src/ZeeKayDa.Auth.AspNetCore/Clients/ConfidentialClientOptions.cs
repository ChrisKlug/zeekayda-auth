using ZeeKayDa.Auth.Clients;
using ZeeKayDa.Auth.Tokens;

namespace ZeeKayDa.Auth.AspNetCore.Clients;

/// <summary>
/// The settings a confidential client registered with
/// <see cref="IInMemoryClientRegistrationBuilder.AddConfidential"/> can configure.
/// </summary>
public sealed class ConfidentialClientOptions : ClientOptions
{
    internal ConfidentialClientOptions(ClientRegistration defaults)
        : base(defaults)
    {
        RequirePkce = defaults.RequirePkce;
        AllowedTokenEndpointAuthMethods = new HashSet<string>(
            defaults.AllowedTokenEndpointAuthMethods, StringComparer.Ordinal);
    }

    internal override ClientRegistration ApplyTo(ClientRegistration registration) => base.ApplyTo(registration) with
    {
        RequirePkce = RequirePkce,
        AllowedTokenEndpointAuthMethods = new HashSet<string>(AllowedTokenEndpointAuthMethods, StringComparer.Ordinal),
    };

    /// <inheritdoc cref="IClientMetadata.RequirePkce"/>
    public bool RequirePkce { get; set; }

    /// <summary>
    /// Token endpoint authentication methods this client is permitted to use. Contains
    /// <see cref="TokenEndpointAuthMethods.ClientSecretBasic"/> by default.
    /// </summary>
    /// <remarks>
    /// Every entry must also be listed in the server's <c>TokenEndpointOptions.AuthMethodsSupported</c>,
    /// and <see cref="TokenEndpointAuthMethods.None"/> is refused; startup fails otherwise.
    /// </remarks>
    public ISet<string> AllowedTokenEndpointAuthMethods { get; }
}
