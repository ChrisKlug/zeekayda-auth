using ZeeKayDa.Auth.Clients;

namespace ZeeKayDa.Auth.Clients;

/// <summary>
/// The settings a public client registered with
/// <see cref="InMemoryClientRegistrationBuilder.AddPublic"/> can configure.
/// </summary>
/// <remarks>
/// A public client always authenticates with <c>none</c> at the token endpoint and is always held to
/// PKCE, so neither is configurable here.
/// </remarks>
public sealed class PublicClientOptions : ClientOptions
{
    internal PublicClientOptions()
    {
    }

    internal override Client ToClient(string clientId) => ToClient(clientId, isPublic: true);
}
