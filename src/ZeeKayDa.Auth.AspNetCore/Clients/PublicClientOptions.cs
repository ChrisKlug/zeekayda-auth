using ZeeKayDa.Auth.Clients;

namespace ZeeKayDa.Auth.AspNetCore.Clients;

/// <summary>
/// The settings a public client registered with
/// <see cref="IInMemoryClientRegistrationBuilder.AddPublic"/> can configure.
/// </summary>
/// <remarks>
/// A public client always authenticates with <c>none</c> at the token endpoint and is always held to
/// PKCE, so neither is configurable here.
/// </remarks>
public sealed class PublicClientOptions : ClientOptions
{
    internal PublicClientOptions(ClientRegistration defaults)
        : base(defaults)
    {
    }
}
