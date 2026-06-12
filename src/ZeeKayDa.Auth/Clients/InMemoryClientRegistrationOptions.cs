namespace ZeeKayDa.Auth.Clients;

internal sealed class InMemoryClientRegistrationOptions
{
    public List<IClientRegistration> PreBuilt { get; } = new();
    public List<PendingConfidentialClientSpec> Pending { get; } = new();
}

internal sealed record PendingConfidentialClientSpec(
    string ClientId,
    string PlaintextSecret,
    IEnumerable<string> RedirectUris,
    IEnumerable<string> PostLogoutRedirectUris,
    IEnumerable<string> AllowedScopes);
