namespace ZeeKayDa.Auth.Clients;

internal sealed class InMemoryClientRegistrationOptions
{
    public List<IClientRegistration> PreBuilt { get; } = new();
    public List<PendingConfidentialClientSpec> Pending { get; } = new();
}

// A confidential client whose secret has not been hashed yet. Registration is complete except for
// its credentials, which the hashed secret fills in when the repository is built.
internal sealed record PendingConfidentialClientSpec(
    ClientRegistration Registration,
    string PlaintextSecret);
