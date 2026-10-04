namespace ZeeKayDa.Auth.Clients;

internal sealed class InMemoryClientRegistrationOptions
{
    public List<IClientWithCredentials> PreBuilt { get; } = new();
    public List<PendingConfidentialClientSpec> Pending { get; } = new();
}

// A confidential client whose credential is not built yet: a plaintext secret is hashed with the
// host's default hasher, which is resolved only when the repository is built.
internal sealed record PendingConfidentialClientSpec(
    Client Registration,
    string? PlaintextSecret,
    string? SecretHash);
