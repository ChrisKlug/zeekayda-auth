using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using ZeeKayDa.Auth;
using ZeeKayDa.Auth.Logging;
using ZeeKayDa.Auth.Tokens;

namespace ZeeKayDa.Auth.Clients;

/// <summary>An in-memory <see cref="IClientRepository"/>, populated at startup from <see cref="InMemoryClientRegistrationOptions"/>.</summary>
internal sealed class InMemoryClientRepository : IClientRepository
{
    private readonly IReadOnlyDictionary<string, IClientWithCredentials> _clients;

    private InMemoryClientRepository(IReadOnlyDictionary<string, IClientWithCredentials> clients) =>
        _clients = clients;

    /// <summary>The DI factory <c>AddInMemoryClients</c> registers, and recognises as its own.</summary>
    internal static readonly Func<IServiceProvider, IClientRepository> Factory = services => Build(
        services.GetRequiredService<InMemoryClientRegistrationOptions>(),
        services.GetRequiredService<ClientSecrets>(),
        services.GetRequiredService<FrameworkThenHostValidator>());

    /// <summary>
    /// Hashes the pending secrets, then checks every registration. Plaintext is released only on success, so
    /// building again fails the same way rather than succeed without those clients.
    /// </summary>
    /// <exception cref="ZeeKayDaConfigurationException">
    /// Any registration is invalid. Every failure across all of them is aggregated, so operators
    /// see every problem in one pass.
    /// </exception>
    internal static InMemoryClientRepository Build(
        InMemoryClientRegistrationOptions registrations,
        ClientSecrets secrets,
        FrameworkThenHostValidator validator)
    {
        var (clients, failures) = HashPending(registrations.Pending, secrets);
        clients.AddRange(registrations.PreBuilt);

        failures.AddRange(FindDuplicateClientIds(clients));
        failures.AddRange(clients.SelectMany(validator.Validate));

        if (failures.Count > 0)
            throw new ZeeKayDaConfigurationException([.. failures]);

        registrations.Pending.Clear();
        return new InMemoryClientRepository(clients.ToDictionary(client => client.ClientId, StringComparer.Ordinal));
    }

    /// <summary>The pending specs with their secrets set, and a failure for each without exactly one usable secret.</summary>
    private static (List<IClientWithCredentials> Clients, List<ZeeKayDaConfigurationFailure> Failures) HashPending(
        IEnumerable<PendingConfidentialClientSpec> pending,
        ClientSecrets secrets)
    {
        var clients = new List<IClientWithCredentials>();
        var failures = new List<ZeeKayDaConfigurationFailure>();

        foreach (var spec in pending)
        {
            if (CheckSecret(spec) is { } failure)
            {
                failures.Add(failure);
                continue;
            }

            var secret = spec.SecretHash is { } hash ? new ClientSecret(hash) : secrets.Create(spec.PlaintextSecret!);
            clients.Add(spec.Registration with { Secrets = [secret] });
        }

        return (clients, failures);
    }

    private static ZeeKayDaConfigurationFailure? CheckSecret(PendingConfidentialClientSpec spec) =>
        (spec.PlaintextSecret, spec.SecretHash) switch
        {
            (null, null) => new ZeeKayDaConfigurationFailure(
                "client.credentials.no_secret",
                $"Confidential client '{spec.Registration.ClientId}' has neither a Secret nor a SecretHash. Set one of them."),
            (not null, not null) => new ZeeKayDaConfigurationFailure(
                "client.credentials.secret_and_secret_hash",
                $"Confidential client '{spec.Registration.ClientId}' has both a Secret and a SecretHash. " +
                "Set only one, so it is clear which secret the client authenticates with."),
            ({ } plaintext, null) when string.IsNullOrWhiteSpace(plaintext) => new ZeeKayDaConfigurationFailure(
                "client.credentials.empty_plaintext_secret",
                $"Client '{spec.Registration.ClientId}' was registered with an empty or whitespace plaintext secret. " +
                "Use a strong random secret loaded from a secrets manager or environment variable."),
            (null, { } hash) when string.IsNullOrWhiteSpace(hash) => new ZeeKayDaConfigurationFailure(
                "client.credentials.empty_secret_hash",
                $"Confidential client '{spec.Registration.ClientId}' has an empty or whitespace SecretHash. " +
                "Set it to a hashed secret such as '$pbkdf2-sha256$...'."),
            _ => null,
        };

    private static IEnumerable<ZeeKayDaConfigurationFailure> FindDuplicateClientIds(IEnumerable<IClientWithCredentials> clients)
    {
        var seen = new HashSet<string>(StringComparer.Ordinal);

        return clients.Where(client => !seen.Add(client.ClientId)).Select(client => new ZeeKayDaConfigurationFailure(
            "client.client_id.duplicate",
            $"A client with ClientId '{client.ClientId}' has been registered more than once. " +
            "Each client must have a unique ClientId (ordinal comparison)."));
    }

    /// <summary>Every registration this repository serves, for the startup checks that read them all.</summary>
    internal IEnumerable<IClientWithCredentials> Registrations => _clients.Values;

    /// <inheritdoc/>
    public Task<IClientWithCredentials?> FindByClientIdAsync(
        string clientId,
        CancellationToken cancellationToken = default)
    {
        // The contract answers null, never throws, for a malformed client_id.
        if (clientId is null)
            return Task.FromResult<IClientWithCredentials?>(null);

        _clients.TryGetValue(clientId, out var reg);
        return Task.FromResult(reg);
    }
}
