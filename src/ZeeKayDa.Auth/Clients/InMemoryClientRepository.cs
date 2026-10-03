using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using ZeeKayDa.Auth;
using ZeeKayDa.Auth.Logging;
using ZeeKayDa.Auth.Tokens;

namespace ZeeKayDa.Auth.Clients;

/// <summary>
/// An in-memory <see cref="IClientRepository"/> populated at startup from configured
/// <see cref="InMemoryClientRegistrationOptions"/>.
/// </summary>
/// <remarks>
/// Suitable for development, testing, and simple deployments. For production scenarios with
/// many clients or dynamic registration, implement a custom <see cref="IClientRepository"/>.
/// </remarks>
internal sealed class InMemoryClientRepository : IClientRepository
{
    private readonly IReadOnlyDictionary<string, IClientWithCredentials> _clients;

    private InMemoryClientRepository(IReadOnlyDictionary<string, IClientWithCredentials> clients) =>
        _clients = clients;

    /// <summary>The DI factory <c>AddInMemoryClients</c> registers, and recognises as its own.</summary>
    internal static readonly Func<IServiceProvider, IClientRepository> Factory = services =>
    {
        var repository = Build(
            services.GetRequiredService<InMemoryClientRegistrationOptions>(),
            services.GetRequiredService<ClientSecrets>(),
            services.GetRequiredService<IClientRegistrationValidator>());

        repository.WarnIfNoneHasNoPublicClient(
            services.GetRequiredService<IOptions<AuthorizationServerOptions>>().Value,
            services.GetRequiredService<SanitizingLogger<InMemoryClientRepository>>());

        return repository;
    };

    /// <summary>
    /// Hashes the pending secrets, then checks every registration for a duplicate
    /// <c>client_id</c> and against <paramref name="validator"/>.
    /// </summary>
    /// <exception cref="ZeeKayDaConfigurationException">
    /// Any registration is invalid. Every failure across all of them is aggregated, so operators
    /// see every problem in one pass.
    /// </exception>
    internal static InMemoryClientRepository Build(
        InMemoryClientRegistrationOptions registrations,
        ClientSecrets secrets,
        IClientRegistrationValidator validator)
    {
        var (clients, failures) = HashPending(registrations.Pending, secrets);
        clients.AddRange(registrations.PreBuilt);

        failures.AddRange(FindDuplicateClientIds(clients));
        failures.AddRange(clients.SelectMany(client => FrameworkThenHostValidator.Checked(validator, client)));

        return failures.Count > 0
            ? throw new ZeeKayDaConfigurationException([.. failures])
            : new InMemoryClientRepository(clients.ToDictionary(client => client.ClientId, StringComparer.Ordinal));
    }

    /// <summary>
    /// The pending specs as confidential registrations with their secrets hashed, and a failure for
    /// each spec whose plaintext secret is blank, which is skipped so the rest are still checked.
    /// </summary>
    private static (List<IClientWithCredentials> Clients, List<ZeeKayDaConfigurationFailure> Failures) HashPending(
        IEnumerable<PendingConfidentialClientSpec> pending,
        ClientSecrets secrets)
    {
        var clients = new List<IClientWithCredentials>();
        var failures = new List<ZeeKayDaConfigurationFailure>();

        foreach (var spec in pending)
        {
            if (string.IsNullOrWhiteSpace(spec.PlaintextSecret))
            {
                failures.Add(new ZeeKayDaConfigurationFailure(
                    "client.credentials.empty_plaintext_secret",
                    $"Client '{spec.Registration.ClientId}' was registered with a null, empty, or whitespace plaintext secret. " +
                    "Use a strong random secret loaded from a secrets manager or environment variable."));
                continue;
            }

            clients.Add(spec.Registration with { Secrets = [secrets.Create(spec.PlaintextSecret)] });
        }

        return (clients, failures);
    }

    private static IEnumerable<ZeeKayDaConfigurationFailure> FindDuplicateClientIds(IEnumerable<IClientWithCredentials> clients)
    {
        var seen = new HashSet<string>(StringComparer.Ordinal);

        return clients.Where(client => !seen.Add(client.ClientId)).Select(client => new ZeeKayDaConfigurationFailure(
            "client.client_id.duplicate",
            $"A client with ClientId '{client.ClientId}' has been registered more than once. " +
            "Each client must have a unique ClientId (ordinal comparison)."));
    }

    /// <summary>Warns when the server accepts <c>none</c> but no public client is registered to use it.</summary>
    internal void WarnIfNoneHasNoPublicClient(AuthorizationServerOptions serverOptions, ILogger logger)
    {
        var advertisesNone = serverOptions.TokenEndpoint.AuthMethodsSupported
            .Any(method => string.Equals(method, TokenEndpointAuthMethods.None, StringComparison.Ordinal));

        if (advertisesNone && !_clients.Values.Any(client => client.IsPublic))
        {
            logger.LogWarning(
                "The server advertises 'none' as a supported token endpoint authentication method " +
                "but no public clients (IsPublic=true) are registered. Consider removing " +
                "TokenEndpointAuthMethods.None from AuthMethodsSupported if no public clients are expected.");
        }
    }

    /// <summary>Every registration this repository serves, for the startup checks that read them all.</summary>
    internal IEnumerable<IClientWithCredentials> Registrations => _clients.Values;

    /// <inheritdoc/>
    public Task<IClientWithCredentials?> FindByClientIdAsync(
        string clientId,
        CancellationToken cancellationToken = default)
    {
        // Dictionary<string, T>.TryGetValue throws ArgumentNullException on a null key, but the
        // IClientRepository contract requires returning null for an unknown or malformed
        // client_id — never throwing.
        if (clientId is null)
            return Task.FromResult<IClientWithCredentials?>(null);

        _clients.TryGetValue(clientId, out var reg);
        return Task.FromResult(reg);
    }
}
