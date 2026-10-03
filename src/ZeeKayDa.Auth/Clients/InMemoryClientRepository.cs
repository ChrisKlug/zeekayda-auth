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
    internal static readonly Func<IServiceProvider, IClientRepository> Factory = services => Build(
        services.GetRequiredService<InMemoryClientRegistrationOptions>(),
        services.GetRequiredService<ClientSecrets>(),
        services.GetRequiredService<IClientRegistrationValidator>(),
        services.GetRequiredService<IOptions<AuthorizationServerOptions>>().Value,
        services.GetRequiredService<SanitizingLogger<InMemoryClientRepository>>());

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
        IClientRegistrationValidator validator,
        AuthorizationServerOptions serverOptions,
        ILogger logger)
    {
        var failures = new List<ZeeKayDaConfigurationFailure>();
        var clients = new List<IClientWithCredentials>(registrations.PreBuilt.Count + registrations.Pending.Count);

        foreach (var spec in registrations.Pending)
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

        clients.AddRange(registrations.PreBuilt);

        var seen = new HashSet<string>(StringComparer.Ordinal);
        foreach (var client in clients.Where(client => !seen.Add(client.ClientId)))
        {
            failures.Add(new ZeeKayDaConfigurationFailure(
                "client.client_id.duplicate",
                $"A client with ClientId '{client.ClientId}' has been registered more than once. " +
                "Each client must have a unique ClientId (ordinal comparison)."));
        }

        foreach (var client in clients)
            failures.AddRange(validator.Validate(client));

        if (failures.Count > 0)
            throw new ZeeKayDaConfigurationException([.. failures]);

        var advertisesNone = serverOptions.TokenEndpoint.AuthMethodsSupported
            .Any(method => string.Equals(method, TokenEndpointAuthMethods.None, StringComparison.Ordinal));

        if (advertisesNone && !clients.Any(client => client.IsPublic))
        {
            logger.LogWarning(
                "The server advertises 'none' as a supported token endpoint authentication method " +
                "but no public clients (IsPublic=true) are registered. Consider removing " +
                "TokenEndpointAuthMethods.None from AuthMethodsSupported if no public clients are expected.");
        }

        return new InMemoryClientRepository(clients.ToDictionary(client => client.ClientId, StringComparer.Ordinal));
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
