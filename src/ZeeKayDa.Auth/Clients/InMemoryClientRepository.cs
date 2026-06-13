using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

namespace ZeeKayDa.Auth.Clients;

/// <summary>
/// An in-memory <see cref="IClientRepository"/> populated at startup from configured
/// <see cref="InMemoryClientRegistrationOptions"/>.
/// </summary>
/// <remarks>
/// <para>
/// Clients are validated at construction time via <see cref="IClientRegistrationValidator"/>.
/// Any validation failure throws <see cref="ZeeKayDaConfigurationException"/> with all
/// aggregated failures so operators see every problem in one pass.
/// </para>
/// <para>
/// Suitable for development, testing, and simple deployments. For production scenarios with
/// many clients or dynamic registration, implement a custom <see cref="IClientRepository"/>.
/// </para>
/// </remarks>
internal sealed class InMemoryClientRepository : IClientRepository
{
    private readonly IReadOnlyDictionary<string, IClientRegistration> _clients;

    public InMemoryClientRepository(
        IOptions<InMemoryClientRegistrationOptions> options,
        CompositeClientSecretHasher hasher,
        IClientRegistrationValidator validator,
        IOptions<AuthorizationServerOptions> serverOptions,
        ILogger<InMemoryClientRepository> logger)
    {
        ArgumentNullException.ThrowIfNull(options);
        ArgumentNullException.ThrowIfNull(hasher);
        ArgumentNullException.ThrowIfNull(validator);
        ArgumentNullException.ThrowIfNull(serverOptions);
        ArgumentNullException.ThrowIfNull(logger);

        var opts = options.Value;
        var allRegistrations = new List<IClientRegistration>(opts.PreBuilt.Count + opts.Pending.Count);

        // Collect all failures: secret hashing + duplicates + per-client validation, so operators
        // see every problem in one pass rather than the first hashing failure aborting the rest.
        var allFailures = new List<ZeeKayDaConfigurationFailure>();

        // Build confidential clients from pending specs (hash plaintext secrets now)
        foreach (var spec in opts.Pending)
        {
            IClientSecret hashedSecret;
            try
            {
                hashedSecret = hasher.Create(spec.PlaintextSecret);
            }
            catch (ArgumentException)
            {
                // ClientSecretHasher<T>.Create throws on a null/empty/whitespace secret. Convert it
                // to an aggregated failure and skip this spec so the remaining clients are still
                // validated and reported.
                allFailures.Add(new ZeeKayDaConfigurationFailure(
                    "client.credentials.empty_plaintext_secret",
                    $"Client '{spec.ClientId}' was registered with a null, empty, or whitespace plaintext secret. " +
                    "Use a strong random secret loaded from a secrets manager or environment variable."));
                continue;
            }

            var reg = ClientRegistration.CreateConfidential(
                spec.ClientId,
                hashedSecret,
                spec.RedirectUris,
                spec.PostLogoutRedirectUris,
                spec.AllowedScopes);
            allRegistrations.Add(reg);
        }

        // All pending specs have been processed (hashed or converted to a failure). Clear the list
        // so the PendingConfidentialClientSpec objects — and the plaintext secrets they contain —
        // become GC-eligible. Because the options object is a plain singleton (no capturing closure
        // holds a reference to the specs), clearing is sufficient to release them.
        opts.Pending.Clear();

        // Add pre-built registrations
        allRegistrations.AddRange(opts.PreBuilt);

        // The pre-built registrations have been snapshotted into allRegistrations; clear the
        // source list so it is not retained alongside the snapshot.
        opts.PreBuilt.Clear();

        // Check for duplicate client_id (ordinal)
        var seen = new HashSet<string>(StringComparer.Ordinal);
        foreach (var reg in allRegistrations.Where(reg => !seen.Add(reg.ClientId)))
        {
            allFailures.Add(new ZeeKayDaConfigurationFailure(
                "client.client_id.duplicate",
                $"A client with ClientId '{reg.ClientId}' has been registered more than once. " +
                "Each client must have a unique ClientId (ordinal comparison)."));
        }

        // Validate each registration, accumulating failures
        foreach (var reg in allRegistrations)
        {
            try
            {
                validator.Validate(reg);
            }
            catch (ZeeKayDaConfigurationException ex)
            {
                allFailures.AddRange(ex.AggregatedFailures);
            }
        }

        if (allFailures.Count > 0)
            throw new ZeeKayDaConfigurationException([.. allFailures]);

        _clients = allRegistrations.ToDictionary(r => r.ClientId, StringComparer.Ordinal);

        // AC #27: warn if "none" is advertised server-wide but no public client is registered
        var serverAdvertisesNone = serverOptions.Value.TokenEndpoint.AuthMethodsSupported
            .Any(m => string.Equals(m, TokenEndpointAuthMethods.None, StringComparison.Ordinal));

        if (serverAdvertisesNone && !_clients.Values.Any(c => c.IsPublic))
        {
            logger.LogWarning(
                "The server advertises 'none' as a supported token endpoint authentication method " +
                "but no public clients (IsPublic=true) are registered. Consider removing " +
                "TokenEndpointAuthMethods.None from AuthMethodsSupported if no public clients are expected.");
        }
    }

    /// <inheritdoc/>
    public ValueTask<IClientRegistration?> FindByClientIdAsync(
        string clientId,
        CancellationToken cancellationToken = default)
    {
        // Dictionary<string, T>.TryGetValue throws ArgumentNullException on a null key, but the
        // IClientRepository contract requires returning null for an unknown or malformed
        // client_id — never throwing.
        if (clientId is null)
            return ValueTask.FromResult<IClientRegistration?>(null);

        _clients.TryGetValue(clientId, out var reg);
        return ValueTask.FromResult(reg);
    }
}
