using System.Collections.Concurrent;
using Microsoft.Extensions.Options;
using ZeeKayDa.Auth.Logging;
using ZeeKayDa.Auth.Tokens;

namespace ZeeKayDa.Auth.Clients;

/// <summary>
/// The framework's client registration rules, grouped by topic in sibling files and run in the order
/// <see cref="Validate"/> lists. A custom <see cref="IClientRepository"/> may inject it to check a client
/// before saving; only the framework constructs it.
/// </summary>
public sealed partial class ClientRegistrationValidator
{
    private readonly IOptions<AuthorizationServerOptions> _options;
    private readonly AdvertisedAuthMethods _advertisedAuthMethods;
    private readonly ClientSecretHasherRegistry _registry;
    private readonly SanitizingLogger<ClientRegistrationValidator> _logger;
    private readonly SigningKeyRing? _keyRing;

    // keyRing has no default, so omitting it cannot silently skip the signing-algorithm check.
    internal ClientRegistrationValidator(
        IOptions<AuthorizationServerOptions> options,
        AdvertisedAuthMethods advertisedAuthMethods,
        ClientSecretHasherRegistry registry,
        SanitizingLogger<ClientRegistrationValidator> logger,
        SigningKeyRing? keyRing)
    {
        _options = options;
        _advertisedAuthMethods = advertisedAuthMethods;
        _registry = registry;
        _logger = logger;
        _keyRing = keyRing;
    }

    // Validation runs on every lookup, so advisories are written once, keyed by what the store returned.
    private const int MaxWarnedAdvisories = 16_384;

    private readonly ConcurrentDictionary<(string ClientId, string Advisory, string? Detail), byte> _warned = new();

    /// <summary>Validates <paramref name="client"/> against every framework rule.</summary>
    /// <param name="client">The registration to validate.</param>
    /// <returns>
    /// Every rule violation found, so operators see every problem in one pass; empty when the
    /// registration is valid. An invalid registration is an expected outcome, never an exception.
    /// </returns>
    public IReadOnlyList<ZeeKayDaConfigurationFailure> Validate(IClientWithCredentials client)
    {
        ArgumentNullException.ThrowIfNull(client);

        return
        [
            .. ValidateIdentity(client),
            .. ValidateCredentials(client),
            .. ValidateGrants(client),
            .. ValidateDestinations(client),
            .. ValidateIssued(client),
        ];
    }

    /// <summary>
    /// <see langword="true"/> the first time an advisory is raised for a client, and
    /// <see langword="false"/> for every repeat of it.
    /// </summary>
    private bool FirstTime(string clientId, string advisory, string? detail = null)
    {
        if (!_warned.TryAdd((clientId, advisory, detail), 0))
            return false;

        if (_warned.Count >= MaxWarnedAdvisories)
            _warned.Clear();

        return true;
    }
}
