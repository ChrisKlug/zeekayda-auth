using System.Collections.Concurrent;
using Microsoft.Extensions.Options;
using ZeeKayDa.Auth.Logging;
using ZeeKayDa.Auth.Tokens;

namespace ZeeKayDa.Auth.Clients;

/// <summary>
/// Default implementation of <see cref="IClientRegistrationValidator"/> that enforces all
/// client registration rules.
/// </summary>
/// <remarks>
/// Registered as a singleton by <c>AddZeeKayDaAuth()</c>. The rules are grouped by what they are
/// about, one sibling file per group, and run in the order <see cref="Validate"/> lists them.
/// </remarks>
// keyRing is null when no ring is registered, and deliberately has no default: omitting it would
// silently weaken the check that a client's AllowedSigningAlgorithms are ones the ring signs with.
internal sealed partial class ClientRegistrationValidator(
    IOptions<AuthorizationServerOptions> options,
    AdvertisedAuthMethods advertisedAuthMethods,
    ClientSecretHasherRegistry registry,
    SanitizingLogger<ClientRegistrationValidator> logger,
    SigningKeyRing? keyRing) : IClientRegistrationValidator
{
    // The resolver validates on every lookup, so an advisory written each time would let anyone
    // who knows a client_id repeat it per request. Keyed by what the store returned, never by
    // request input; cleared at the cap, which costs one repeat per advisory.
    private const int MaxWarnedAdvisories = 16_384;

    private readonly ConcurrentDictionary<(string ClientId, string Advisory, string? Detail), byte> _warned = new();

    /// <inheritdoc/>
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
