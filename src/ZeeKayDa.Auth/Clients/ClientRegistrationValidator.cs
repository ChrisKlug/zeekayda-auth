using System.Collections.Concurrent;
using Microsoft.Extensions.Options;
using ZeeKayDa.Auth.Logging;
using ZeeKayDa.Auth.Tokens;

namespace ZeeKayDa.Auth.Clients;

/// <summary>
/// The default <see cref="IClientRegistrationValidator"/>; its rules are grouped by topic in sibling files,
/// run in the order <see cref="Validate"/> lists.
/// </summary>
// keyRing has no default, so omitting it cannot silently skip the signing-algorithm check.
internal sealed partial class ClientRegistrationValidator(
    IOptions<AuthorizationServerOptions> options,
    AdvertisedAuthMethods advertisedAuthMethods,
    ClientSecretHasherRegistry registry,
    SanitizingLogger<ClientRegistrationValidator> logger,
    SigningKeyRing? keyRing) : IClientRegistrationValidator
{
    // Validation runs on every lookup, so advisories are written once, keyed by what the store returned.
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
