using Microsoft.Extensions.Logging;
using ZeeKayDa.Auth.Tokens;

namespace ZeeKayDa.Auth.Clients;

// What the client is issued: how its tokens are signed, how long they live, and the claims added
// to them.
internal sealed partial class ClientRegistrationValidator
{
    private IEnumerable<ZeeKayDaConfigurationFailure> ValidateIssued(IClientWithCredentials client) =>
        ValidateAllowedSigningAlgorithms(client)
            .Concat(ValidateTokenLifetime(client, client.AccessTokenLifetime, nameof(IClient.AccessTokenLifetime)))
            .Concat(ValidateTokenLifetime(client, client.IdTokenLifetime, nameof(IClient.IdTokenLifetime)))
            .Concat(ValidateClaimAdditions(client, client.AdditionalIdTokenClaims, nameof(IClient.AdditionalIdTokenClaims)))
            .Concat(ValidateClaimAdditions(client, client.AdditionalUserInfoClaims, nameof(IClient.AdditionalUserInfoClaims)))
            .Concat(ValidateClaimAdditions(client, client.AdditionalAccessTokenClaims, nameof(IClient.AdditionalAccessTokenClaims)));

    private IEnumerable<ZeeKayDaConfigurationFailure> ValidateAllowedSigningAlgorithms(IClientWithCredentials client)
    {
        var algorithms = client.AllowedSigningAlgorithms;

        if (algorithms is null)
            yield break;

        if (algorithms.Count == 0)
        {
            yield return new ZeeKayDaConfigurationFailure(
                "client.signing_algorithms.empty_when_set",
                $"Client '{client.ClientId}' has AllowedSigningAlgorithms set to a non-null empty set. " +
                "When set, AllowedSigningAlgorithms must contain at least one value, or be null to inherit the server default.");
            yield break;
        }

        var undefinedValues = algorithms.Where(algorithm => !Enum.IsDefined(algorithm)).ToList();
        foreach (var undefined in undefinedValues)
        {
            yield return new ZeeKayDaConfigurationFailure(
                "client.signing_algorithms.undefined",
                $"Client '{client.ClientId}' has AllowedSigningAlgorithms value {(int)undefined}, which is not a " +
                $"defined {nameof(SigningAlgorithm)} member.");
        }

        if (undefinedValues.Count > 0)
            yield break;

        // CurrentOrNull rather than Current: a custom repository may validate before the ring has
        // been initialized, and throwing there would turn "cannot check yet" into a startup crash.
        if (keyRing?.CurrentOrNull is not { } keySet)
        {
            WarnSigningUnchecked(client);
            yield break;
        }

        if (!algorithms.Contains(keySet.Algorithm))
        {
            yield return new ZeeKayDaConfigurationFailure(
                "client.signing_algorithms.excludes_signing_key",
                $"Client '{client.ClientId}' has AllowedSigningAlgorithms that exclude '{keySet.Algorithm}', the " +
                "algorithm the server signs with, so no ID token could be issued to it. Add that algorithm.");
            yield break;
        }

        WarnUnusedAlgorithms(client, algorithms, keySet.Algorithm);
    }

    /// <summary>
    /// Nothing to check against yet. The JWT issuer enforces the set again at signing, so only the
    /// earlier message is lost; say so. With no ring at all the endpoints refuse to start anyway.
    /// </summary>
    private void WarnSigningUnchecked(IClientWithCredentials client)
    {
        if (keyRing is not null && FirstTime(client.ClientId, "signing-unchecked"))
        {
            logger.LogWarning(
                "Client '{ClientId}' declares AllowedSigningAlgorithms, but the signing key ring " +
                "has not yet read its source, so the set could not be checked against the " +
                "algorithm the server signs with. This happens when an IClientRepository is " +
                "resolved before host startup verification runs.",
                client.ClientId);
        }
    }

    /// <summary>
    /// An acceptance list may name an algorithm the server never signs with — a client kept ready for
    /// another server, or for a planned change of algorithm — so it only warns, once per client and
    /// algorithm, since a repository may validate on every lookup.
    /// </summary>
    private void WarnUnusedAlgorithms(
        IClientWithCredentials client, IReadOnlySet<SigningAlgorithm> algorithms, SigningAlgorithm signingAlgorithm)
    {
        foreach (var algorithm in algorithms.Where(algorithm =>
            algorithm != signingAlgorithm && FirstTime(client.ClientId, "algorithm-never-signed", algorithm.ToString())))
        {
            logger.LogWarning(
                "Client '{ClientId}' has AllowedSigningAlgorithms entry '{Algorithm}', which the server never " +
                "signs with: it signs only with {SigningAlgorithm}. The entry has no effect.",
                client.ClientId,
                algorithm,
                signingAlgorithm);
        }
    }

    /// <summary>
    /// A client override must be positive; one past the family ceiling only warns, because a
    /// custom repository may validate on resolution rather than at startup, and a warning there
    /// is still read while a failure would take the request down with it.
    /// </summary>
    private IEnumerable<ZeeKayDaConfigurationFailure> ValidateTokenLifetime(
        IClientWithCredentials client,
        TimeSpan? lifetime,
        string propertyName)
    {
        if (lifetime is not { } value)
            yield break;

        if (value <= TimeSpan.Zero)
        {
            yield return new ZeeKayDaConfigurationFailure(
                "client.token_lifetime.not_positive",
                $"Client '{client.ClientId}' has {propertyName} set to {value}. " +
                "When set, a token lifetime must be greater than zero, or null to inherit the server default.");
            yield break;
        }

        if (value > options.Value.TokenEndpoint.AbsoluteFamilyLifetime
            && FirstTime(client.ClientId, "lifetime-past-family", propertyName))
        {
            logger.LogWarning(
                "Client '{ClientId}' has {PropertyName} set past TokenEndpoint.AbsoluteFamilyLifetime, " +
                "so a token issued to it would outlive the grant family that produced it.",
                client.ClientId,
                propertyName);
        }
    }

    /// <summary>
    /// An addition is a claim name selection can act on: present, non-blank, and not one of the
    /// protocol names the framework writes itself, which selection would drop anyway. Whether it
    /// collides with a scope is checked per grant, against the scope repository this validator
    /// cannot see.
    /// </summary>
    private static IEnumerable<ZeeKayDaConfigurationFailure> ValidateClaimAdditions(
        IClientWithCredentials client,
        IReadOnlyCollection<string>? additions,
        string propertyName)
    {
        if (additions is null)
        {
            yield return new ZeeKayDaConfigurationFailure(
                "client.claim_additions.null",
                $"Client '{client.ClientId}' has {propertyName} set to null. Use an empty collection for no additions.");
            yield break;
        }

        foreach (var _ in additions.Where(string.IsNullOrWhiteSpace))
        {
            yield return new ZeeKayDaConfigurationFailure(
                "client.claim_additions.blank_entry",
                $"Client '{client.ClientId}' has a null, empty, or whitespace-only entry in {propertyName}. " +
                "Entries must be claim type names.");
        }

        foreach (var claim in additions.Where(claim => !string.IsNullOrWhiteSpace(claim) && Claims.ReservedClaimNames.IsReserved(claim)))
        {
            yield return new ZeeKayDaConfigurationFailure(
                "client.claim_additions.reserved",
                $"Client '{client.ClientId}' names '{claim}' in {propertyName}, which is a protocol claim the " +
                "framework writes from the grant. It cannot be supplied by a claims provider and is never selected.");
        }
    }
}
