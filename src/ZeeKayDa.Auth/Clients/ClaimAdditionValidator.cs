namespace ZeeKayDa.Auth.Clients;

/// <summary>
/// Validates a client's additional ID token, UserInfo, and access token claims and records a
/// <see cref="ZeeKayDaConfigurationFailure"/> for every rule they break.
/// </summary>
internal static class ClaimAdditionValidator
{
    /// <summary>
    /// Validates all three of the client's claim addition collections.
    /// </summary>
    internal static void Validate(
        IClientRegistration client,
        List<ZeeKayDaConfigurationFailure> failures)
    {
        Validate(client, client.AdditionalIdTokenClaims, nameof(IClientMetadata.AdditionalIdTokenClaims), failures);
        Validate(client, client.AdditionalUserInfoClaims, nameof(IClientMetadata.AdditionalUserInfoClaims), failures);
        Validate(client, client.AdditionalAccessTokenClaims, nameof(IClientMetadata.AdditionalAccessTokenClaims), failures);
    }

    /// <summary>
    /// An addition is a claim name selection can act on: present, non-blank, and not one of the
    /// protocol names the framework writes itself, which selection would drop anyway. Whether it
    /// collides with a scope is checked per grant, against the scope repository this validator
    /// cannot see.
    /// </summary>
    private static void Validate(
        IClientRegistration client,
        IReadOnlyCollection<string>? additions,
        string propertyName,
        List<ZeeKayDaConfigurationFailure> failures)
    {
        if (additions is null)
        {
            failures.Add(new ZeeKayDaConfigurationFailure(
                "client.claim_additions.null",
                $"Client '{client.ClientId}' has {propertyName} set to null. Use an empty collection for no additions."));
            return;
        }

        foreach (var _ in additions.Where(string.IsNullOrWhiteSpace))
        {
            failures.Add(new ZeeKayDaConfigurationFailure(
                "client.claim_additions.blank_entry",
                $"Client '{client.ClientId}' has a null, empty, or whitespace-only entry in {propertyName}. " +
                "Entries must be claim type names."));
        }

        foreach (var claim in additions.Where(claim => !string.IsNullOrWhiteSpace(claim) && Claims.ReservedClaimNames.IsReserved(claim)))
        {
            failures.Add(new ZeeKayDaConfigurationFailure(
                "client.claim_additions.reserved",
                $"Client '{client.ClientId}' names '{claim}' in {propertyName}, which is a protocol claim the " +
                "framework writes from the grant. It cannot be supplied by a claims provider and is never selected."));
        }
    }
}
