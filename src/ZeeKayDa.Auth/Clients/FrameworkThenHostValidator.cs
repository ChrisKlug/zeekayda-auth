namespace ZeeKayDa.Auth.Clients;

/// <summary>
/// What the framework validates every registration with — at startup in
/// <see cref="InMemoryClientRepository.Build"/> and per request in <see cref="ValidatedClientResolver"/>:
/// the framework's rules always, then a host's own <see cref="IClientRegistrationValidator"/> if it
/// registered one. A host can add rules, never remove the framework's; the <c>none</c>
/// client-authentication path relies on the framework's public ⇔ no credentials ⇔ <c>{ "none" }</c>
/// rule.
/// </summary>
internal sealed class FrameworkThenHostValidator(
    ClientRegistrationValidator framework,
    IClientRegistrationValidator host) : IClientRegistrationValidator
{
    public IReadOnlyList<ZeeKayDaConfigurationFailure> Validate(IClientWithCredentials client) =>
        ReferenceEquals(host, framework)
            ? framework.Validate(client)
            : [.. framework.Validate(client), .. Checked(host, client)];

    /// <summary>
    /// <paramref name="host"/>'s failures, or a single <c>client.validator.malformed_result</c> when
    /// it breaks its contract with a null list or a null entry, which would otherwise surface as a
    /// bare <see cref="NullReferenceException"/> far from its cause.
    /// </summary>
    private static IReadOnlyList<ZeeKayDaConfigurationFailure> Checked(
        IClientRegistrationValidator host,
        IClientWithCredentials client)
    {
        // Copied once, so the list that is checked is the list that is returned: a host's own list
        // may yield something different each time it is enumerated.
        var found = host.Validate(client)?.ToArray();

        // The real failures it did return are kept, so the operator sees them in the same pass.
        return found is null || found.Any(failure => failure is null)
            ?
            [
                .. (found ?? []).OfType<ZeeKayDaConfigurationFailure>(),
                new ZeeKayDaConfigurationFailure(
                    "client.validator.malformed_result",
                    $"The IClientRegistrationValidator '{host.GetType().FullName}' returned a null list or a " +
                    $"null failure for client '{client.ClientId}'. Return an empty list for a valid registration."),
            ]
            : found;
    }
}
