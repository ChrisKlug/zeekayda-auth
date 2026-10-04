namespace ZeeKayDa.Auth.Clients;

/// <summary>
/// What <see cref="ValidatedClientResolver"/> validates with: the framework's rules always, then a
/// host's own <see cref="IClientRegistrationValidator"/> if it registered one. A host can add rules
/// to what is served, never remove the framework's; the <c>none</c> client-authentication path
/// relies on the framework's public ⇔ no credentials ⇔ <c>{ "none" }</c> rule.
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
    internal static IReadOnlyList<ZeeKayDaConfigurationFailure> Checked(
        IClientRegistrationValidator host,
        IClientWithCredentials client)
    {
        // Copied once, so the list that is checked is the list that is returned: a host's own list
        // may yield something different each time it is enumerated.
        var found = host.Validate(client)?.ToArray();

        return found is null || found.Any(failure => failure is null)
            ?
            [
                new ZeeKayDaConfigurationFailure(
                    "client.validator.malformed_result",
                    $"The IClientRegistrationValidator '{host.GetType().FullName}' returned a null list or a " +
                    $"null failure for client '{client.ClientId}'. Return an empty list for a valid registration."),
            ]
            : found;
    }
}
