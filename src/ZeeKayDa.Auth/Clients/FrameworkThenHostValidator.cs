namespace ZeeKayDa.Auth.Clients;

/// <summary>
/// The framework's rules, then a host's own validator if registered: a host can add rules, never remove the
/// ones the <c>none</c> authentication path relies on.
/// </summary>
internal sealed class FrameworkThenHostValidator(
    ClientRegistrationValidator framework,
    IClientRegistrationValidator host) : IClientRegistrationValidator
{
    public IReadOnlyList<ZeeKayDaConfigurationFailure> Validate(IClientWithCredentials client) =>
        ReferenceEquals(host, framework)
            ? framework.Validate(client)
            : [.. framework.Validate(client), .. Checked(host, client)];

    /// <summary>The host's failures, plus one <c>client.validator.malformed_result</c> for a null list or entry.</summary>
    private static IReadOnlyList<ZeeKayDaConfigurationFailure> Checked(
        IClientRegistrationValidator host,
        IClientWithCredentials client)
    {
        // Copied once: a host's list may yield something different on each enumeration.
        var found = host.Validate(client)?.ToArray();

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
