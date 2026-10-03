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
            : [.. framework.Validate(client), .. host.Validate(client)];
}
