using ZeeKayDa.Auth.Clients;

namespace ZeeKayDa.Auth.AspNetCore.Clients;

internal sealed class InMemoryClientRegistrationBuilder : IInMemoryClientRegistrationBuilder
{
    private readonly InMemoryClientRegistrationOptions _options;

    public InMemoryClientRegistrationBuilder(InMemoryClientRegistrationOptions options)
        => _options = options;

    /// <inheritdoc/>
    public IInMemoryClientRegistrationBuilder AddPublic(
        string clientId,
        IEnumerable<string> redirectUris,
        IEnumerable<string> postLogoutRedirectUris,
        IEnumerable<string> allowedScopes)
    {
        var reg = ClientRegistration.CreatePublic(clientId, redirectUris, postLogoutRedirectUris, allowedScopes);
        _options.PreBuilt.Add(reg);
        return this;
    }

    /// <inheritdoc/>
    public IInMemoryClientRegistrationBuilder AddConfidential(
        string clientId,
        string clientSecret,
        IEnumerable<string> redirectUris,
        IEnumerable<string> postLogoutRedirectUris,
        IEnumerable<string> allowedScopes)
    {
        var spec = new PendingConfidentialClientSpec(
            clientId,
            clientSecret,
            redirectUris.ToList(),
            postLogoutRedirectUris.ToList(),
            allowedScopes.ToList());
        _options.Pending.Add(spec);
        return this;
    }

    /// <inheritdoc/>
    public IInMemoryClientRegistrationBuilder Add(IClientRegistration registration)
    {
        _options.PreBuilt.Add(registration);
        return this;
    }
}
