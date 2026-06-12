using Microsoft.Extensions.DependencyInjection;
using ZeeKayDa.Auth.Clients;

namespace ZeeKayDa.Auth.AspNetCore.Clients;

internal sealed class InMemoryClientRegistrationBuilder : IInMemoryClientRegistrationBuilder
{
    private readonly IServiceCollection _services;

    public InMemoryClientRegistrationBuilder(IServiceCollection services)
        => _services = services;

    /// <inheritdoc/>
    public IInMemoryClientRegistrationBuilder AddPublic(
        string clientId,
        IEnumerable<string> redirectUris,
        IEnumerable<string> postLogoutRedirectUris,
        IEnumerable<string> allowedScopes)
    {
        var reg = ClientRegistration.CreatePublic(clientId, redirectUris, postLogoutRedirectUris, allowedScopes);
        _services.Configure<InMemoryClientRegistrationOptions>(o => o.PreBuilt.Add(reg));
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
        _services.Configure<InMemoryClientRegistrationOptions>(o => o.Pending.Add(spec));
        return this;
    }

    /// <inheritdoc/>
    public IInMemoryClientRegistrationBuilder Add(IClientRegistration registration)
    {
        _services.Configure<InMemoryClientRegistrationOptions>(o => o.PreBuilt.Add(registration));
        return this;
    }
}
