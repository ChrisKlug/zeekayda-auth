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
        IEnumerable<string> allowedScopes,
        Action<PublicClientOptions>? configure = null)
    {
        var registration = ClientRegistration.CreatePublic(clientId, redirectUris, postLogoutRedirectUris, allowedScopes);
        _options.PreBuilt.Add(Configure(registration, configure, defaults => new PublicClientOptions(defaults)));
        return this;
    }

    /// <inheritdoc/>
    public IInMemoryClientRegistrationBuilder AddConfidential(
        string clientId,
        string clientSecret,
        IEnumerable<string> redirectUris,
        IEnumerable<string> postLogoutRedirectUris,
        IEnumerable<string> allowedScopes,
        Action<ConfidentialClientOptions>? configure = null)
    {
        // The credentials stay empty until the repository hashes the secret at startup.
        var registration = ClientRegistration.CreateConfidentialWithoutCredential(
            clientId, redirectUris, postLogoutRedirectUris, allowedScopes);
        _options.Pending.Add(new PendingConfidentialClientSpec(
            Configure(registration, configure, defaults => new ConfidentialClientOptions(defaults)),
            clientSecret));
        return this;
    }

    /// <inheritdoc/>
    public IInMemoryClientRegistrationBuilder Add(IClientRegistration registration)
    {
        _options.PreBuilt.Add(registration);
        return this;
    }

    private static ClientRegistration Configure<TOptions>(
        ClientRegistration registration,
        Action<TOptions>? configure,
        Func<ClientRegistration, TOptions> createOptions)
        where TOptions : ClientOptions
    {
        if (configure is null)
            return registration;

        var options = createOptions(registration);
        configure(options);
        return options.ApplyTo(registration);
    }
}
