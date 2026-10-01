using ZeeKayDa.Auth.Clients;

namespace ZeeKayDa.Auth.Clients;

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
        var registration = Client.CreatePublic(clientId, redirectUris, postLogoutRedirectUris, allowedScopes);
        _options.PreBuilt.Add(Configure(registration, configure, () => new PublicClientOptions()));
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
        var registration = Client.CreateConfidentialWithoutCredential(
            clientId, redirectUris, postLogoutRedirectUris, allowedScopes);
        _options.Pending.Add(new PendingConfidentialClientSpec(
            Configure(registration, configure, () => new ConfidentialClientOptions()),
            clientSecret));
        return this;
    }

    /// <inheritdoc/>
    public IInMemoryClientRegistrationBuilder Add(IClientWithCredentials registration)
    {
        _options.PreBuilt.Add(registration);
        return this;
    }

    private static Client Configure<TOptions>(
        Client registration,
        Action<TOptions>? configure,
        Func<TOptions> createOptions)
        where TOptions : ClientOptions
    {
        if (configure is null)
            return registration;

        var options = createOptions();
        configure(options);
        return options.ApplyTo(registration);
    }
}
