using ZeeKayDa.Auth.Clients;

namespace ZeeKayDa.Auth.Clients;

/// <summary>
/// Registers clients with the in-memory client repository.
/// </summary>
/// <remarks>
/// Obtained via <c>builder.AddInMemoryClients(clients => { ... })</c>. Multiple
/// <c>AddInMemoryClients</c> calls are additive — registrations accumulate rather than replace.
/// </remarks>
public sealed class InMemoryClientRegistrationBuilder
{
    private readonly InMemoryClientRegistrationOptions _options;

    internal InMemoryClientRegistrationBuilder(InMemoryClientRegistrationOptions options)
        => _options = options;

    /// <summary>
    /// Registers a public client: no credentials, token endpoint auth method <c>none</c>, and always
    /// held to PKCE.
    /// </summary>
    /// <param name="clientId">The client's <c>client_id</c>.</param>
    /// <param name="configure">
    /// Sets the client's redirect URIs, scopes and other settings. It is called once, before this
    /// method returns.
    /// </param>
    /// <returns>This builder, so calls can be chained.</returns>
    /// <remarks>
    /// The server advertises <c>none</c> by default; a <c>TokenEndpoint.AdvertisedAuthMethods</c>
    /// filter that withholds it makes startup reject the registration.
    /// </remarks>
    /// <exception cref="ArgumentNullException">
    /// <paramref name="clientId"/> or <paramref name="configure"/> is <see langword="null"/>.
    /// </exception>
    public InMemoryClientRegistrationBuilder AddPublic(string clientId, Action<PublicClientOptions> configure)
    {
        ArgumentNullException.ThrowIfNull(clientId);
        ArgumentNullException.ThrowIfNull(configure);

        var options = new PublicClientOptions();
        configure(options);
        _options.PreBuilt.Add(options.ToClient(clientId));
        return this;
    }

    /// <summary>
    /// Registers a confidential client, authenticated at the token endpoint with its secret.
    /// </summary>
    /// <param name="clientId">The client's <c>client_id</c>.</param>
    /// <param name="configure">
    /// Sets the client's secret, redirect URIs, scopes and other settings. It is called once, before
    /// this method returns.
    /// </param>
    /// <returns>This builder, so calls can be chained.</returns>
    /// <remarks>
    /// Exactly one of <see cref="ConfidentialClientOptions.Secret"/> and
    /// <see cref="ConfidentialClientOptions.SecretHash"/> must be set. A plaintext secret is hashed by
    /// the host's default <see cref="IClientSecretHasher"/> when the host starts, and the plaintext is
    /// released after that.
    /// </remarks>
    /// <exception cref="ArgumentNullException">
    /// <paramref name="clientId"/> or <paramref name="configure"/> is <see langword="null"/>.
    /// </exception>
    public InMemoryClientRegistrationBuilder AddConfidential(string clientId, Action<ConfidentialClientOptions> configure)
    {
        ArgumentNullException.ThrowIfNull(clientId);
        ArgumentNullException.ThrowIfNull(configure);

        var options = new ConfidentialClientOptions();
        configure(options);
        _options.Pending.Add(new PendingConfidentialClientSpec(options.ToClient(clientId), options.Secret, options.SecretHash));
        return this;
    }

    /// <summary>
    /// Registers a pre-built or pre-hashed <see cref="IClientWithCredentials"/> directly.
    /// </summary>
    /// <param name="registration">The client registration.</param>
    /// <returns>This builder, so calls can be chained.</returns>
    /// <exception cref="ArgumentNullException"><paramref name="registration"/> is <see langword="null"/>.</exception>
    public InMemoryClientRegistrationBuilder Add(IClientWithCredentials registration)
    {
        ArgumentNullException.ThrowIfNull(registration);

        _options.PreBuilt.Add(registration);
        return this;
    }
}
