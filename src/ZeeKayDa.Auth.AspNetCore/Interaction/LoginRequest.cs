namespace ZeeKayDa.Auth.AspNetCore.Interaction;

/// <summary>What the host's login page renders for, read through <see cref="LoginInteraction.GetRequestAsync"/>.</summary>
public sealed class LoginRequest
{
    internal LoginRequest(
        ClientInformation client,
        IReadOnlyList<ProviderDescriptor> providers,
        bool localLoginEnabled,
        ProviderReturn? providerReturn,
        string? loginHint)
    {
        ArgumentNullException.ThrowIfNull(client);
        ArgumentNullException.ThrowIfNull(providers);

        Client = client;
        Providers = providers;
        LocalLoginEnabled = localLoginEnabled;
        ProviderReturn = providerReturn;
        LoginHint = loginHint;
    }

    /// <summary>The client the user is signing in to.</summary>
    public ClientInformation Client { get; }

    /// <summary>
    /// The providers registered through <c>WithProviders</c>, in order, for the page to offer; the
    /// chosen <see cref="ProviderDescriptor.Id"/> goes back to <see cref="LoginInteraction.ChallengeAsync"/>.
    /// </summary>
    public IReadOnlyList<ProviderDescriptor> Providers { get; }

    /// <summary>Whether to render a credential form: <c>AuthorizationEndpoint.Interaction.SupportsLocalSignIn</c>.</summary>
    public bool LocalLoginEnabled { get; }

    /// <summary>
    /// How the last provider trip ended when it brought the user back here instead of signing them
    /// in; <see langword="null"/> on an ordinary arrival.
    /// </summary>
    public ProviderReturn? ProviderReturn { get; }

    /// <summary>
    /// The client's <c>login_hint</c> (OIDC Core §3.1.2.1) for the page to pre-fill. Unverified
    /// input, at most 256 characters with no control or formatting characters: encode it, and never
    /// sign anyone in or look anyone up on its strength alone.
    /// </summary>
    public string? LoginHint { get; }
}
